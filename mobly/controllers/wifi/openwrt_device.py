# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Mobly controller module for AP devices running on the OpenWrt system."""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
import contextlib
import datetime
import itertools
import logging
import os
import pathlib
import tempfile
import time
import traceback
from typing import Any

from mobly import logger as mobly_logger
from mobly import runtime_test_info
from mobly import utils
from mobly.controllers.android_device_lib import service_manager
import paramiko

from mobly.controllers.wifi.lib import ssh as ssh_lib
from mobly.controllers.wifi import openwrt_device_config
from mobly.controllers.wifi.lib import captive_portal_server
from mobly.controllers.wifi.lib import constants
from mobly.controllers.wifi.lib import device_info as device_info_lib
from mobly.controllers.wifi.lib import hostapd_manager
from mobly.controllers.wifi.lib import iw_utils
from mobly.controllers.wifi.lib import package_manager
from mobly.controllers.wifi.lib import sniffer_manager
from mobly.controllers.wifi.lib import utils as wifi_utils
from mobly.controllers.wifi.lib import wifi_configs
from mobly.controllers.wifi.lib import wifi_manager
from mobly.controllers.wifi.lib.encryption import certificate
from mobly.controllers.wifi.lib.services import system_log_service

MOBLY_CONTROLLER_CONFIG_NAME = 'OpenWrtDevice'

_SSH_KEY_IDENTITY = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'data/testing_rsa'
)
_SSH_PORT = 22

_ERR_USE_AS_BOTH_AP_AND_SNIFFER = (
    "{device} It's not supported to use one OpenWrt device as both AP and"
    ' sniffer at the same time.'
)

_ERR_START_PACKET_CAPTURE_ARG_ERROR = (
    '{device} Exactly one of wifi_config, network_config, or freq_config must'
    ' be provided.'
)


class Error(Exception):
  """Error class for the OpenWrtDevice controller."""


def create(configs: list[dict[str, Any]]) -> list[OpenWrtDevice]:
  """Creates OpenWrt device instances."""
  if not configs:
    raise Error(f'Missing configuration {configs!r}.')
  try:
    device_configs = openwrt_device_config.from_dicts(configs)
  except Exception as e:
    raise Error(f'Failed to parse device configs: {e}') from e

  devices = [OpenWrtDevice(config) for config in device_configs]
  devices = _initialize_devices(devices)
  return devices


def destroy(devices: list[OpenWrtDevice]) -> None:
  """Closes all created OpenWrt device instances."""
  for device in devices:
    try:
      device.teardown()
    except Exception:  # pylint: disable=broad-except
      logging.exception('Failed to clean up properly.')


def get_info(devices: Sequence[OpenWrtDevice]) -> Sequence[Mapping[str, Any]]:
  """Gets info from the OpenWrt device instances used in a test run.

  Args:
    devices: A list of OpenWrt device instances.

  Returns:
    A list of dict, each representing info for a device object.
  """
  return [d.device_info.to_dict() for d in devices]


def _initialize_devices(
    devices: Sequence[OpenWrtDevice],
) -> list[OpenWrtDevice]:
  """Registers basic long running services on multiple OpenWrtDevice objects.

  Args:
    devices: A list of OpenWrtDevice objects.

  Returns:
    A list of initialized device objects.
  """
  initialized_devices = []
  for device in devices:
    try:
      device.initialize()
      initialized_devices.append(device)
    except Exception:  # pylint: disable=broad-except
      device.log.exception(
          'Failed to initialize AP device %s, ignoring it.', device
      )
  return initialized_devices


IpInterface = wifi_utils.IpInterface


class OpenWrtDevice:
  """Mobly controller for AP devices running on the OpenWrt system.

  Attributes:
    config: The configuration of the OpenWrt device.
    ssh: The underlying SSH client object.
    serial: A string that identifies the ChromeOS device.
    log_path: A string that is the path where all logs collected on this device
      should be stored.
    debug_tag: A string that represents this ChromeOS device in the debug info.
    log: A logger adapted from root logger with an added prefix specific to a
      remote test machine. The prefix is "[OpenWrtDevice|<self.serial>] ".
    device_info: A collection of device information.
    services: The manager of long running services on the device.
    wifi_id_counter: The id counter of WiFi networks.
  """

  _DEVICE_TAG = MOBLY_CONTROLLER_CONFIG_NAME
  _DEVICE_REBOOT_WAIT = datetime.timedelta(seconds=10)
  _BOOT_STATUS_CHECK_INTERVAL = datetime.timedelta(seconds=5)
  _BOOT_STATUS_CHECK_TIMEOUT = datetime.timedelta(minutes=5)
  _SSH_CONNECTION_TIMEOUT = datetime.timedelta(minutes=5)

  _wifi_manager: wifi_manager.WifiManagerProtocol
  _sniffer_manager: sniffer_manager.SnifferManagerProtocol | None = None
  _package_manager: package_manager.PackageManagerProtocol
  _captive_portal_server: (
      captive_portal_server.CaptivePortalServerProtocol | None
  )

  def __init__(
      self, config: openwrt_device_config.DeviceConfig | Mapping[str, Any]
  ):
    # If the config is not a DeviceConfig object, convert it to one. This is
    # to support the old way of passing configs as dicts for backward
    # compatibility.
    if not isinstance(config, openwrt_device_config.DeviceConfig):
      config = openwrt_device_config.DeviceConfig.from_dict(dict(config))
    self.config = config
    self._device_info = None

    log_path = getattr(logging, 'log_path', '/tmp/logs')
    log_filename = mobly_logger.sanitize_filename(
        f'{self._DEVICE_TAG}_{self.serial}'
    )
    self.log_path = os.path.join(log_path, log_filename)
    utils.create_dir(self.log_path)

    self.log = mobly_logger.PrefixLoggerAdapter(
        logging.getLogger(),
        {
            mobly_logger.PrefixLoggerAdapter.EXTRA_KEY_LOG_PREFIX: (
                f'[{self._log_prefix}]'
            )
        },
    )

    self._remote_work_dir = None
    self._wifi_id_counter = itertools.count(0)
    self._last_reboot_error = None
    self._wan_interface = None

    self._ssh = self._create_ssh_client()
    self._wifi_manager = self._create_wifi_manager()
    self.services = service_manager.ServiceManager(device=self)
    self._package_manager = self._create_package_manager()
    self._sniffer_manager = None
    self._captive_portal_server = None
    self._is_torn_down = False

  @property
  def _log_prefix(self) -> str:
    return f'{self._DEVICE_TAG}|{self.serial}'

  @property
  def serial(self) -> str:
    return f'{self._hostname}:{self._ssh_port}'

  @property
  def _hostname(self) -> str:
    return self.config.hostname

  @property
  def _username(self) -> str:
    return self.config.username

  @property
  def _password(self) -> str | None:
    return self.config.password

  @property
  def _ssh_port(self) -> int:
    return self.config.ssh_port

  @property
  def _skip_init_reboot(self) -> bool:
    return self.config.skip_init_reboot

  @property
  def _skip_init_package_installation(self) -> bool:
    return self.config.skip_init_package_installation

  @property
  def wan_interface(self) -> str:
    """The WAN uplink interface name."""
    if self._wan_interface is None:
      self._wan_interface = self._detect_wan_interface()
    return self._wan_interface

  def _detect_wan_interface(self) -> str:
    """Detects the active WAN interface from OpenWrt UCI configuration."""
    wan_dev = self.ssh.execute_command(
        command=constants.Commands.GET_WAN_INTERFACE,
        timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
        ignore_error=True,
    )
    if wan_dev and wan_dev.strip():
      return wan_dev.strip()
    return constants.DEFAULT_WAN_INTERFACE

  def _create_wifi_manager(self) -> wifi_manager.WifiManagerProtocol:
    return wifi_manager.WiFiManager(device=self)

  def _create_package_manager(self) -> package_manager.PackageManagerProtocol:
    return package_manager.PackageManager(device=self)

  def __repr__(self) -> str:
    return f'<{self._log_prefix}>'

  def _create_ssh_client(self) -> ssh_lib.SSHProxy:
    return ssh_lib.SSHProxy(
        hostname=self._hostname,
        ssh_port=self._ssh_port,
        username=self._username,
        proxy_command=self.config.ssh_proxy_command,
        keyfile=_SSH_KEY_IDENTITY if self._password is None else None,
        password=self._password,
    )

  def start_captive_portal_server(
      self,
      use_opennds: bool = False,
  ) -> None:
    """Starts the captive portal server on the device.

    Configures captive portal and redirects localhost traffic to
    http://example.com. Only one captive portal server can be active on the
    device at a time. When opennds is used, it will be configured and started.
    Otherwise, the default captive portal server will be used. If a server is
    already active but with a different configuration (e.g. switching between
    OpenNDS and default server), it will be stopped first, and a new server of
    the requested type will be started instead.

    Args:
      use_opennds: Whether to configure and use opennds for captive portal.
    """
    if (
        self._captive_portal_server is not None
        and use_opennds != self._captive_portal_server.use_opennds
    ):
      self.log.info(
          'Stopping existing captive portal server to switch configurations.'
      )
      self.stop_captive_portal_server()

    if self._captive_portal_server is None:
      self._captive_portal_server = captive_portal_server.CaptivePortalServer(
          device=self, use_opennds=use_opennds
      )

    target_wifi_info = [
        comp.info for comp in self._wifi_manager.running_wifis.values()
    ]

    dhcp_lease_file = self._wifi_manager.get_dhcp_lease_file(
        target_wifi_info[0] if target_wifi_info else None
    )

    self._captive_portal_server.start_captive_portal_server(
        wifi_info=target_wifi_info,
        dhcp_lease_file=dhcp_lease_file,
    )

  def stop_captive_portal_server(self) -> None:
    """Stops the captive portal server on the device if one is running."""
    if self._captive_portal_server is not None:
      self._captive_portal_server.stop_captive_portal_server()
      self._captive_portal_server = None

  @property
  def wifi_id_counter(self) -> Iterator[int]:
    """The id counter of WiFi networks.

    This is a controller level counter and will not be reset until this
    controller object is teared down.

    Returns:
      The id counter.
    """
    return self._wifi_id_counter

  @property
  def remote_work_dir(self) -> str:
    """The path of the working directory on the AP device."""
    if self._remote_work_dir is None:
      time_str = mobly_logger.get_log_file_timestamp()
      self._remote_work_dir = os.path.join(
          constants.REMOTE_WORK_DIR, f'test-{time_str}'
      )
      self.make_dirs(self._remote_work_dir)
    return self._remote_work_dir

  def initialize(self):
    """Initializes this controller object.

    This method performs some one-off setup steps on the AP device.
    """
    os.chmod(_SSH_KEY_IDENTITY, 0o600)
    self._ssh.connect(
        open_sftp=False, timeout=self._SSH_CONNECTION_TIMEOUT.total_seconds()
    )
    if not self._skip_init_package_installation:
      self._package_manager.install_required_packages()

    if self._skip_init_reboot:
      self.log.info('Skipped reboot when initializing this controller object.')
      self._ssh.open_sftp()
      self._wifi_manager.initialize()
    else:
      # Fetch and cache device info before rebooting. This is important because
      # the reboot check command depends on whether the device is running a
      # custom image, which is determined during device info initialization.
      _ = self.device_info
      self.reboot()

    self._register_syslog_service()

  def reboot(self) -> None:
    """Reboots the device.

    Generally one should use this method to reboot the device instead of
    directly calling `ssh.execute_command('sudo reboot')`. Because this method
    gracefully handles the teardown and restoration of running services.

    This method is blocking and only returns when the reboot has completed
    and the services restored.
    """
    self.log.info('Rebooting AP device...')
    with self.handle_reboot():
      # Use execute_command_async here to avoid getting stuck in dangling
      # ssh connection during rebooting.
      self.ssh.execute_command_async(command=constants.Commands.REBOOT)
      time.sleep(self._DEVICE_REBOOT_WAIT.total_seconds())

  @contextlib.contextmanager
  def handle_reboot(self) -> Iterator[None]:
    """Properly manages the service life cycle when the device needs to reboot.

    The device can temporarily lose SSH connection due to user-triggered reboot.
    Use this function to make sure all Mobly components are properly stopped and
    restored afterwards.

    For sample usage, see self.reboot().

    Yields:
      None
    """
    self._wifi_manager.teardown()
    if self._sniffer_manager is not None:
      self._sniffer_manager.teardown()
      self._sniffer_manager = None

    is_captive_portal_server_running = (
        self._captive_portal_server is not None
        and self._captive_portal_server.is_alive
    )
    was_using_opennds = False
    if self._captive_portal_server is not None:
      was_using_opennds = self._captive_portal_server.use_opennds
    self.stop_captive_portal_server()
    live_services = self.services.list_live_services()
    self.services.stop_all()

    try:
      yield
    finally:
      self._wan_interface = None
      self._ssh.disconnect()
      self._wait_for_boot_completion()
      self.services.start_services(live_services)
      self._wifi_manager.initialize()
      if is_captive_portal_server_running:
        self.start_captive_portal_server(use_opennds=was_using_opennds)

  def _wait_for_boot_completion(self) -> None:
    """Waits for a ssh connection can be reestablished.

    Raises:
      Error: Raised if booting process timed out.
    """
    self._last_reboot_error = None
    if not wifi_utils.wait_for_predicate(
        predicate=self._is_reboot_ready,
        timeout=self._BOOT_STATUS_CHECK_TIMEOUT,
        interval=self._BOOT_STATUS_CHECK_INTERVAL,
    ):
      message = (
          f'{repr(self)} Booting process timed out after'
          f' {self._BOOT_STATUS_CHECK_TIMEOUT.total_seconds()} seconds.'
      )
      if self._last_reboot_error is not None:
        error_traceback = '\n'.join(
            traceback.format_exception(self._last_reboot_error)
        )
        message += f' Last error we caught:\n{error_traceback}'
      raise Error(message)

  def ssh_connect(self):
    """Connects to the device through ssh with sftp enabled."""
    self._ssh.connect(
        open_sftp=True,
        timeout=self._SSH_CONNECTION_TIMEOUT.total_seconds(),
    )

  @property
  def _reboot_check_command(self) -> str:
    """Returns the command to check if the device is ready after reboot."""
    if self.device_info.is_cros_image:
      return constants.Commands.CHECK_DEVICE_REBOOT_READY_CUSTOM_IMAGE
    return constants.Commands.CHECK_DEVICE_REBOOT_READY

  def _is_reboot_ready(self) -> bool:
    """Returns whether the device is ready after reboot."""
    try:
      self.ssh_connect()
      self._ssh.execute_command(
          self._reboot_check_command,
          timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
          ignore_error=False,
      )
      return True
    except (
        paramiko.ssh_exception.NoValidConnectionsError,
        paramiko.ssh_exception.SSHException,
        ConnectionResetError,
        TimeoutError,
        ssh_lib.ExecuteCommandError,
    ) as e:
      # ssh connect may fail during certain period of booting
      # process, which is normal. Ignoring these errors.
      self._last_reboot_error = e
      self.log.info('Waiting for device reboot completion.')
      self._ssh.disconnect()
      return False

  def _register_syslog_service(self):
    try:
      self.services.register(
          alias='syslog', service_class=system_log_service.SystemLogService
      )
    except Exception:  # pylint: disable=broad-except
      self.log.exception(
          'Failed to register system log service, no system logs will be'
          ' collected for this device.'
      )

  @property
  def device_info(self) -> device_info_lib.DeviceInfo:
    """Information to be pulled into controller info in the test summary."""
    if self._device_info is None:
      self._device_info = device_info_lib.DeviceInfo.from_device(self)
    return self._device_info

  @property
  def ssh(self) -> ssh_lib.SSHProxy:
    """The ssh connection to the AP device."""
    return self._ssh

  def make_dirs(self, remote_dir: str) -> None:
    """Recursively makes directories on the remote machine.

    Args:
      remote_dir: string, the remote directory.

    Raises:
      RuntimeError: a component in remote_dir is not a directory.
      SSHNotConnectedError: If sftp is not connected.
    """
    self.ssh.make_dirs(remote_dir)

  def push_file(
      self,
      local_src_filename: str,
      remote_dest_filename: str,
      change_permission: bool = False,
  ) -> None:
    """Pushes local file to the remote machine.

    Args:
      local_src_filename: the local file.
      remote_dest_filename: the destination file location in the remote machine.
      change_permission: whether to change the permission to 777 on remote
        destination.
    """
    self.ssh.push(local_src_filename, remote_dest_filename, change_permission)

  def remove_file(self, remote_path: str, ignore_error: bool = False) -> None:
    """Removes a file from the remote machine.

    Args:
      remote_path: The path to the file on the remote machine.
      ignore_error: Whether to ignore errors if command fails.
    """
    try:
      self.ssh.rm_file(remote_path)
    except Exception as e:  # pylint: disable=broad-except
      if not ignore_error:
        raise
      self.log.debug('Failed to remove file %s: %s', remote_path, e)

  def start_wifi_with_network_config(
      self, config: wifi_configs.NetworkConfig
  ) -> Sequence[wifi_configs.WifiInfo]:
    """Starts a WiFi networks with the given network configurations."""
    if self._sniffer_manager is not None and self._sniffer_manager.is_alive:
      raise Error(_ERR_USE_AS_BOTH_AP_AND_SNIFFER.format(device=self))

    return self._wifi_manager.start_wifi_with_network_config(config)

  def start_wifi(
      self, config: wifi_configs.WiFiConfig
  ) -> wifi_configs.WifiInfo:
    if self._sniffer_manager is not None and self._sniffer_manager.is_alive:
      raise Error(_ERR_USE_AS_BOTH_AP_AND_SNIFFER.format(device=self))
    return self._wifi_manager.start_wifi(config)

  def stop_wifi(self, wifi_info: wifi_configs.WifiInfo) -> None:
    self._wifi_manager.stop_wifi(wifi_info)

  def stop_all_wifi(self) -> None:
    self._wifi_manager.stop_all_wifi()

  def send_bss_tm_request(
      self,
      source_wifi_info: wifi_configs.WifiInfo,
      params: hostapd_manager.HostapdBssTmReqParams,
  ) -> str:
    """Sends a BSS Transition Management Request from the source AP.

    Args:
      source_wifi_info: The WifiInfo object for the source AP sending the
        request.
      params: The parameters for the BSS TM Request.

    Returns:
      The stdout from the hostapd_cli command.

    Raises:
      Error: If the source_wifi_info is not found among running Wi-Fi
        instances or if the associated HostapdManager is not found.
    """
    return self._wifi_manager.send_bss_tm_request(source_wifi_info, params)

  def set_hostapd_property(
      self, wifi_info: wifi_configs.WifiInfo, property_name: str, value: str
  ) -> None:
    """Sets the property of the hostapd daemon.

    This function modifies a specific property of the running hostapd instance.

    Args:
      wifi_info: The `WifiInfo` object for the AP whose property is to be set.
        This object's ID is used to identify the running hostapd instance.
      property_name: The name of the property to configure.
      value: The value of the property to set.
    """
    self._wifi_manager.set_hostapd_property(
        wifi_info, property_name=property_name, value=value
    )

  def channel_switch(
      self,
      wifi_info: wifi_configs.WifiInfo,
      target_channel: int,
      beacon_count: int = 1,
      optional_args: Sequence[str] | None = None,
  ) -> wifi_configs.WifiInfo | None:
    """Performs a channel switch from the current channel to the target channel.

    Args:
      wifi_info: The `WifiInfo` object for the AP whose channel is to be
        switched.
      target_channel: The target channel to switch to.
      beacon_count: The number of beacons to send before switching channels.
      optional_args: Optional arguments to pass to the hostapd_cli chan-switch
        command.

    Returns:
      The updated `WifiInfo` with the new channel and frequency.
    """
    return self._wifi_manager.channel_switch(
        wifi_info,
        target_channel=target_channel,
        beacon_count=beacon_count,
        optional_args=optional_args,
    )

  def turn_off_radio(self, wifi_info: wifi_configs.WifiInfo) -> None:
    """Turns off radio of a running Wi-Fi to simulate abrupt AP power-off.

    This method stops beacon and radio frame transmissions immediately via
    `hostapd_cli disable` without sending deauthentication frames to connected
    clients or tearing down interfaces/configurations. The specified Wi-Fi
    network must be currently running. Unlike `stop_wifi`, which gracefully
    shuts down hostapd and deauthenticates stations, `turn_off_radio` is used to
    test client behavior when an AP suddenly disappears (e.g., missing beacon
    detection, auto-connect recovery).

    Args:
      wifi_info: The `WifiInfo` object for the running Wi-Fi network whose radio
        transmission should be turned off.

    Raises:
      Error: If the `wifi_info` is not found among running Wi-Fi instances.
    """
    self._wifi_manager.turn_off_radio(wifi_info)

  def get_all_known_stations(
      self, wifi_info: wifi_configs.WifiInfo
  ) -> Sequence[iw_utils.Station]:
    """Gets all the known stations associated with the given WiFi network.

    Clients connected to WiFi network are part of stations.

    Args:
      wifi_info: The WiFi network to query the known stations.

    Returns:
      The sequence of all known stations.
    """
    return iw_utils.get_all_known_stations(
        device=self, interface=wifi_info.interface
    )

  def get_station_info(
      self, wifi_info: wifi_configs.WifiInfo, mac_address: str
  ) -> iw_utils.Station:
    """Gets info for the station with the given MAC address.

    Clients connected to WiFi network are part of stations.

    Args:
      wifi_info: The WiFi network to query the known stations.
      mac_address: The MAC address of the station.

    Returns:
      The information for the specified station.

    Raises:
      iw_utils.NoSuchStationError: Failed to find the specified station.
    """
    return iw_utils.get_station_info(
        device=self, interface=wifi_info.interface, mac_address=mac_address
    )

  def restart_dhcp_server(self, interface: str | None = None) -> None:
    """Restarts the DHCP server for the given interface or running networks.

    Args:
      interface: The interface name (e.g. wlan0, br-lan) whose DHCP server
        should be restarted. If None, restarts DHCP for all running networks.
    """
    if self._wifi_manager is not None:
      self._wifi_manager.restart_dhcp_server(interface)

  def get_all_wifi_ssid(self) -> Sequence[str]:
    """Gets all currently broadcasting Wi-Fi SSIDs."""
    return [
        interface.ssid
        for interface in iw_utils.get_all_interfaces(self)
        if interface.type == 'AP' and interface.ssid is not None
    ]

  def _get_or_init_sniffer_manager(
      self,
  ) -> sniffer_manager.SnifferManagerProtocol:
    """Gets the sniffer manager instance; Initializes it if not yet."""
    if self._sniffer_manager is None:
      self._sniffer_manager = sniffer_manager.SnifferManager(device=self)
      self._sniffer_manager.initialize()
    return self._sniffer_manager

  def start_packet_capture(
      self,
      network_config: wifi_configs.NetworkConfig | None = None,
      wifi_config: wifi_configs.WiFiConfig | None = None,
      freq_config: wifi_configs.FreqConfig | None = None,
      capture_config: wifi_configs.PcapConfig | None = None,
  ) -> None:
    """Starts packet capture on a specific channel.

    You need to provide either wifi_config or freq_config. If you provide
    `freq_config`, this will monitor the frequency band specified by it. If you
    provide `wifi_config`, this method will extract channel info from it and
    monitor the same channel that is used by the WiFi network.

    Args:
      network_config: The WiFi network to capture the packets.
      wifi_config: The WiFi network to capture the packets.
      freq_config: The frequency to capture the packets.
      capture_config: The configuration to control the packet capture process.

    Raises:
      Error: If not exactly one of network_config, wifi_config, or freq_config
        is provided.
    """
    if (
        sum((
            network_config is not None,
            wifi_config is not None,
            freq_config is not None,
        ))
        != 1
    ):
      raise Error(_ERR_START_PACKET_CAPTURE_ARG_ERROR.format(device=self))
    if self._wifi_manager.is_alive:
      raise Error(_ERR_USE_AS_BOTH_AP_AND_SNIFFER.format(device=self))

    manager = self._get_or_init_sniffer_manager()
    if network_config is not None:
      manager.start_packet_capture_with_network_config(
          network_config=network_config, capture_config=capture_config
      )
    elif wifi_config is not None:
      manager.start_packet_capture_with_wifi_config(
          wifi_config=wifi_config, capture_config=capture_config
      )
    elif freq_config is not None:
      manager.start_capture(
          freq_config=freq_config, capture_config=capture_config  # pyrefly: ignore[bad-argument-type]
      )

  def stop_packet_capture(
      self,
      current_test_info: runtime_test_info.RuntimeTestInfo | None = None,
      band_type: wifi_configs.BandType | None = None,
  ):
    """Stops packet capture.

    Stops packet capture on the band specified, or all bands if no band is
    specified.

    Args:
      current_test_info: If provided, this will move the captured packets to
        `current_test_info.output_path`. Otherwise the captured packets will be
        removed.
      band_type: The band on which to stop packet capture.
    """
    self._get_or_init_sniffer_manager().stop_capture(
        current_test_info=current_test_info, band_type=band_type
    )

  def get_capture_file(self) -> str | None:
    """Gets the full path of the last capture."""
    capture_files = self._get_or_init_sniffer_manager().get_capture_files()
    if capture_files is None:
      return None
    if len(capture_files) > 1:
      self.log.warning(
          'Multiple capture files found, returning the first one: %s',
          capture_files,
      )
    return capture_files[0]

  def add_station_interface(
      self, phy_name: str, iface_name: str, mac_address: str
  ) -> None:
    """Adds a virtual station interface to the given phy.

    If the interface succeeds to be created, but fails to be configured or
    brought up, deletion is initiated.

    Args:
      phy_name: The name of the physical device to add interface to.
      iface_name: The name of the virtual interface to add.
      mac_address: The MAC address to assign to the new interface.

    Raises:
      Error: If the interface fails to be created or come up after being added.
    """
    try:
      self.ssh.execute_command(
          constants.Commands.IW_DEV_ADD.format(
              phy=phy_name, interface=iface_name
          )
      )
    except ssh_lib.ExecuteCommandError as e:
      raise Error(f'Failed to create interface {iface_name}: {e}') from e
    try:
      self.ssh.execute_command(
          constants.Commands.IP_LINK_SET_ADDRESS.format(
              interface=iface_name, mac_address=mac_address
          )
      )
      self.ssh.execute_command(
          constants.Commands.IP_LINK_UP.format(interface=iface_name)
      )
    except ssh_lib.ExecuteCommandError as e:
      self.delete_interface(iface_name)
      raise Error(f'Failed to bring up interface {iface_name}: {e}') from e

  def delete_interface(self, iface_name: str) -> None:
    """Deletes a virtual interface.

    Args:
      iface_name: The name of the virtual interface to delete.
    """
    self.ssh.execute_command(
        constants.Commands.IW_DEV_DEL.format(interface=iface_name),
        ignore_error=True,
    )

  def _log_certificate_info(self, cert_file: pathlib.PurePosixPath) -> None:
    """Logs the certificate information to the syslog.

    Args:
      cert_file: The path to the certificate file to log.
    """
    cmd = (
        f"openssl x509 -in '{cert_file}' -noout -text 2>&1 | "
        'logger -t openssl-test'
    )
    self.ssh.execute_command(command=cmd, ignore_error=True)

  def upload_certificates(
      self, cert: certificate.Certificate
  ) -> certificate.CertificatesData:
    """Uploads certificates to the router.

    Args:
      cert: The certificate content to upload.

    Returns:
      CertificatesData containing the paths on the router.
    """
    suffix = mobly_logger.get_log_file_timestamp()
    work_dir = self.remote_work_dir

    work_path = pathlib.PurePosixPath(work_dir)
    ca_cert_file = work_path / f'ca_cert_{suffix}.pem'
    cert_file = work_path / f'cert_{suffix}.pem'
    key_file = work_path / f'key_{suffix}.pem'
    eap_user_file = (
        work_path / f'eap_user_{suffix}.conf' if cert.eap_users else None
    )

    def _push_content(content: str, dest_path: pathlib.PurePosixPath):
      with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp:
        tmp.write(content)
        tmp_name = tmp.name
      try:
        self.push_file(tmp_name, str(dest_path), change_permission=True)
      finally:
        os.remove(tmp_name)

    _push_content(cert.ca_cert, ca_cert_file)
    _push_content(cert.cert, cert_file)
    _push_content(cert.private_key, key_file)
    if cert.eap_users and eap_user_file is not None:
      _push_content(cert.eap_users, eap_user_file)

    self._log_certificate_info(ca_cert_file)

    return certificate.CertificatesData(
        ca_cert_file=ca_cert_file,
        cert_file=cert_file,
        key_file=key_file,
        eap_user_file=eap_user_file,
        suffix=suffix,
    )

  def remove_certificates(
      self, cert_data: certificate.CertificatesData
  ) -> None:
    """Removes certificates from the router.

    Args:
      cert_data: The certificates data containing paths to remove.
    """
    self.remove_file(str(cert_data.ca_cert_file), ignore_error=True)
    self.remove_file(str(cert_data.cert_file), ignore_error=True)
    self.remove_file(str(cert_data.key_file), ignore_error=True)
    if cert_data.eap_user_file:
      self.remove_file(str(cert_data.eap_user_file), ignore_error=True)

  def teardown(self):
    """Tears the device object down."""
    if self._is_torn_down:
      return
    self._is_torn_down = True

    self.log.info('Tearing down the controller.')
    if self._sniffer_manager is not None:
      self._sniffer_manager.teardown()
      self._sniffer_manager = None
    # Stop the captive portal server before tearing down the WiFi manager
    # because stopping the captive portal restores the network configuration by
    # restarting the DHCP server on active WiFi interfaces. If WiFi manager is
    # torn down first, the DHCP server restarted during stop will be left
    # running as an orphaned process on the device port.
    self.stop_captive_portal_server()
    self._wifi_manager.teardown()
    self._ssh.disconnect()
