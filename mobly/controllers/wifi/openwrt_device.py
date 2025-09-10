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

from collections.abc import Iterator, Mapping, Sequence
import contextlib
import dataclasses
import datetime
import ipaddress
import itertools
import logging
import os
import time
import traceback
from typing import Any

from mobly import logger as mobly_logger
from mobly import runtime_test_info
from mobly import utils
from mobly.controllers.android_device_lib import service_manager
import paramiko

from mobly.controllers.wifi.lib import ssh as ssh_lib
from mobly.controllers.wifi.lib import constants
from mobly.controllers.wifi.lib import device_info_utils
from mobly.controllers.wifi.lib import hostapd_manager
from mobly.controllers.wifi.lib import iw_utils
from mobly.controllers.wifi.lib import sniffer_manager
from mobly.controllers.wifi.lib import utils as wifi_utils
from mobly.controllers.wifi.lib import wifi_configs
from mobly.controllers.wifi.lib import wifi_manager
from mobly.controllers.wifi.lib.services import system_log_service
from mobly.controllers.wifi.utils import ip_utils


MOBLY_CONTROLLER_CONFIG_NAME = 'OpenWrtDevice'

_SSH_KEY_IDENTITY = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'data/testing_rsa'
)
_SSH_PORT = 22
_DEVICE_TAG = MOBLY_CONTROLLER_CONFIG_NAME

_DEVICE_REBOOT_WAIT = datetime.timedelta(seconds=10)
_BOOT_STATUS_CHECK_INTERVAL = datetime.timedelta(seconds=5)
_BOOT_STATUS_CHECK_TIMEOUT = datetime.timedelta(minutes=5)
_SSH_CONNECTION_TIMEOUT = datetime.timedelta(minutes=5)


_ERR_USE_AS_BOTH_AP_AND_SNIFFER = (
    "{device} It's not supported to use one OpenWrt device as both AP and"
    ' sniffer at the same time.'
)

_ERR_START_PACKET_CAPTURE_ARG_ERROR = (
    '{device} Exactly one of wifi_config and freq_config must be provided.'
)


class Error(Exception):
  """Error class for the OpenWrtDevice controller."""


def create(configs: list[dict[str, Any]]) -> list['OpenWrtDevice']:
  """Creates OpenWrt device instances."""
  if not configs:
    raise Error(f'Missing configuration {configs!r}.')
  devices = [OpenWrtDevice(config) for config in configs]
  devices = _initialize_devices(devices)
  return devices


def destroy(devices: list['OpenWrtDevice']) -> None:
  """Closes all created OpenWrt device instances."""
  for device in devices:
    try:
      device.teardown()
    except Exception:  # pylint: disable=broad-except
      logging.exception('Failed to clean up properly.')


def get_info(devices: Sequence['OpenWrtDevice']) -> Sequence[Mapping[str, Any]]:
  """Gets info from the OpenWrt device instances used in a test run.

  Args:
    devices: A list of OpenWrt device instances.

  Returns:
    A list of dict, each representing info for a device object.
  """
  return [d.device_info for d in devices]


def _initialize_devices(
    devices: Sequence['OpenWrtDevice'],
) -> list['OpenWrtDevice']:
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


@dataclasses.dataclass(frozen=True, kw_only=True)
class IpInterface:
  """IP Interface class for OpenWrt device.

  Attributes:
    id: The interface id.
    name: The interface name.
    type: The interface type.
    mac_address: The MAC address of the interface.
    state: The state of the interface.
    virtual_of: The interface that this interface is virtual of.
    bridge: The bridge of the interface.
    ip: The IPv4 address of the interface.
    subnet: The IPv4 subnet of the interface.
    iw_interface: The interface information from `iw dev` command if this
      interface is a wireless interface.
  """
  id: int
  name: str
  type: str
  mac_address: str
  state: str
  virtual_of: str | None = None
  bridge: str | None = None
  ip: ipaddress.IPv4Address | None = None
  subnet: ipaddress.IPv4Network | None = None
  iw_interface: iw_utils.Interface | None = None


class OpenWrtDevice:
  """Mobly controller for AP devices running on the OpenWrt system.

  Attributes:
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

  def __init__(self, config: dict[str, Any]):
    if 'hostname' not in config:
      raise Error(
          'Missing required field "hostname" in device configuration'
          f' {config!r}.'
      )
    self._hostname = config['hostname']
    self._username = config.get('username', constants.SSH_USERNAME)
    self._password = config.get('password', None)
    self._ssh_port = config.get('ssh_port', _SSH_PORT)
    self._skip_init_reboot = wifi_utils.convert_testbed_bool_value(
        config.get('skip_init_reboot', False)
    )
    self._skip_init_package_installation = (
        wifi_utils.convert_testbed_bool_value(
            config.get('skip_init_package_installation', False)
        )
    )
    self.serial = f'{self._hostname}:{self._ssh_port}'
    self._device_info = None

    log_path = getattr(logging, 'log_path', '/tmp/logs')
    log_filename = mobly_logger.sanitize_filename(
        f'{_DEVICE_TAG}_{self.serial}'
    )
    self.log_path = os.path.join(log_path, log_filename)
    utils.create_dir(self.log_path)

    self.log = mobly_logger.PrefixLoggerAdapter(
        logging.getLogger(),
        {
            mobly_logger.PrefixLoggerAdapter.EXTRA_KEY_LOG_PREFIX: (
                f'[{_DEVICE_TAG}|{self.serial}]'
            )
        },
    )

    self._remote_work_dir = None
    self._wifi_id_counter = itertools.count(0)
    self._last_reboot_error = None

    self._ssh = self._create_ssh_client()
    self._wifi_manager = wifi_manager.WiFiManager(device=self)
    self.services = service_manager.ServiceManager(device=self)
    self._sniffer_manager = sniffer_manager.SnifferManager(device=self)

  def __repr__(self) -> str:
    return f'<{_DEVICE_TAG}|{self.serial}>'

  def _create_ssh_client(self) -> ssh_lib.SSHProxy:
    if self._password is None:
      return ssh_lib.SSHProxy(
          hostname=self._hostname,
          ssh_port=self._ssh_port,
          username=self._username,
          keyfile=_SSH_KEY_IDENTITY,
      )
    else:
      return ssh_lib.SSHProxy(
          hostname=self._hostname,
          ssh_port=self._ssh_port,
          username=self._username,
          password=self._password,
      )

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
        open_sftp=False, timeout=_SSH_CONNECTION_TIMEOUT.total_seconds()
    )

    packages = self._get_required_packages()
    for pkg in packages:
      self._install_package(pkg)

    if self._skip_init_reboot:
      self.log.info('Skipped reboot when initializing this controller object.')
      self._ssh.open_sftp()
      self._wifi_manager.initialize()
      self._sniffer_manager.initialize()
    else:
      self.reboot()

    self._register_syslog_service()

  def _get_required_packages(self) -> Sequence[str]:
    """Returns all required OpenWrt packages for this device."""
    if self._skip_init_package_installation:
      return tuple()

    if self.device_info.get(
        'device_name', None
    ) == constants.ApModel.BPIR3 and wifi_utils.is_using_custom_image(
        device=self
    ):
      return constants.REQUIRED_PACKAGES_BPIR3_AND_CROS_BUILT_IMAGE

    if wifi_utils.is_using_openwrt_snapshot_image(self.device_info['release']):
      # By default, the controller should not install any packages on a snapshot
      # image.
      return tuple()

    return constants.REQUIRED_PACKAGES_RELEASED_IMAGE

  def _install_package(self, package: str):
    """Installs a package on the device through `opkg`."""
    result = self.ssh.execute_command(
        command=constants.Commands.OPKG_LIST.format(package=package),
        timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
    )
    if package in result:
      self.log.debug('Package %s is already installed.', package)
      return
    self.ssh.execute_command(
        command=constants.Commands.OPKG_UPDATE,
        timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
    )
    self.ssh.execute_command(
        command=constants.Commands.OPKG_INSTALL.format(package=package),
        timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
    )

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
      time.sleep(_DEVICE_REBOOT_WAIT.total_seconds())

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
    try:
      yield
    finally:
      self._ssh.disconnect()
      self._wait_for_boot_completion()
      self._wifi_manager.initialize()
      self._sniffer_manager.initialize()

  def _wait_for_boot_completion(self) -> None:
    """Waits for a ssh connection can be reestablished.

    Raises:
      Error: Raised if booting process timed out.
    """
    self._last_reboot_error = None
    if not wifi_utils.wait_for_predicate(
        predicate=self._is_reboot_ready,
        timeout=_BOOT_STATUS_CHECK_TIMEOUT,
        interval=_BOOT_STATUS_CHECK_INTERVAL,
    ):
      message = (
          f'{repr(self)} Booting process timed out after'
          f' {_BOOT_STATUS_CHECK_TIMEOUT.total_seconds()} seconds.'
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
        timeout=_SSH_CONNECTION_TIMEOUT.total_seconds(),
    )

  def _is_reboot_ready(self) -> bool:
    """Returns whether the device is ready after reboot."""
    try:
      self.ssh_connect()
      self._ssh.execute_command(
          constants.Commands.CHECK_DEVICE_REBOOT_READY,
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

  def __del__(self):
    self.teardown()

  @property
  def device_info(self) -> Mapping[str, str]:
    """Information to be pulled into controller info in the test summary."""
    if self._device_info is None:
      self._device_info = device_info_utils.get_device_info(device=self) | {
          'serial': self.serial
      }
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

  def start_wifi(
      self, config: wifi_configs.WiFiConfig
  ) -> wifi_configs.WifiInfo:
    if self._sniffer_manager.is_alive:
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
        wifi_info, property_name, value
    )

  def channel_switch(
      self,
      wifi_info: wifi_configs.WifiInfo,
      target_channel: int,
      beacon_count: int = 1,
      optional_args: Sequence[str] | None = None,
  ) -> None:
    """Performs a channel switch from the current channel to the target channel.

    Args:
      wifi_info: The `WifiInfo` object for the AP whose channel is to be
        switched.
      target_channel: The target channel to switch to.
      beacon_count: The number of beacons to send before switching channels.
      optional_args: Optional arguments to pass to the hostapd_cli chan-switch
        command.
    """
    self._wifi_manager.channel_switch(
        wifi_info, target_channel, beacon_count, optional_args
    )

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

  def get_interface_ip_iw_map(self) -> Mapping[str, IpInterface]:
    """Gets all interfaces and their information.

    This method also correlates the information from `iw dev` command with the
    information from `ip addr show` command to get the wireless interface
    information on matched interface names.

    Returns:
      A mapping of interface name to interface information.
    """
    interfaces: Sequence[ip_utils.IpAddrInterface] = (
        ip_utils.get_all_ip_addr_interfaces(self)
    )
    iw_interfaces = iw_utils.get_all_interfaces(self)
    iw_interfaces_map = {
        interface.name: interface for interface in iw_interfaces
    }
    # IP address is in the format of `ip_addr/mask_len`.
    parse_ipv4_addr = (
        lambda ip_addr: ipaddress.IPv4Address(ip_addr.split('/')[0])
        if ip_addr is not None
        else None
    )

    parse_subnet_addr = (
        lambda subnet_addr: ipaddress.IPv4Network(subnet_addr, strict=False)
        if subnet_addr is not None
        else None
    )

    return {
        intf.name: IpInterface(
            id=intf.id,
            name=intf.name,
            type=intf.link_type,
            mac_address=intf.mac_address,
            state=intf.state,
            ip=parse_ipv4_addr(intf.ipv4_address),
            subnet=parse_subnet_addr(intf.ipv4_address),
            iw_interface=iw_interfaces_map.get(intf.name),
        ) for intf in interfaces
    }

  def get_all_wifi_ssid(self) -> Sequence[str]:
    """Gets all currently broadcasting Wi-Fi SSIDs."""
    return [
        interface.ssid
        for interface in iw_utils.get_all_interfaces(self)
        if interface.type == 'AP' and interface.ssid is not None
    ]

  def start_packet_capture(
      self,
      wifi_config: wifi_configs.WiFiConfig | None = None,
      freq_config: wifi_configs.FreqConfig | None = None,
      capture_config: wifi_configs.PcapConfig | None = None,
  ):
    """Starts pacaket capture on a specific channel.

    You need to provide either wifi_config or freq_config. If you provide
    `freq_config`, this will monitor the frequency band specified by it. If you
    provide `wifi_config`, this method will extract channel info from it and
    monitor the same channel that is used by the WiFi network.

    Args:
      wifi_config: The WiFi network to capture the packets.
      freq_config: The frequency to capture the packets.
      capture_config: The configuration to control the packet capture process.

    Raises:
      Error: If both wifi_config and freq_config are provided or not provided.
    """
    if sum([wifi_config is not None, freq_config is not None]) != 1:
      raise Error(_ERR_START_PACKET_CAPTURE_ARG_ERROR.format(device=self))
    if self._wifi_manager.is_alive:
      raise Error(_ERR_USE_AS_BOTH_AP_AND_SNIFFER.format(device=self))

    if wifi_config is not None:
      freq_config = wifi_configs.get_freq_config(wifi_config)
    self._sniffer_manager.start_capture(
        freq_config=freq_config, capture_config=capture_config
    )

  def stop_packet_capture(
      self,
      current_test_info: runtime_test_info.RuntimeTestInfo | None = None,
      band_type: wifi_configs.BandType | None = None,
  ):
    """Stops packet capture on the band specified, or all bands if no band is specified."""
    self._sniffer_manager.stop_capture(
        current_test_info=current_test_info, band_type=band_type
    )

  def get_capture_file(self) -> str | None:
    """Gets the full path of the last capture."""
    return self._sniffer_manager.get_capture_file()

  def teardown(self):
    """Tears the device object down."""
    self.log.info('Tearing down the controller.')
    self._sniffer_manager.teardown()
    self._wifi_manager.teardown()
    self._ssh.disconnect()
