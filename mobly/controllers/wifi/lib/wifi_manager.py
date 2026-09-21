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

"""The module for managing the lifecycle of WiFi networks.

This is entry point for WiFi network level management, i.e., start / stop / get
WiFi network status.
"""

from collections.abc import Sequence
import contextlib
import dataclasses
import datetime
from typing import Any, Mapping, Protocol

from mobly import logger as mobly_logger

from mobly.controllers.wifi.lib import ssh as ssh_lib
from mobly.controllers.wifi.lib import constants
from mobly.controllers.wifi.lib import dhcp_manager
from mobly.controllers.wifi.lib import errors
from mobly.controllers.wifi.lib import firewall_manager
from mobly.controllers.wifi.lib import hostapd_manager
from mobly.controllers.wifi.lib import iw_utils
from mobly.controllers.wifi.lib import wifi_configs


class WifiManagerProtocol(Protocol):
  """Protocol for managing WiFi networks on AP devices."""

  def initialize(self) -> None:
    """Initializes the AP device to be ready for starting WiFi networks.

    This method should be called after each AP device reboot.
    """
    ...

  def start_wifi(
      self, config: wifi_configs.WiFiConfig
  ) -> wifi_configs.WifiInfo:
    """Starts a WiFi network with the given configurations."""
    ...

  def start_wifi_with_network_config(
      self, config: wifi_configs.NetworkConfig
  ) -> Sequence[wifi_configs.WifiInfo]:
    """Starts a WiFi network with the given network configurations."""
    ...

  def stop_wifi(self, wifi_info: wifi_configs.WifiInfo) -> None:
    """Stops the given WiFi network."""
    ...

  def stop_all_wifi(self) -> None:
    """Stops all running WiFi."""
    ...

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
    """
    ...

  def set_hostapd_property(
      self, wifi_info: wifi_configs.WifiInfo, *, property_name: str, value: str
  ) -> None:
    """Sets the property of the hostapd daemon.

    This function modifies a specific property of the running hostapd instance.

    Args:
      wifi_info: The `WifiInfo` object for the AP whose property is to be set.
        This object's ID is used to identify the running hostapd instance.
      property_name: The name of the property to set.
      value: The value to assign to the specified property.
    """
    ...

  def channel_switch(
      self,
      wifi_info: wifi_configs.WifiInfo,
      *,
      target_channel: int,
      beacon_count: int,
      optional_args: Sequence[str] | None = None,
  ) -> wifi_configs.WifiInfo | None:
    """Performs a channel switch from the current channel to the target channel.

    Args:
      wifi_info: The `WifiInfo` object for the AP whose channel is to be
        switched.
      target_channel: The target channel to switch to.
      beacon_count: The number of beacons to send before switching channels.
      optional_args: Optional arguments to pass to the hostapd_cli command.

    Returns:
      The updated `WifiInfo` with the new channel and frequency.
    """
    ...

  def turn_off_radio(self, wifi_info: wifi_configs.WifiInfo) -> None:
    """Turns off radio of a running Wi-Fi to simulate abrupt AP power-off.

    This method stops beacon and radio frame transmissions immediately via
    `hostapd_cli disable` without sending deauthentication frames to connected
    clients or tearing down interfaces/configurations.

    Args:
      wifi_info: The `WifiInfo` object for the running AP whose radio is to be
        turned off.
    """
    ...

  def teardown(self) -> None:
    """Tears this WiFi manager down and stops all running WiFi."""
    ...

  @property
  def is_alive(self) -> bool:
    """True if there are any running WiFi networks, False otherwise."""
    ...

  @property
  def running_wifis(self) -> Mapping[int, Any]:
    """Gets all running WiFi networks."""
    ...

  def restart_dhcp_server(self, interface: str | None = None) -> None:
    """Restarts the DHCP server for the specified interface or all running networks."""
    ...

  def get_dhcp_lease_file(
      self, wifi_info: wifi_configs.WifiInfo | None = None
  ) -> str | None:
    """Returns the remote path of the DHCP lease file for the network or AP."""
    ...


# Avoid directly importing OpenWrtDevice, which causes circular dependencies
OpenWrtDevice = Any


WIFI_START_WAIT_TIME = datetime.timedelta(seconds=30)
# DFS channels require 60s extra start time to check channel availability.
WIFI_START_WAIT_TIME_DFS = datetime.timedelta(seconds=180)


@dataclasses.dataclass
class WiFiComponents:
  """The data class that combines all components related to one WiFi network.

  Attributes:
    info: The WiFi network information.
    config: The user specified WiFi configurations.
    hostapd_manager: The hostapd manager instance.
    dhcp_manager: The dhcp manager instance.
  """

  info: wifi_configs.WifiInfo
  config: wifi_configs.WiFiConfig
  hostapd_manager: hostapd_manager.HostapdManager
  dhcp_manager: dhcp_manager.DhcpManager | None


class WiFiManager:
  """The class for managing the lifecycle of WiFi networks.

  This class is the entry point of WiFi network level management, i.e., start /
  stop / get WiFi status. To manage WiFi networks, this class utilizes other
  modules like hostapd_manager, dhcp_manager to manage instances running on AP
  devices.
  """

  _running_wifis: dict[int, WiFiComponents]
  _was_system_dnsmasq_enabled: bool
  _system_dnsmasq_active: bool

  @property
  def running_wifis(self) -> Mapping[int, WiFiComponents]:
    """Gets all running WiFi networks."""
    return self._running_wifis

  @property
  def wan_interface(self) -> str:
    """The WAN uplink interface name."""
    if self._wan_interface is not None:
      return self._wan_interface
    return self._device.wan_interface

  def _is_system_dnsmasq_enabled(self) -> bool:
    """Returns True if system dnsmasq was originally enabled on the device."""
    try:
      self._device.ssh.execute_command(
          command=constants.Commands.DNSMASQ_ENABLED,
          timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
      )
      return True
    except (ssh_lib.ExecuteCommandError, ssh_lib.SSHRemoteError):
      return False

  def set_dnsmasq(self, enabled: bool) -> None:
    """Enables/starts or disables/stops the system dnsmasq service."""
    command = (
        constants.Commands.DNSMASQ_ENABLE_AND_START
        if enabled
        else constants.Commands.DNSMASQ_DISABLE_AND_STOP
    )
    self._device.ssh.execute_command(
        command=command,
        timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
        ignore_error=True,
    )
    self._system_dnsmasq_active = enabled

  def restart_dhcp_server(self, interface: str | None = None) -> None:
    """Restarts the DHCP server for the specified interface or all running networks.

    Args:
      interface: The interface name (e.g. wlan0, br-lan) whose DHCP server
        should be restarted. If None, restarts DHCP for all running networks.
    """
    is_valid_comp = lambda comp: interface is None or interface in [
        comp.info.interface,
        comp.info.bridge,
    ]
    target_comps = [
        comp for comp in self._running_wifis.values() if is_valid_comp(comp)
    ]

    restarted_interfaces = []
    for comp in target_comps:
      if comp.dhcp_manager is not None:
        comp.dhcp_manager.start()
        restarted_interfaces.append(comp.info.source_iface)

    if restarted_interfaces:
      self._log.debug(
          'Successfully restarted DHCP server for interfaces %s.',
          restarted_interfaces,
      )
    else:
      self._log.debug(
          'No DHCP manager found to restart for interface %s.', interface
      )

  def get_dhcp_lease_file(
      self, wifi_info: wifi_configs.WifiInfo | None = None
  ) -> str | None:
    """Returns the remote path of the DHCP lease file.

    Args:
      wifi_info: Optional WifiInfo object to get the lease file for. If None,
        returns the lease file for the first running Wi-Fi network with an
        active DHCP manager.

    Returns:
      The remote path of the DHCP lease file, or None if no DHCP manager is
      active.
    """
    if wifi_info is not None:
      comp = self._running_wifis.get(wifi_info.id)
      if comp is not None and comp.dhcp_manager is not None:
        return comp.dhcp_manager.get_lease_file_path()
      return None

    for comp in self._running_wifis.values():
      if comp.dhcp_manager is not None:
        return comp.dhcp_manager.get_lease_file_path()
    return None

  def __init__(
      self,
      device: 'OpenWrtDevice',
      firewall: firewall_manager.FirewallProtocol | None = None,
      wan_interface: str | None = None,
  ):
    self._device = device
    self._id_counter = device.wifi_id_counter
    self._running_wifis = {}
    self._wan_interface = wan_interface or None
    self._firewall = firewall or firewall_manager.Firewall(device.ssh)
    self._was_system_dnsmasq_enabled = False
    self._system_dnsmasq_active = False
    self._is_torn_down = False

    self._log = mobly_logger.PrefixLoggerAdapter(
        device.log,
        {
            mobly_logger.PrefixLoggerAdapter.EXTRA_KEY_LOG_PREFIX: (
                '[WiFiManager]'
            )
        },
    )

  def initialize(self):
    """Initializes the AP device to be ready for starting WiFi networks.

    This method should be called after each AP device reboot.
    """
    self._was_system_dnsmasq_enabled = self._is_system_dnsmasq_enabled()
    self.set_dnsmasq(enabled=False)

    # Kill any existing hostapd instances.
    self._device.ssh.execute_command(
        command=constants.Commands.KILLALL.format(name=constants.HOSTAPD),
        timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
        ignore_error=True,
    )

    # Kill any existing dnsmasq instances.
    self._device.ssh.execute_command(
        command=constants.Commands.KILLALL.format(name=constants.DNSMASQ),
        timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
        ignore_error=True,
    )

    # We don't need to remove these firewall rule modifications in teardown
    # phase because device reboot automatically reset them.
    # Enable the kernel to route packets between different networks.
    self._firewall.allow_ip_forward()

    # Enable NAT, i.e., outbound traffic through the WAN interface will have its
    # source addr replaced with the WAN interface.
    self._firewall.enable_nat(self.wan_interface)

  @property
  def is_alive(self) -> bool:
    """True if there are any running WiFi networks, False otherwise."""
    return bool(self._running_wifis)

  def start_wifi_with_network_config(
      self, config: wifi_configs.NetworkConfig
  ) -> Sequence[wifi_configs.WifiInfo]:
    """Starts a WiFi network with the given network configurations."""
    if config.mlo_config is not None:
      raise errors.ConfigError('mlo_config is not supported yet.')
    return [self.start_wifi(wifi_config) for wifi_config in config.wifi_configs]

  def start_wifi(
      self, config: wifi_configs.WiFiConfig
  ) -> wifi_configs.WifiInfo:
    """Starts a WiFi network with the given configurations."""
    if config.band_type == wifi_configs.BandType.BAND_6G:
      raise errors.ConfigError('band_type BAND_6G is not supported yet.')
    if config.access_wan_through_nat and self._system_dnsmasq_active:
      raise errors.ConfigError(
          'Cannot start WiFi with access_wan_through_nat=True while system'
          ' dnsmasq is active for another WiFi network with'
          ' access_wan_through_nat=False.'
      )
    if not config.access_wan_through_nat and any(
        comp.dhcp_manager is not None for comp in self._running_wifis.values()
    ):
      raise errors.ConfigError(
          'Cannot start WiFi with access_wan_through_nat=False while'
          ' DhcpManager is running for another WiFi network with'
          ' access_wan_through_nat=True.'
      )

    wifi_id = next(self._id_counter)
    self._log.debug(
        'Starting a WiFi network (id=%d) with config: %s', wifi_id, config
    )

    try:
      return self._start_wifi(wifi_id, config)
    except (ssh_lib.SSHRemoteError, errors.BaseError):
      self._log.error(
          'Cleaning up allocated resources for WiFi network (id=%d) due to'
          ' start failure.',
          wifi_id,
      )
      if (component := self._running_wifis.pop(wifi_id, None)) is not None:
        with contextlib.suppress(errors.BaseError, ssh_lib.SSHRemoteError):
          self._stop_wifi(component=component)
      raise

  def _start_wifi(
      self, wifi_id: int, config: wifi_configs.WiFiConfig
  ) -> wifi_configs.WifiInfo:
    """Performs the device operations to start a specified WiFi network."""
    self._print_debug_info_before_starting_wifi()
    self._set_country_code(config.country_code)
    # Parse phy info after setting country code because hardware capabilities
    # are affected by country code.
    phys = iw_utils.get_all_phys(self._device)
    phy = iw_utils.get_phy_by_channel(phys, channel=config.channel)
    managed_interface = self._create_virtual_interface(wifi_id, phy)
    bridge_name = None
    if config.host_subnet_on_bridge:
      bridge_name = self._create_and_enable_bridge_interface(wifi_id)
      subnet_interface = bridge_name
    else:
      subnet_interface = managed_interface

    hostapd_manager_obj = hostapd_manager.HostapdManager(
        device=self._device,
        wifi_id=wifi_id,
        phy=phy,
        interface=managed_interface,
        wifi_config=config,
        bridge=bridge_name,
    )
    wifi_info = hostapd_manager_obj.start()
    self._running_wifis[wifi_id] = WiFiComponents(
        info=wifi_info,
        config=config,
        hostapd_manager=hostapd_manager_obj,
        dhcp_manager=None,
    )

    if config.access_wan_through_nat:
      dhcp_manager_obj = dhcp_manager.DhcpManager(
          device=self._device,
          wifi_id=wifi_id,
          iface=subnet_interface,
          custom_dhcp_configs=config.custom_dhcp_configs,
          resolve_to_host_ip=config.enable_resolve_to_host_ip,
      )
      dhcp_manager_obj.start()
      self._running_wifis[wifi_id].dhcp_manager = dhcp_manager_obj
    elif not self._system_dnsmasq_active:
      self.set_dnsmasq(enabled=True)

    self._modify_firewall_rules(
        managed_interface,
        action=firewall_manager.FirewallAction.INSERT,
    )

    self._set_txpower(managed_interface, config)

    self._log.debug(
        'Started WiFi network %d with config: %s', wifi_info.id, config
    )

    # Print device status info for debugging.
    self._device.ssh.execute_command(
        command=constants.Commands.IW_DEV_INFO.format(
            interface=managed_interface
        ),
        timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
    )
    self._device.ssh.execute_command(
        command=constants.Commands.IW_REG_GET,
        timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
    )

    return wifi_info

  def _set_txpower(self, interface: str, config: wifi_configs.WiFiConfig):
    """Sets the transmit power of the wireless interface on the AP device."""
    if config.maximum_txpower_dbm is None:
      return
    txpower_mbm = config.maximum_txpower_dbm * 100
    self._device.ssh.execute_command(
        command=constants.Commands.IW_DEV_SET_MAXIMUM_TXPOWER.format(
            interface=interface,
            txpower_mbm=txpower_mbm,
        ),
        timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
    )

  def _print_debug_info_before_starting_wifi(self):
    """Prints debug information before starting each WiFi network."""
    self._device.ssh.execute_command(
        command=constants.Commands.GET_PROCESS_BY_NAME.format(
            name=constants.HOSTAPD
        ),
        timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
        ignore_error=True,
    )

  def _set_country_code(self, country_code: str):
    """Sets country code to AP devices."""
    self._device.ssh.execute_command(
        command=constants.Commands.IW_REG_SET.format(
            country_code=country_code,
        ),
        timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
    )

  def _create_virtual_interface(self, wifi_id: int, phy: iw_utils.Phy) -> str:
    """Creates a new virtual interface using the given hardware device."""
    interface = f'managed{wifi_id}'
    self._device.ssh.execute_command(
        command=constants.Commands.IW_DEV_DEL.format(interface=interface),
        timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
        ignore_error=True,
    )
    self._device.ssh.execute_command(
        command=constants.Commands.IW_DEV_ADD.format(
            phy=phy.name, interface=interface
        ),
        timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
    )
    return interface

  def _create_and_enable_bridge_interface(self, wifi_id: int) -> str:
    """Creates a bridge interface for the given WiFi ID and sets it up.

    Args:
      wifi_id: The ID of the WiFi network.

    Returns:
      The name of the created bridge interface.
    """
    bridge_name = f'br{wifi_id}'
    self._device.ssh.execute_command(
        command=constants.Commands.IP_LINK_ADD_BRIDGE.format(
            interface=bridge_name
        ),
        timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
    )
    self._device.ssh.execute_command(
        command=constants.Commands.IP_LINK_UP.format(
            interface=bridge_name,
        ),
        timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
    )
    return bridge_name

  def _modify_firewall_rules(
      self,
      interface: str,
      action: firewall_manager.FirewallAction,
  ):
    """Modifies firewall rules to forward traffic between the WLAN and WAN."""
    wan_interface = self.wan_interface
    wireless_interface = interface

    # The rule that only allows packets that are from WAN interface to wireless
    # interface and are part of a connection that has already been established,
    # such as a TCP connection.
    self._firewall.forward_known_traffic(
        in_interface=wan_interface,
        out_interface=wireless_interface,
        action=action,
    )
    # The rule that allows all packets from wireless interface to WAN interface.
    self._firewall.forward_traffic(
        in_interface=wireless_interface,
        out_interface=wan_interface,
        action=action,
    )

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
      errors.BaseError: If the source_wifi_info is not found among running
        Wi-Fi instances or if the associated HostapdManager is not found.
    """
    if source_wifi_info.id not in self._running_wifis:
      raise errors.BaseError(
          f'WiFi network with ID {source_wifi_info.id} (SSID:'
          f' {source_wifi_info.ssid}) is not currently running or managed by'
          ' this WiFiManager.'
      )
    wifi_components = self._running_wifis[source_wifi_info.id]
    return wifi_components.hostapd_manager.send_bss_tm_request(params)

  def set_hostapd_property(
      self, wifi_info: wifi_configs.WifiInfo, *, property_name: str, value: str
  ) -> None:
    """Sets the property of the hostapd daemon.

    This function modifies a specific property of the running hostapd instance.

    Args:
      wifi_info: The `WifiInfo` object for the AP whose property is to be set.
        This object's ID is used to identify the running hostapd instance.
      property_name: The name of the property to set.
      value: The value to assign to the specified property.

    Raises:
      errors.BaseError: If the `wifi_info` is not found among running Wi-Fi
        instances or if the associated HostapdManager is not found.
    """
    if wifi_info.id not in self._running_wifis:
      raise errors.BaseError(
          f'WiFi network with ID {wifi_info.id} (SSID:'
          f' {wifi_info.ssid}) is not currently running or managed by'
          ' this WiFiManager.'
      )
    wifi_components = self._running_wifis[wifi_info.id]
    wifi_components.hostapd_manager.set_hostapd_property(property_name, value)

  def channel_switch(
      self,
      wifi_info: wifi_configs.WifiInfo,
      *,
      target_channel: int,
      beacon_count: int,
      optional_args: Sequence[str] | None = None,
  ) -> wifi_configs.WifiInfo:
    """Performs a channel switch from the current channel to the target channel.

    Args:
      wifi_info: The `WifiInfo` object for the AP whose channel is to be
        switched.
      target_channel: The target channel to switch to.
      beacon_count: The number of beacons to send before switching channels.
      optional_args: Optional arguments to pass to the hostapd_cli command.

    Returns:
      The updated `WifiInfo` with the new channel and frequency.

    Raises:
      errors.BaseError: If the `wifi_info` is not found among running Wi-Fi
        instances.
    """
    if wifi_info.id not in self._running_wifis:
      raise errors.BaseError(
          f'WiFi network with ID {wifi_info.id} (SSID:'
          f' {wifi_info.ssid}) is not currently running or managed by'
          ' this WiFiManager.'
      )
    wifi_components = self._running_wifis[wifi_info.id]
    wifi_components.hostapd_manager.channel_switch(
        target_channel, beacon_count, optional_args
    )
    new_freq = wifi_configs.get_frequency(
        target_channel, wifi_components.info.band_type
    )
    new_link = dataclasses.replace(
        wifi_components.info.links[0],
        channel=target_channel,
        frequency=new_freq,
    )
    new_info = dataclasses.replace(
        wifi_components.info,
        links=(new_link,),
    )
    self._running_wifis[wifi_info.id] = dataclasses.replace(
        wifi_components, info=new_info
    )
    return new_info

  def turn_off_radio(self, wifi_info: wifi_configs.WifiInfo) -> None:
    """Turns off radio of a running Wi-Fi to simulate abrupt AP power-off.

    This method stops beacon and radio frame transmissions immediately via
    `hostapd_cli disable` without sending deauthentication frames to connected
    clients or tearing down interfaces/configurations. The specified Wi-Fi
    network must be currently running. Unlike `stop_wifi`, which gracefully
    shuts down hostapd and deauthenticates stations, `turn_off_radio` is used to
    test client behavior when an AP suddenly disappears.

    Args:
      wifi_info: The `WifiInfo` object for the running AP whose radio is to be
        turned off.

    Raises:
      errors.BaseError: If the `wifi_info` is not found among running Wi-Fi
        instances.
    """
    if wifi_info.id not in self._running_wifis:
      raise errors.BaseError(
          f'WiFi network with ID {wifi_info.id} (SSID:'
          f' {wifi_info.ssid}) is not currently running or managed by'
          ' this WiFiManager.'
      )
    wifi_components = self._running_wifis[wifi_info.id]
    wifi_components.hostapd_manager.turn_off_radio()

  def teardown(self):
    """Tears this WiFi manager down and stops all running WiFi."""
    if self._is_torn_down:
      return
    self._is_torn_down = True
    self.stop_all_wifi()
    self.set_dnsmasq(enabled=self._was_system_dnsmasq_enabled)

  def stop_all_wifi(self):
    """Stops all running WiFi."""
    self._log.debug('Stopping all running WiFi networks.')
    wifis = self._running_wifis
    self._running_wifis = {}
    for wifi_id, component in list(wifis.items()):
      try:
        self._stop_wifi(component=component)
      except (ssh_lib.RemoteTimeoutError, ssh_lib.SSHRemoteError):
        self._log.exception(
            'Ignoring the exception when trying to stop WiFi %s', wifi_id
        )

  def stop_wifi(self, wifi_info: wifi_configs.WifiInfo):
    """Stops the given WiFi network."""
    component = self._running_wifis.pop(wifi_info.id, None)
    if component is None:
      self._log.debug(
          'WiFi network with following WifiInfo does not exist or is already'
          ' stopped: %s',
          wifi_info,
      )
      return

    self._stop_wifi(component=component)

  def _stop_wifi(self, *, component: WiFiComponents):
    """Stops all the given WiFi components related to one WiFi network."""
    self._log.debug('Stopping WiFi network with id %d', component.info.id)

    hostapd_stop_error = None
    try:
      # Stop hostapd manager first so hostapd can gracefully send deauth frames
      # to connected stations before the interface is deleted.
      component.hostapd_manager.stop()
    except (ssh_lib.SSHRemoteError, errors.BaseError) as e:
      hostapd_stop_error = e
      self._log.exception(
          'Failed to stop hostapd manager for WiFi network %d',
          component.info.id,
      )
    finally:
      # Stop DHCP manager if running.
      dhcp_stop_error = None
      if component.dhcp_manager is not None:
        try:
          component.dhcp_manager.stop()
        except (ssh_lib.SSHRemoteError, errors.BaseError) as e:
          dhcp_stop_error = e
          self._log.exception(
              'Failed to stop DHCP manager for WiFi network %d',
              component.info.id,
          )
      elif (
          not self._is_torn_down
          and self._system_dnsmasq_active
          and not any(
              c.dhcp_manager is None for c in self._running_wifis.values()
          )
      ):
        self.set_dnsmasq(enabled=False)

      # Remove added firewall rules.
      self._modify_firewall_rules(
          component.info.interface,
          action=firewall_manager.FirewallAction.DELETE,
      )

      # Delete the bridge interface.
      if component.info.bridge is not None:
        self._device.ssh.execute_command(
            command=constants.Commands.IP_LINK_DELETE_BRIDGE.format(
                interface=component.info.bridge
            ),
            timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
            ignore_error=True,
        )

      # Delete the network interface.
      self._log.debug(
          'Deleting network interface: %s', component.info.interface
      )
      self._device.ssh.execute_command(
          command=constants.Commands.IW_DEV_DEL.format(
              interface=component.info.interface
          ),
          timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
          ignore_error=True,
      )

    if hostapd_stop_error is not None:
      raise hostapd_stop_error
    if dhcp_stop_error is not None:
      raise dhcp_stop_error
