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

import contextlib
import dataclasses
import datetime
from typing import Any

from mobly import logger as mobly_logger

from mobly.controllers.wifi.lib import ssh as ssh_lib
from mobly.controllers.wifi.lib import constants
from mobly.controllers.wifi.lib import dhcp_manager
from mobly.controllers.wifi.lib import errors
from mobly.controllers.wifi.lib import hostapd_manager
from mobly.controllers.wifi.lib import iw_utils
from mobly.controllers.wifi.lib import utils
from mobly.controllers.wifi.lib import wifi_configs

# Avoid directly importing cros_device, which causes circular dependencies
OpenWrtDevice = Any


WIFI_START_WAIT_TIME = datetime.timedelta(seconds=30)
# DFS channels require 60s extra start time to check channel availability.
WIFI_START_WAIT_TIME_DFS = datetime.timedelta(seconds=180)


@dataclasses.dataclass
class _WiFiComponents:
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

  _running_wifis: dict[int, _WiFiComponents]

  def __init__(self, device: 'OpenWrtDevice'):
    self._device = device
    self._id_counter = device.wifi_id_counter
    self._running_wifis = {}
    self._wan_interface = constants.WAN_INTERFACE

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
    # Kill any existing hostapd instances.
    self._device.ssh.execute_command(
        command=constants.Commands.KILLALL.format(name=constants.HOSTAPD),
        timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
        ignore_error=True,
    )

    # We don't need to remove these firewall rule modifications in teardown
    # phase because device reboot automatically reset them.
    # Enable the kernel to route packets between different networks.
    self._device.ssh.execute_command(
        command=constants.Commands.FIREWALL_ENABLE_IP_FORWARD,
        timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
    )

    # TODO: Temp workaround for new firewall rule.
    if utils.is_new_firewall_rule_version(self._device.device_info['release']):
      return

    if utils.is_using_openwrt_snapshot_image(
        self._device.device_info['release']
    ):
      return

    # Enable NAT, i.e., outbound traffic through the WAN interface will have its
    # source addr replaced with the WAN interface.
    self._device.ssh.execute_command(
        command=constants.Commands.FIREWALL_ENABLE_NAT.format(
            interface=self._wan_interface
        ),
        timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
    )

  @property
  def is_alive(self) -> bool:
    """True if there are any running WiFi networks, False otherwise."""
    return bool(self._running_wifis)

  def start_wifi(
      self, config: wifi_configs.WiFiConfig
  ) -> wifi_configs.WifiInfo:
    """Starts a WiFi network with the given configurations."""
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
    interface = self._create_virtual_interface(wifi_id, phy)

    hostapd_manager_obj = hostapd_manager.HostapdManager(
        device=self._device,
        wifi_id=wifi_id,
        phy=phy,
        interface=interface,
        wifi_config=config,
    )
    wifi_info = hostapd_manager_obj.start()
    self._running_wifis[wifi_id] = _WiFiComponents(
        info=wifi_info,
        config=config,
        hostapd_manager=hostapd_manager_obj,
        dhcp_manager=None,
    )

    if config.access_wan_through_nat:
      dhcp_manager_obj = dhcp_manager.DhcpManager(
          device=self._device, wifi_id=wifi_id, iface=interface
      )
      dhcp_manager_obj.start()
      self._running_wifis[wifi_id].dhcp_manager = dhcp_manager_obj

    self._modify_firewall_rules(
        interface,
        action=constants.IptablesAction.INSERT,
        access_wan_through_nat=config.access_wan_through_nat,
    )

    self._set_txpower(interface, config)

    self._log.debug(
        'Started WiFi network %d with config: %s', wifi_info.id, config
    )

    # Print device status info for debugging.
    self._device.ssh.execute_command(
        command=constants.Commands.IW_DEV_INFO.format(interface=interface),
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

  def _modify_firewall_rules(
      self,
      interface: str,
      action: constants.IptablesAction,
      access_wan_through_nat: bool,
  ):
    """Modifies firewall rules to forward traffic between the WLAN and WAN."""
    if utils.is_using_openwrt_snapshot_image(
        self._device.device_info['release']
    ):
      return

    # TODO: Temp workaround for new firewall rule.
    if utils.is_new_firewall_rule_version(self._device.device_info['release']):
      if access_wan_through_nat and not utils.is_using_custom_image(
          self._device
      ):
        raise errors.ConfigError(
            'Config access_wan_through_nat=True is not supported under current'
            'official OpenWrt image and version'
            f' {self._device.device_info["release"]}'
        )
      return

    wan_interface = self._wan_interface
    wireless_interface = interface

    # The rule that allows all packets from wireless interface to WAN interface.
    self._device.ssh.execute_command(
        command=constants.Commands.FIREWALL_FORWARD_KNOWN_TRAFFIC.format(
            action=action,
            in_interface=wan_interface,
            out_interface=wireless_interface,
        ),
        timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
    )
    # The rule that only allows packets that are from WAN interface to wireless
    # interface and are part of a connection that has already been established,
    # such as a TCP connection.
    self._device.ssh.execute_command(
        command=constants.Commands.FIREWALL_FORWARD_TRAFFIC.format(
            action=action,
            in_interface=wireless_interface,
            out_interface=wan_interface,
        ),
        timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
    )

  def __del__(self):
    self.teardown()

  def teardown(self):
    """Tears this WiFi manager down and stops all running WiFi."""
    self.stop_all_wifi()

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

  def _stop_wifi(self, *, component: _WiFiComponents):
    """Stops all the given WiFi components related to one WiFi network."""
    self._log.debug('Stopping WiFi network with id %d', component.info.id)

    # Remove added firewall rules.
    self._modify_firewall_rules(
        component.info.interface,
        action=constants.IptablesAction.DELETE,
        access_wan_through_nat=component.config.access_wan_through_nat,
    )

    # Stop hostapd manager.
    try:
      component.hostapd_manager.stop()
    except ssh_lib.SSHRemoteError as e:
      # We need to stop other components when hostapd_manager stop failed.
      if component.dhcp_manager is not None:
        component.dhcp_manager.stop()
      raise e

    if component.dhcp_manager is not None:
      component.dhcp_manager.stop()
