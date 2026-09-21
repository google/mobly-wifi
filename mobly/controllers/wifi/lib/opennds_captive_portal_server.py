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

"""The module for managing the OpenNDS captive portal server."""

from __future__ import annotations

import dataclasses
import pathlib
from typing import Any, Sequence

from mobly import logger as mobly_logger

from mobly.controllers.wifi.lib import ssh as ssh_lib
from mobly.controllers.wifi.lib import constants
from mobly.controllers.wifi.lib import errors
from mobly.controllers.wifi.lib import opennds_manager
from mobly.controllers.wifi.lib import package_manager
from mobly.controllers.wifi.lib import utils
from mobly.controllers.wifi.lib import wifi_configs

OpenWrtDevice = Any

_SSH_ERRORS = (
    ssh_lib.RemoteTimeoutError,
    ssh_lib.SSHRemoteError,
    ssh_lib.ExecuteCommandError,
)

_PACKAGE_NAME = "opennds"


@dataclasses.dataclass
class _ServerConfig:
  """The class for the OpenNDS captive portal server configuration."""

  interface: str = "managed0"
  bridge: str | None = None
  added_bridge_ip: bool = False
  configured_bridge_ip: str | None = None
  configured_bridge_name: str | None = None

  def is_bridge_configured(self) -> bool:
    return bool(
        self.added_bridge_ip
        and self.configured_bridge_ip
        and self.configured_bridge_name
    )

  def reset(self) -> None:
    self.added_bridge_ip = False
    self.configured_bridge_ip = None
    self.configured_bridge_name = None

  def set_interface_and_bridge(
      self, interface: str, bridge: str | None
  ) -> None:
    self.interface = interface
    self.bridge = bridge

  def set_configured_bridge_ip(
      self, ip: str, netmask_suffix: str, bridge: str
  ) -> None:
    self.added_bridge_ip = True
    self.configured_bridge_ip = f"{ip}{netmask_suffix}"
    self.configured_bridge_name = bridge


class OpenndsCaptivePortalServer:
  """Manages the OpenNDS captive portal server on a device."""

  _config: _ServerConfig

  def __init__(
      self,
      device: OpenWrtDevice,
      package_manager_obj: package_manager.PackageManagerProtocol | None = None,
      dhcp_lease_file: str | None = None,
  ) -> None:
    self._device = device
    self._config = _ServerConfig()
    self._opennds_manager = opennds_manager.OpenndsManager(device)
    if package_manager_obj is None:
      raise ValueError("package_manager_obj must be provided.")
    self._package_manager = package_manager_obj
    self._dhcp_lease_file = dhcp_lease_file

    self._log = mobly_logger.PrefixLoggerAdapter(
        device.log,
        {
            mobly_logger.PrefixLoggerAdapter.EXTRA_KEY_LOG_PREFIX: (
                "[OpenndsCaptivePortalServer]"
            )
        },
    )

  @property
  def use_opennds(self) -> bool:
    """True if using opennds; False otherwise."""
    return True

  @property
  def is_alive(self) -> bool:
    """True if the service is alive; False otherwise."""
    return self._opennds_manager.is_running()

  def _execute_sequential(
      self,
      commands: list[str],
      *,
      ignore_error: bool = False,
      timeout: float | None = None,
  ) -> str:
    """Runs a list of commands sequentially (using ';') on the device."""
    joined_cmd = " ; ".join(f"({c})" for c in commands)
    return self._device.ssh.execute_command(
        f"({joined_cmd}) 2>&1 | logger -t captive_portal",
        ignore_error=ignore_error,
        timeout=timeout,
    )

  def start_captive_portal_server(
      self,
      wifi_info: Sequence[wifi_configs.WifiInfo] | None = None,
      dhcp_lease_file: str | None = None,
  ) -> None:
    """Starts the captive portal server if it is not already running.

    Args:
      wifi_info: Sequence of Wi-Fi network infos.
      dhcp_lease_file: Optional path to the DHCP lease file.

    Raises:
      errors.CaptivePortalError: If the captive portal server failed to start.
    """
    if self.is_alive:
      self._log.debug("Captive portal server is already running.")
      return
    try:
      self._device.restart_dhcp_server()
      self._install_opennds_if_needed()
      if not self._configure_opennds(
          wifi_info, dhcp_lease_file=dhcp_lease_file
      ):
        raise errors.CaptivePortalError(
            "Failed to configure OpenNDS captive portal."
        )
    except _SSH_ERRORS as e:
      raise errors.CaptivePortalError(
          "Failed to configure OpenNDS captive portal."
      ) from e

  def _is_u6_lite(self) -> bool:
    """Returns True if the device is a Ubiquiti UniFi 6 Lite."""
    return self._device.device_info.device_name == constants.ApModel.U6LITE

  def _install_opennds_if_needed(self) -> None:
    """Ensures OpenNDS binary is installed on the device; installs it if needed."""
    try:
      check_bin = self._device.ssh.execute_command(
          f"which {_PACKAGE_NAME}",
          timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
          ignore_error=True,
      )
      if check_bin.strip():
        return

      self._log.debug("opennds binary not found. Installing package opennds.")
      self._device.ssh.execute_command(
          f"(/etc/init.d/{_PACKAGE_NAME} stop) && (/etc/init.d/firewall"
          " restart) 2>&1 | logger -t captive_portal",
          ignore_error=True,
      )
      # Clear any stale status record from non-volatile package db
      # (e.g. if rebooted)
      self._package_manager.remove_package(
          _PACKAGE_NAME, from_ram=self._is_u6_lite()
      )

      is_u6_lite = self._is_u6_lite()
      self._package_manager.install_package(
          _PACKAGE_NAME, install_to_ram=is_u6_lite
      )
    except Exception as e:
      raise errors.CaptivePortalError(
          f"Failed to install opennds package: {e}"
      ) from e

  def _extract_wifi_info(
      self,
      wifi_info: Sequence[wifi_configs.WifiInfo],
  ) -> wifi_configs.WifiInfo | None:
    """Extracts the primary WifiInfo (preferring bridged ones) from a sequence."""
    if not wifi_info:
      return None
    for info in wifi_info:
      if info.bridge:
        return info
    return wifi_info[0]

  def _configure_opennds(
      self,
      wifi_info: Sequence[wifi_configs.WifiInfo] | None = None,
      dhcp_lease_file: str | None = None,
  ) -> bool:
    """Configures and starts the OpenNDS captive portal server on the device.

    Args:
      wifi_info: Wi-Fi network info or sequence of network infos.
      dhcp_lease_file: Optional path to the DHCP lease file.

    Returns:
      True if configuration succeeded; False otherwise.
    """
    if not wifi_info:
      self._log.warning("No Wi-Fi info found; cannot configure OpenNDS.")
      return False

    extracted_info = self._extract_wifi_info(wifi_info)
    if not extracted_info:
      self._log.warning("No Wi-Fi info found; cannot configure OpenNDS.")
      return False

    interface: str = extracted_info.source_iface
    if not interface:
      self._log.warning(
          "Wi-Fi info missing interface; cannot configure OpenNDS."
      )
      return False

    lease_file = dhcp_lease_file or self._dhcp_lease_file

    sys_bridge = self._detect_system_bridge(interface)

    target_interface = interface
    opennds_interface = interface
    bridge = None
    if sys_bridge and sys_bridge not in ("yes", "no"):
      self._log.debug(
          "Detected interface %s is bridged to %s.",
          target_interface,
          sys_bridge,
      )
      opennds_interface = sys_bridge
      bridge = sys_bridge

    self._config.set_interface_and_bridge(target_interface, bridge)

    self._log.debug(
        "Configuring OpenNDS captive portal on %s using built-in login form.",
        opennds_interface,
    )
    try:
      if self._config.bridge:
        self._configure_bridge_gateway_ip(self._config.bridge, extracted_info)

      if lease_file:
        self._expose_dhcp_leases_file(lease_file)

      # Configure OpenNDS through OpenndsManager
      self._opennds_manager.configure(opennds_interface)

      self._log.debug("Starting OpenNDS service.")
      self._opennds_manager.start()

      return True
    except _SSH_ERRORS as e:
      self._log.warning("Failed to configure OpenNDS captive portal: %s", e)
      return False

  def stop_captive_portal_server(self) -> None:
    """Stops the captive portal server."""
    self._stop_opennds_captive_portal_server()

  def _stop_opennds_captive_portal_server(self) -> None:
    """Stops the OpenNDS captive portal server and restores configurations."""
    self._log.debug("Stopping opennds captive portal.")
    is_ram_install = False
    try:
      check_symlink = self._device.ssh.execute_command(
          f"[ -L /usr/bin/{_PACKAGE_NAME} ] && echo 'yes' || echo 'no'",
          timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
      ).strip()
      is_ram_install = check_symlink == "yes"
    except _SSH_ERRORS:
      pass

    try:
      # Stop and disable OpenNDS service
      self._opennds_manager.stop()
      self._opennds_manager.disable()

      if is_ram_install:
        # Symlink/binary files RAM package cleanup remains here
        self._package_manager.remove_package(_PACKAGE_NAME, from_ram=True)

      # Standard environment restoration
      self._device.ssh.execute_command(
          f"[ -L {constants.DEFAULT_DHCP_LEASE_FILE} ] && rm -f"
          f" {constants.DEFAULT_DHCP_LEASE_FILE} || true",
          ignore_error=True,
      )

      if self._config.is_bridge_configured():
        self._device.ssh.execute_command(
            "ip addr del"
            f" {self._config.configured_bridge_ip}"
            f" dev {self._config.configured_bridge_name} || true",
            ignore_error=True,
        )
        self._config.reset()

      self._device.restart_dhcp_server(self._config.interface)
    except _SSH_ERRORS as e:
      raise errors.CaptivePortalError(
          "Failed to stop OpenNDS captive portal server."
      ) from e

  def _detect_system_bridge(self, interface: str) -> str:
    """Returns the bridge name if the interface is bridged; empty otherwise."""
    try:
      check_bridge = self._device.ssh.execute_command(
          f'bridge_path="/sys/class/net/{interface}/brport/bridge"; '
          '[ -d "$bridge_path" ] && basename $(readlink "$bridge_path") '
          '|| echo ""',
          timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
      )
      return check_bridge.strip()
    except _SSH_ERRORS:
      return ""

  def _configure_bridge_gateway_ip(
      self, bridge: str, wifi_info: wifi_configs.WifiInfo
  ) -> None:
    """Configures the gateway IP on the bridge if not already present."""
    ip_str = None
    netmask_str = None

    try:
      ip, subnet = utils.get_ap_ip_and_subnet(self._device, wifi_info.ssid)
      ip_str = str(ip)
      netmask_str = str(subnet.netmask)
    except Exception as e:  # pylint: disable=broad-except
      self._log.warning(
          "Failed to get AP IP and subnet for SSID %s: %s", wifi_info.ssid, e
      )

    if not ip_str:
      return

    # Check if the IP is already configured on the bridge.
    ip_check = self._device.ssh.execute_command(
        f"ip addr show dev {bridge} | grep -q 'inet {ip_str}/' && echo 'yes' ||"
        " echo 'no'",
        ignore_error=True,
    ).strip()
    if ip_check != "yes":
      netmask_suffix = f"/{netmask_str}" if netmask_str else ""
      self._device.ssh.execute_command(
          f"ip addr add {ip_str}{netmask_suffix} dev {bridge} || true",
          ignore_error=True,
      )
      self._config.set_configured_bridge_ip(ip_str, netmask_suffix, bridge)

  def _expose_dhcp_leases_file(self, dhcp_leases_file: str) -> None:
    """Exposes the remote DHCP leases file to DEFAULT_DHCP_LEASE_FILE for OpenNDS."""
    if dhcp_leases_file == constants.DEFAULT_DHCP_LEASE_FILE:
      return
    leases_dir = str(pathlib.PurePosixPath(dhcp_leases_file).parent)
    leases_parent = str(pathlib.PurePosixPath(leases_dir).parent)
    self._device.ssh.execute_command(
        f"(chmod 755 {leases_parent} {leases_dir}) && (chmod 644"
        f" {dhcp_leases_file}) && (ln -sf {dhcp_leases_file}"
        f" {constants.DEFAULT_DHCP_LEASE_FILE}) 2>&1 | logger -t"
        " captive_portal",
        ignore_error=True,
    )
