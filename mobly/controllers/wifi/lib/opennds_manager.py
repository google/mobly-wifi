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

"""The module for managing the OpenNDS service on OpenWrt."""

from typing import Any

from mobly.controllers.wifi.lib import ssh as ssh_lib
from mobly.controllers.wifi.lib import constants


class OpenndsManager:
  """Manages the OpenNDS service on an OpenWrt device using UCI."""

  def __init__(self, device: Any):
    self._device = device

  def is_running(self) -> bool:
    """Returns True if the opennds daemon is currently running on the device."""
    try:
      result = self._device.ssh.execute_command(
          'pgrep opennds',
          ignore_error=True,
          timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
      ).strip()
      return bool(result)
    except ssh_lib.Error:
      return False

  def configure(self, interface: str, port: int = 2050) -> None:
    """Configures the opennds service via UCI."""
    cmds = [
        # Make sure the config file exists
        'test -f /etc/config/opennds || touch /etc/config/opennds',
        # Delete existing opennds section if it exists, to re-create a clean one
        'while uci -q delete opennds.@opennds[0]; do :; done',
        'uci add opennds opennds',
        f'uci set opennds.@opennds[0].gatewayinterface="{interface}"',
        'uci set opennds.@opennds[0].enabled="1"',
        'uci set opennds.@opennds[0].login_option_enabled="2"',
        f'uci set opennds.@opennds[0].gatewayport="{port}"',
        'uci -q delete opennds.@opennds[0].gatewayfqdn || true',
        'uci commit opennds',
    ]

    chained_cmd = ' && '.join(f'({c})' for c in cmds)
    self._device.ssh.execute_command(
        f'({chained_cmd}) 2>&1 | logger -t opennds'
    )

  def start(self) -> None:
    """Starts the opennds service."""
    self._device.ssh.execute_command(
        '/etc/init.d/opennds restart 2>&1 | logger -t opennds'
    )

  def stop(self) -> None:
    """Stops the opennds service."""
    self._device.ssh.execute_command(
        '/etc/init.d/opennds stop 2>&1 | logger -t opennds'
    )

  def disable(self) -> None:
    """Disables the opennds service in UCI config."""
    cmds = [
        'uci set opennds.@opennds[0].enabled="0"',
        'uci commit opennds',
    ]
    chained_cmd = ' && '.join(f'({c})' for c in cmds)
    self._device.ssh.execute_command(
        f'({chained_cmd}) 2>&1 | logger -t opennds'
    )
