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

"""The module for controlling wpa_supplicant on client devices."""

import datetime
import enum
import logging
import os
from typing import Any

from mobly import logger as mobly_logger

from mobly.controllers.wifi.lib import ssh as ssh_lib
from mobly.controllers.wifi.lib import errors
from mobly.controllers.wifi.lib import utils

OpenWrtDevice = Any

_WPA_SUPPLICANT_START_COMMAND = (
    'wpa_supplicant -s -c {conf_path} -i {interface}'
)
_WPA_CLI_COMMAND = 'wpa_cli -p {ctrl_path} -i {interface} {command_args}'

_WIFI_CONNECT_WAIT_TIME = datetime.timedelta(seconds=30)
_WIFI_CONNECT_CHECK_INTERVAL = datetime.timedelta(seconds=1)
_WIFI_DISCONNECT_WAIT_TIME = datetime.timedelta(seconds=10)
_CTRL_SOCKET_PATH = '/var/run/wpa_supplicant'

WPA_STATE_KEY = 'wpa_state'
WPA_STATE_COMPLETED = 'COMPLETED'


@enum.unique
class Security(enum.Enum):
  """The security type of the WiFi network."""

  OPEN = 'open'
  WPA2 = 'wpa2'
  WPA3 = 'wpa3'


@enum.unique
class WpaCliCommand(enum.Enum):
  """The command for wpa_cli."""

  STATUS = ('status',)
  TERMINATE = ('terminate',)
  DISCONNECT = ('disconnect',)


class WpaSupplicantConfig:
  """Generates configuration for a wpa_supplicant instance."""

  def __init__(self, interface: str):
    self._interface = interface
    self._raw_config: dict[str, str] = {}
    self.update('ctrl_interface', _CTRL_SOCKET_PATH)
    self.update('ctrl_interface_group', '0')
    self.update('update_config', '1')

  def update(self, key: str, value: str):
    self._raw_config[key] = value

  def get(self, key: str) -> str | None:
    return self._raw_config.get(key)

  def generate_network_config(
      self,
      ssid: str,
      security: Security,
      password: str | None,
  ) -> str:
    """Generates network block for wpa_supplicant config file."""
    network_params = [f'ssid="{ssid}"']

    if security == Security.OPEN:
      network_params.append('key_mgmt=NONE')
    elif security in (Security.WPA2, Security.WPA3):
      if not password:
        raise errors.ConfigError(
            f'Password is required for security {security.value}.'
        )
      network_params.append(f'psk="{password}"')
      if security == Security.WPA2:
        network_params.append('key_mgmt=WPA-PSK')
      else:
        network_params.append('key_mgmt=SAE')
        network_params.append('ieee80211w=1')

    lines = '\n'.join(f'    {line}' for line in network_params)
    return f'network={{\n{lines}\n}}'

  @property
  def config_content(self) -> str:
    return '\n'.join(
        f'{key}={value}' for key, value in self._raw_config.items()
    )

  def write_to_file(self, filepath: str, content: str) -> None:
    """Writes the configurations to the given host filepath."""
    with open(filepath, 'w') as f:
      f.write(content)


class WpaSupplicantManager:
  """Manages a wpa_supplicant instance on a client device for specific interface."""

  def __init__(
      self,
      device: 'OpenWrtDevice',
      interface: str,
      base_logger: (
          logging.Logger | mobly_logger.PrefixLoggerAdapter | None
      ) = None,
  ):
    self._device = device
    self._interface = interface
    self._wpa_supplicant_config: WpaSupplicantConfig | None = None
    self._remote_process = None
    self._identifier = f'wpa_supplicant,{self._interface}'
    base_logger = base_logger or device.log
    self._log = mobly_logger.PrefixLoggerAdapter(
        base_logger,
        {
            mobly_logger.PrefixLoggerAdapter.EXTRA_KEY_LOG_PREFIX: (
                f'[WpaSupplicantManager|{self._interface}]'
            )
        },
    )
    self._local_work_dir = self._device.log_path
    self._remote_work_dir = self._device.remote_work_dir
    self._config_remote_path: str | None = None
    self._device.ssh.execute_command(f'mkdir -p {_CTRL_SOCKET_PATH}')

  def __del__(self):
    self.disconnect()

  def _get_remote_path(self, filename: str) -> str:
    return os.path.join(self._remote_work_dir, filename)

  def _get_local_path(self, filename: str) -> str:
    return os.path.join(self._local_work_dir, filename)

  def _get_conf_filename(self) -> str:
    return f'{self._identifier},wpa_supplicant.conf'

  def _generate_remote_config_file(self, network_config: str) -> str:
    """Generates wpa_supplicant config file on device."""
    self._wpa_supplicant_config = WpaSupplicantConfig(
        interface=self._interface,
    )
    filename = self._get_conf_filename()
    local_path = self._get_local_path(filename)
    remote_path = self._get_remote_path(filename)

    config_content = self._wpa_supplicant_config.config_content
    config_content += f'\n{network_config}'
    self._wpa_supplicant_config.write_to_file(local_path, config_content)

    self._device.push_file(local_path, remote_path)
    os.rename(local_path, f'{local_path}.txt')
    return remote_path

  def _run_wpa_cli_command(self, command: WpaCliCommand) -> str:
    """Runs a wpa_cli command.

    Args:
      command: The command to run.

    Returns:
      The output of the command as a string.

    Raises:
      errors.BaseError: If wpa_supplicant is not running or the command fails.
    """
    if self._remote_process is None or self._remote_process.poll() is not None:
      raise errors.BaseError('wpa_supplicant is not running.')

    full_command = _WPA_CLI_COMMAND.format(
        ctrl_path=_CTRL_SOCKET_PATH,
        interface=self._interface,
        command_args=' '.join(command.value),
    )
    self._log.debug('Executing wpa_cli command: %s', full_command)
    try:
      output = self._device.ssh.execute_command(full_command)
      return output.strip()
    except ssh_lib.ExecuteCommandError as e:
      raise errors.BaseError(f'wpa_cli command failed: {e}') from e

  def get_status(self) -> dict[str, str]:
    """Returns wpa_supplicant status as a dictionary."""
    try:
      status_output = self._run_wpa_cli_command(WpaCliCommand.STATUS)
      status_dict = {}
      for line in status_output.splitlines():
        if '=' in line:
          key, value = line.split('=', 1)
          status_dict[key] = value
      return status_dict
    except errors.BaseError as e:
      self._log.warning('Failed to get wpa_supplicant status: %s', e)
      return {}

  def _is_connected(self) -> bool:
    """Checks if supplicant state is COMPLETED."""
    return self.get_status().get(WPA_STATE_KEY) == WPA_STATE_COMPLETED

  def connect(
      self,
      ssid: str,
      security: Security,
      password: str | None,
  ):
    """Connects to a network."""
    if self._remote_process is not None:
      self.disconnect()

    self._wpa_supplicant_config = WpaSupplicantConfig(self._interface)
    network_config = self._wpa_supplicant_config.generate_network_config(
        ssid, security, password
    )
    conf_remote_path = self._generate_remote_config_file(network_config)
    self._config_remote_path = conf_remote_path

    command = _WPA_SUPPLICANT_START_COMMAND.format(
        conf_path=conf_remote_path,
        interface=self._interface,
    )
    self._remote_process = self._device.ssh.start_remote_process(
        command, get_pty=True
    )

    if not utils.wait_for_predicate(
        self._is_connected,
        timeout=_WIFI_CONNECT_WAIT_TIME,
        interval=_WIFI_CONNECT_CHECK_INTERVAL,
    ):
      raise errors.BaseError(
          f'Failed to connect to {ssid} on interface {self._interface}.'
      )
    self._log.info('Connected to %s on interface %s.', ssid, self._interface)

  def disconnect(self):
    """Disconnects from network and terminates the wpa_supplicant process."""
    remote_process = self._remote_process
    if remote_process is None:
      return

    self._log.debug('Disconnecting from network with wpa_cli disconnect.')
    try:
      self._run_wpa_cli_command(WpaCliCommand.DISCONNECT)
    except errors.BaseError as e:
      self._log.warning('Failed to disconnect from network: %s', e)

    self._log.debug('Stopping wpa_supplicant with wpa_cli terminate.')
    try:
      self._run_wpa_cli_command(WpaCliCommand.TERMINATE)
      if utils.wait_for_predicate(
          lambda: remote_process.poll() is not None,
          timeout=_WIFI_DISCONNECT_WAIT_TIME,
          interval=_WIFI_CONNECT_CHECK_INTERVAL,
      ):
        self._log.debug('wpa_supplicant process stopped.')
      else:
        self._log.warning('wpa_supplicant process did not stop in time.')
    except errors.BaseError as e:
      self._log.warning('Failed to stop wpa_supplicant: %s', e)
    finally:
      self._remote_process = None
      remote_process.terminate(
          timeout=_WIFI_DISCONNECT_WAIT_TIME.total_seconds(),
          assert_process_exit=True,
      )
