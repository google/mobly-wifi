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

"""Controller configurations for the OpenWrt controller module."""

from __future__ import annotations

from collections.abc import Sequence
import dataclasses
import logging
from typing import Any

import dacite

from mobly.controllers.wifi.lib import constants
from mobly.controllers.wifi.lib import utils

# Error messages used in this module.
_DEVICE_EMPTY_CONFIG_MSG = 'Configuration is empty, abort!'
_CONFIG_MISSING_REQUIRED_KEY_MSG = (
    'Missing required key {missing_keys} in config'
)
_CONFIG_WRONG_TYPE_MSG = 'Wrong type in config'
_CONFIG_INVALID_VALUE_MSG = 'Invalid value in config'


class ConfigError(Exception):
  """The OpenWrt controller configs encounter error."""

  def __init__(
      self, message: str, config: dict[str, Any] | None = None
  ) -> None:
    if config is not None:
      message = f'{message}: {config}'
    super().__init__(message)


def from_dicts(configs: Sequence[dict[str, Any]]) -> list[DeviceConfig]:
  """Create DeviceConfig objects from a list of dict configs.

  Args:
    configs: A list of dicts each representing the configuration of one OpenWrt
      reference device.

  Returns:
    A list of DeviceConfig.

  Raises:
    ConfigError: Invalid controller config is given.
  """
  device_configs = []
  if not configs:
    raise ConfigError(_DEVICE_EMPTY_CONFIG_MSG)

  for config in configs:
    logging.debug('Parsing OpenWrt device config: %s', config)
    device_configs.append(DeviceConfig.from_dict(config))

  return device_configs


@dataclasses.dataclass
class DeviceConfig:
  """Provides configs and default values for OpenWrtDevice.

  Attributes:
    hostname: The hostname or IP address of the OpenWrt device.
    username: The username for SSH connection.
    password: The password for SSH connection.
    ssh_port: The SSH port number.
    skip_init_reboot: Whether to skip reboot during initialization.
    skip_init_package_installation: Whether to skip package installation during
      initialization.
    ssh_proxy_format: The format string for the SSH proxy command. If None, no
      SSH proxy will be used. The format string should contain the following
      placeholders: - {username}: The SSH username. - {hostname}: The hostname
        or IP address of the OpenWrt device. - {ssh_port}: The SSH port number
        of the OpenWrt device.
  """

  hostname: str
  username: str = constants.SSH_USERNAME
  password: str | None = None
  ssh_port: int = 22
  skip_init_reboot: bool = False
  skip_init_package_installation: bool = False
  ssh_proxy_format: str | None = None

  @property
  def ssh_proxy_command(self) -> str | None:
    """The SSH proxy command string if ssh_proxy_format is set, otherwise None.

    Returns:
      The SSH proxy command string or None if ssh_proxy_format is None.
    """
    if self.ssh_proxy_format is None:
      return None
    return self.ssh_proxy_format.format(
        username=self.username,
        hostname=self.hostname,
        ssh_port=self.ssh_port,
    )

  @classmethod
  def from_dict(cls, config: dict[str, Any]) -> DeviceConfig:
    """Parses controller configs from Mobly runner to DeviceConfig.

    Args:
      config: A dictionary of string parameters.

    Returns:
      DeviceConfig data class.

    Raises:
      ConfigError: Invalid controller config is given.
    """
    type_converters = {
        bool: utils.convert_testbed_bool_value,
    }
    try:
      config_obj = dacite.from_dict(
          data_class=DeviceConfig,
          data=config,
          config=dacite.Config(type_hooks=type_converters),  # pyrefly: ignore[bad-argument-type]
      )
    except dacite.exceptions.MissingValueError as err:
      raise ConfigError(
          _CONFIG_MISSING_REQUIRED_KEY_MSG.format(missing_keys=err.field_path),
          config,
      ) from err
    except dacite.exceptions.WrongTypeError as err:
      raise ConfigError(_CONFIG_WRONG_TYPE_MSG, config) from err
    except ValueError as err:
      raise ConfigError(_CONFIG_INVALID_VALUE_MSG, config) from err

    return config_obj
