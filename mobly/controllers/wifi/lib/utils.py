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

"""Utilities for the AP controller module."""

import datetime
import string
import time
from typing import Any, Callable

from mobly import utils
from packaging import version

from mobly.controllers.wifi.lib import constants

OpenWrtDevice = Any

_OPENWRT_NEW_FIREWALL_RULE_VERSION = version.parse('22.03')


def is_hex_string(s: str) -> bool:
  """True if the given string is a hex string; False otherwise."""
  return all(c in string.hexdigits for c in s)


def wait_for_predicate(
    predicate: Callable[[], bool],
    timeout: datetime.timedelta,
    interval: datetime.timedelta | None = None,
) -> bool:
  """Returns True if the predicate returns True within the given timeout.

  Any exception raised in the predicate will terminate the wait immediately.

  Args:
    predicate: A predicate function.
    timeout: The timeout to wait.
    interval: The interval time between each check of the predicate.

  Returns:
    Whether the predicate returned True within the given timeout.
  """
  start_time = time.monotonic()
  deadline = start_time + timeout.total_seconds()
  while time.monotonic() < deadline:
    if predicate():
      return True
    if interval is not None:
      time.sleep(interval.total_seconds())
  return False


def is_new_firewall_rule_version(version_number: str) -> bool:
  """Returns True if OpenWrt version is new firewall rule, False otherwise."""
  parsed_version = version.parse(version_number)
  return parsed_version >= _OPENWRT_NEW_FIREWALL_RULE_VERSION


def is_using_openwrt_snapshot_image(release: str) -> bool:
  """Returns True if the image is built against SNAPSHOT, False otherwise."""
  return release == 'SNAPSHOT'


def is_using_custom_image(device: 'OpenWrtDevice') -> bool:
  """Returns True if the image is using a custom image, False otherwise."""
  output = device.ssh.execute_command(
      command=f'ls {constants.CURSTOM_RELEASE_INFO_FILE_PATH}',
      timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
      ignore_error=True,
  )
  return output.strip() == constants.CURSTOM_RELEASE_INFO_FILE_PATH


def run_command(
    cmd: str, ignore_error: bool = False
) -> tuple[int, bytes, bytes]:
  """Runs a command in a subprocess.

  Args:
    cmd: The command to run.
    ignore_error: If False, raise an error if the command execution failed.

  Returns:
    A 3-tuple of the consisting of the return code, the std output, and the
      std error.

  Raises:
    RuntimeError: The command execution failed and `ignore_error=False`.
  """
  ret, out, err = utils.run_command(cmd, shell=True)
  if (not ignore_error) and ret != 0:
    raise RuntimeError(f'Failed to run command "{cmd}" with error: {err}')
  return ret, out, err


def convert_testbed_bool_value(value: bool | str) -> bool:
  """Converts a raw value from testbed configuration to a bool value.

  We need this method because in some trigger approaches bool values in MH
  static testbed are transformed to strings in Mobly testbed.

  Args:
    value: The raw value from testbed configuration.

  Returns:
    The bool value.

  Raises:
    ValueError: If got invalid value.
  """
  if isinstance(value, bool):
    return value
  if isinstance(value, str):
    if value.lower() == 'true':
      return True
    if value.lower() == 'false':
      return False
  raise ValueError(f'Invalid bool value from testbed: {value}')
