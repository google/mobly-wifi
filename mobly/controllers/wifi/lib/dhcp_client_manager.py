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

"""Manages dhcpcd client on device interfaces."""

import datetime
import logging
from typing import Any

from mobly import logger as mobly_logger

from mobly.controllers.wifi.lib import ssh as ssh_lib
from mobly.controllers.wifi.lib import errors
from mobly.controllers.wifi.lib import utils
from mobly.controllers.wifi.utils import ip_utils


OpenWrtDevice = Any

_DHCPCD_START_COMMAND = 'dhcpcd "{interface}" --noipv4ll'
_DHCPCD_STOP_COMMAND = 'dhcpcd -k "{interface}"'

_DHCP_WAIT_TIME = datetime.timedelta(seconds=20)
_DHCP_CHECK_INTERVAL = datetime.timedelta(seconds=1)


class DhcpClientError(errors.BaseError):
  """Raised for errors related to DHCP client."""


class DhcpClientManager:
  """Manages a dhcpcd client instance on a device interface."""

  def __init__(
      self,
      device: 'OpenWrtDevice',
      interface: str,
      base_logger: (
          logging.Logger | mobly_logger.PrefixLoggerAdapter | None
      ) = None,
  ):
    """Initializes the DhcpClientManager.

    Args:
      device: The device on which to manage the DHCP client.
      interface: The name of the interface on which to manage the DHCP client.
      base_logger: The logger to use. If None, defaults to device.log.
    """
    self._device = device
    self._interface = interface
    self._has_ip = False
    base_logger = base_logger or device.log
    self._log = mobly_logger.PrefixLoggerAdapter(
        base_logger,
        {
            mobly_logger.PrefixLoggerAdapter.EXTRA_KEY_LOG_PREFIX: (
                '[DhcpClientManager|%s]' % self._interface
            )
        },
    )

  def _check_ip(self) -> bool:
    """Checks if the interface has an IP address.

    Returns:
      True if the interface has an IP address, False otherwise.
    """
    try:
      interfaces = ip_utils.get_all_ip_addr_interfaces(self._device)
      for interface in interfaces:
        if (
            interface.name == self._interface
            and interface.ipv4_address is not None
        ):
          return True
      return False
    except (ssh_lib.ExecuteCommandError, ValueError) as e:
      self._log.debug('Error checking IP: %s', e)
      return False

  def request_ip(self):
    """Requests an IP address for the interface.

    Raises:
      DhcpClientError: If failed to get an IP address.
    """
    if self._has_ip:
      self.release_ip()

    self._log.debug('Requesting IP for interface: %s', self._interface)
    try:
      self._device.ssh.execute_command(
          _DHCPCD_START_COMMAND.format(interface=self._interface),
          ignore_error=True,
      )
    except ssh_lib.ExecuteCommandError as e:
      raise DhcpClientError(
          f'Failed to start dhcpcd on interface: {self._interface} with'
          f' error {e}'
      ) from e

    if not utils.wait_for_predicate(
        self._check_ip,
        timeout=_DHCP_WAIT_TIME,
        interval=_DHCP_CHECK_INTERVAL,
    ):
      raise DhcpClientError(
          f'Failed to get IP for interface {self._interface} within '
          f'{_DHCP_WAIT_TIME.total_seconds()} seconds.'
      )
    self._has_ip = True
    self._log.info('IP address obtained for interface: %s', self._interface)

  def release_ip(self):
    """Releases IP address for the interface."""
    if not self._has_ip:
      return
    self._log.debug('Releasing IP for interface: %s', self._interface)
    try:
      self._device.ssh.execute_command(
          _DHCPCD_STOP_COMMAND.format(interface=self._interface)
      )
      self._has_ip = False
    except ssh_lib.ExecuteCommandError as e:
      self._log.warning(
          'Failed to stop dhcpcd on interface: %s with error %s',
          self._interface,
          e,
      )
