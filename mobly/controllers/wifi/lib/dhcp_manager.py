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

"""Controlling DHCP server instances on AP devices."""

from collections.abc import Set
import contextlib
import dataclasses
import datetime
import ipaddress
import logging
import os
import threading
import typing
from typing import Any

from mobly import logger as mobly_logger

from mobly.controllers.wifi.lib import ssh as ssh_lib
from mobly.controllers.wifi.lib import constants

OpenWrtDevice = Any


# We intentionally do not set the log-facility configuration because we can
# directly capture logs through remote process output.
_DNSMASQ_CONFIG = """
dhcp-range={network_ip_start},{network_ip_end}
interface={iface}
log-dhcp
no-resolv
no-hosts
server=8.8.8.8
server=8.8.4.4
log-queries
except-interface=lo
bind-interfaces
dhcp-leasefile={lease_file_remote_path}
"""

_REMOTE_CMD_DEFAULT_TIMEOUT = datetime.timedelta(seconds=30)


@dataclasses.dataclass()
class DhcpConfig:
  """Configurations for a DhcpManager instance."""

  # The ID of the subnet where we will operate a DHCP server instance.
  subnet_id: int
  # The wireless interface name.
  iface: str

  # The subnet information structure.
  _subnet: ipaddress.IPv4Network | None = dataclasses.field(
      default=None, init=False
  )

  @property
  def subnet(self) -> ipaddress.IPv4Network:
    """The subnet information structure."""
    if self._subnet is None:
      self._subnet = typing.cast(
          ipaddress.IPv4Network,
          ipaddress.ip_network(f'192.168.{self.subnet_id}.0/24'),
      )
    return self._subnet

  @property
  def broadcast_ip(self) -> str:
    """The broadcast ip address."""
    return str(self.subnet.broadcast_address)

  @property
  def server_ip(self) -> str:
    """The server ip address."""
    # Use -2 here because `self.subnet[-1]` is the broadcast ip address.
    return str(self.subnet[-2])

  @property
  def assignable_ip_range(self) -> tuple[str, str]:
    """The range of the IPs that can be assigned to clients."""
    return (str(self.subnet[0]), str(self.subnet[128]))

  @property
  def mask_len(self) -> int:
    """The length of the network mask."""
    return self.subnet.prefixlen


_SUBNET_ID_MAX_COUNT = 256


class _SubnetIdGenerator:
  """The class to generate subnet IDs."""

  _busy_ids: Set[int]
  _counter: int
  _lock: threading.Lock

  def __init__(self):
    self._busy_ids = set()
    self._counter = 0
    self._lock = threading.Lock()

  def get(self) -> int:
    """Gets a free subnet ID."""
    with self._lock:
      for i in range(_SUBNET_ID_MAX_COUNT):
        counter = (self._counter + i) % _SUBNET_ID_MAX_COUNT
        if counter not in self._busy_ids:
          self._busy_ids.add(counter)
          self._counter = (counter + 1) % _SUBNET_ID_MAX_COUNT
          return counter

    raise RuntimeError(
        'Cannot find a free subnet ID because all'
        f' {_SUBNET_ID_MAX_COUNT} IDs are in use.'
    )

  def release(self, subnet_id: int) -> None:
    """Releases a subnet ID so it can be used by other subnets.

    This is a no-op if the provided ID is not in use.

    Args:
      subnet_id: The subnet ID to release.
    """
    with self._lock:
      if subnet_id in self._busy_ids:
        self._busy_ids.remove(subnet_id)


_subnet_id_generator = _SubnetIdGenerator()


class DhcpManager:
  """The class that manages one DHCP server instance on the AP device."""

  def __init__(
      self,
      device: 'OpenWrtDevice',
      wifi_id: int,
      iface: str,
      base_logger: (
          logging.Logger | mobly_logger.PrefixLoggerAdapter | None
      ) = None,
  ):
    """Constructor.

    Args:
      device: The AP device controller object.
      wifi_id: The ID of the WiFi network where we will operate a DHCP server
        instance.
      iface: The wireless interface name.
      base_logger: The base logger. Based on that logger, this class will prefix
        each log entry with string "[DhcpManager]".
    """
    self._device = device
    self._wifi_id = wifi_id
    self._subnet_id = _subnet_id_generator.get()
    self._remote_process = None
    base_logger = base_logger or device.log
    self._log = mobly_logger.PrefixLoggerAdapter(
        base_logger,
        {
            mobly_logger.PrefixLoggerAdapter.EXTRA_KEY_LOG_PREFIX: (
                f'[DhcpManager|wifi{self._wifi_id}]'
            )
        },
    )
    self._config = DhcpConfig(subnet_id=self._subnet_id, iface=iface)
    self._identifier = f'wifi{self._wifi_id},{self._config.iface}'

    self._local_work_dir = self._device.log_path
    self._remote_work_dir = self._device.remote_work_dir
    self._artifact_time_str = mobly_logger.get_log_file_timestamp()

  def start(self) -> None:
    """Starts this DHCP manager."""
    self._log.debug(
        'Starting a remote DHCP server instance with config %s', self._config
    )
    try:
      self._start()
    except ssh_lib.SSHRemoteError:
      self._log.error('Stopping due to start failure.')
      with contextlib.suppress(ssh_lib.SSHRemoteError):
        self.stop()
      raise

  def _start(self) -> None:
    """Starts a DHCP server instance on the AP device."""
    # Set the ip configurations to the wireless interface.
    self._device.ssh.execute_command(
        constants.Commands.IP_FLUSH.format(iface=self._config.iface),
        timeout=_REMOTE_CMD_DEFAULT_TIMEOUT.total_seconds(),
    )
    self._device.ssh.execute_command(
        constants.Commands.IP_ADDR_ADD.format(
            server_ip=self._config.server_ip,
            network_mask_len=self._config.mask_len,
            iface=self._config.iface,
            broadcast_ip=self._config.broadcast_ip,
        ),
        timeout=_REMOTE_CMD_DEFAULT_TIMEOUT.total_seconds(),
    )

    # Start a dnsmasq process on the remote device.
    config_file_remote_path = self._generate_remote_config_file()
    self._start_dnsmasq_process(config_file_remote_path)

  def _generate_remote_config_file(self):
    """Generates the configurations into a config file on the AP device."""
    # Generate the content of dnsmasq config.
    config_content = _DNSMASQ_CONFIG.format(
        network_ip_start=self._config.assignable_ip_range[0],
        network_ip_end=self._config.assignable_ip_range[1],
        iface=self._config.iface,
        lease_file_remote_path=self._get_remote_path(
            filename=self._get_lease_filename(),
        ),
    )

    # Write dnsmasq config to a remote file.
    filename = self._get_conf_filename()
    local_path = self._get_local_path(filename)
    remote_path = self._get_remote_path(filename)
    with open(local_path, 'w') as f:
      f.write(config_content)
    self._device.push_file(local_path, remote_path)
    # Rename the local file so it can be directly opened on Sponge.
    os.rename(local_path, f'{local_path}.txt')

    return remote_path

  def _start_dnsmasq_process(self, config_remote_path: str):
    local_path = self._get_local_path(filename=self._get_log_filename())
    command_elements = [
        'dnsmasq',
        f'--conf-file={config_remote_path}',
        '--no-daemon',
    ]
    command = ' '.join(command_elements)
    self._remote_process = self._device.ssh.start_remote_process(
        command, get_pty=True, output_file_path=local_path
    )
    self._log.debug(
        'Started dnsmasq remote process %d on the AP device.',
        self._remote_process.pid,
    )

  def __del__(self):
    self.stop()

  def stop(self):
    """Stops the DHCP server instance on the AP device."""
    if self._subnet_id is not None:
      _subnet_id_generator.release(self._subnet_id)
      self._subnet_id = None

    proc = self._remote_process
    self._remote_process = None

    if proc is None:
      return

    self._log.debug('Stopping remote DHCP server.')

    proc.terminate(
        timeout=_REMOTE_CMD_DEFAULT_TIMEOUT.total_seconds(),
        assert_process_exit=True,
    )
    self._log.debug(
        'Killed dnsmasq remote process %d with poll value: %s',
        proc.pid,
        proc.poll(),
    )

  def _get_remote_path(self, filename: str) -> str:
    return os.path.join(self._remote_work_dir, filename)

  def _get_local_path(self, filename: str) -> str:
    return os.path.join(self._local_work_dir, filename)

  def _get_conf_filename(self) -> str:
    return f'{self._identifier},dnsmasq.conf'

  def _get_log_filename(self) -> str:
    return f'{self._identifier},dnsmasq.log'

  def _get_lease_filename(self) -> str:
    return f'{self._identifier},dnsmasq.leases'
