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

"""Utillity functions for Linux `ip` command."""

from collections.abc import Sequence
import dataclasses
import re
from typing import Any

from mobly.controllers.wifi.lib import constants


OpenWrtDevice = Any

_LINK_REGEX = re.compile(
    r'link/(?P<link_type>\S+)\s+'
    r'(?P<mac_address>[0-9a-fA-F:]+)'
    r'(?:\s+brd\s+(?P<broadcast_mac>[0-9a-fA-F:]+))?'
)

_IPV4_REGEX = re.compile(
    r'inet\s+(?P<ipv4_address>\S+/\S+)'
    r'(?:\s+brd\s+(?P<broadcast_ipv4>\S+))?'
    r'\s+scope\s+(?P<ipv4_scope>[^\n]+)'
    r'(?:\n\s+valid_lft\s+(?P<ipv4_valid_lft>\S+)\s+preferred_lft\s+(?P<ipv4_preferred_lft>\S+))?'
)

_IPV6_REGEX = re.compile(
    r'inet6\s+(?P<ipv6_address>\S+/\S+)'
    r'\s+scope\s+(?P<ipv6_scope>[^\n]+)'
    r'(?:\n\s+valid_lft\s+(?P<ipv6_valid_lft>\S+)\s+preferred_lft\s+(?P<ipv6_preferred_lft>\S+))?'
)

_HEADER_REGEX = re.compile(
    r'^(?P<interface_id>\d+):\s+'
    r'(?P<interface_name>\S+):\s+'
    r'<(?P<flags>[A-Z_,-]+)>\s+'
    r'mtu\s+(?P<mtu>\d+)\s+'
    r'qdisc\s+(?P<qdisc>\S+)'
    r'(?:\s+master\s+(?P<bridge>\S+))?'
    r'(?:\s+state\s+(?P<state>\S+))?'
    r'(?:\s+group\s+(?P<group>\S+))?'
    r'(?:\s+qlen\s+(?P<qlen>\d+))?',
    re.MULTILINE,
)


@dataclasses.dataclass(frozen=True, kw_only=True)
class IpAddrInterface:
  """Class for representing an entry in `ip addr show` output."""
  id: int
  name: str
  flags: str
  mtu: str
  qdisc: str
  virtual_of: str | None = None
  bridge: str | None = None
  state: str | None = None
  group: str | None = None
  qlen: str | None = None
  link_type: str | None = None
  mac_address: str | None = None
  broadcast_mac: str | None = None
  ipv4_address: str | None = None
  broadcast_ipv4: str | None = None
  ipv4_scope: str | None = None
  ipv4_valid_lft: str | None = None
  ipv4_preferred_lft: str | None = None
  ipv6_address: str | None = None
  ipv6_scope: str | None = None
  ipv6_valid_lft: str | None = None
  ipv6_preferred_lft: str | None = None


def _parse_interface_name(interface_name: str) -> tuple[str, str | None]:
  """Parses interface name and returns (name, virtual_of)."""
  name, _, virtual_of = interface_name.partition('@')
  return name, virtual_of or None


def parse_all_ip_addr(ip_addr_str: str) -> Sequence[IpAddrInterface]:
  """Parses an entry in `ip addr show` output."""
  ip_addr_list: list[IpAddrInterface] = []

  blocks = re.split(r'(?m)^(?=\d+:)', ip_addr_str)

  for block in blocks:
    block = block.strip()
    if not block:
      continue
    header_match = _HEADER_REGEX.search(block)
    if not header_match:
      continue

    interface_info: dict[str, Any] = header_match.groupdict()
    interface_info['id'] = int(interface_info.pop('interface_id'))
    interface_info['name'], interface_info['virtual_of'] = (
        _parse_interface_name(interface_info.pop('interface_name'))
    )

    for match in (
        _LINK_REGEX.search(block),
        _IPV4_REGEX.search(block),
        _IPV6_REGEX.search(block),
    ):
      if match:
        interface_info.update(match.groupdict())

    if interface_info.get('ipv4_scope'):
      interface_info['ipv4_scope'] = interface_info['ipv4_scope'].strip()
    if interface_info.get('ipv6_scope'):
      interface_info['ipv6_scope'] = interface_info['ipv6_scope'].strip()

    ip_addr_list.append(IpAddrInterface(**interface_info))

  return ip_addr_list


def get_all_ip_addr_interfaces(
    device: 'OpenWrtDevice',
) -> Sequence[IpAddrInterface]:
  """Gets all the entries in `ip addr show` output from the given device."""
  output = device.ssh.execute_command(
      command=constants.Commands.IP_ADDR_SHOW,
      timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
  )
  return parse_all_ip_addr(output)
