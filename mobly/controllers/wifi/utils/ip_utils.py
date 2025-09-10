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

IP_ADDR_REGEX = r"""
(?:
    (?P<interface_id>\d+):                               # Match the id number (e.g., "1:")
    \s+
    (?P<interface_name>\S+):                             # Match the interface name (e.g., "lo:")
    \s+
    <(?P<flags>[A-Z_,-]+)>                               # Match the flags within angle brackets (e.g., "<LOOPBACK,UP,LOWER_UP>")
    \s+
    mtu\s+(?P<mtu>\d+)                                   # Match "mtu" followed by a number
    \s+
    qdisc\s+(?P<qdisc>\S+)                               # Match "qdisc" followed by a word
    (?:
        \s+
        master\s+(?P<bridge>\S+)                         # Match optional bridge
    )?
    (?:
        \s+
        state\s+(?P<state>\S+)                           # Match "state"
        \s+
        qlen\s+(?P<qlen>\d+)                             # Match "qlen"
    )?
    (?:\s+
        link/(?P<link_type>\S+)\s+
        (?P<mac_address>[0-9a-fA-F:]+)                   # Match a MAC address
        (?:\s+brd\s+(?P<broadcast_mac>[0-9a-fA-F:]+))?
    )?
    (?:\s+
        inet\s+(?P<ipv4_address>\S+/\S+)                 # Match IPv4 address and subnet
        (?:\s+brd\s+(?P<broadcast_ipv4>\S+))?            # Match optional broadcast address for IPv4
        \s+scope\s+(?P<ipv4_scope>.+)
        (?:\s+valid_lft\s+(?P<ipv4_valid_lft>\S+)\s+preferred_lft\s+(?P<ipv4_preferred_lft>\S+))?
    )?
    (?:\s+
        inet6\s+(?P<ipv6_address>\S+/\S+)                # Match IPv6 address and subnet
        \s+scope\s+(?P<ipv6_scope>.+)
        (?:\s+valid_lft\s+(?P<ipv6_valid_lft>\S+)\s+preferred_lft\s+(?P<ipv6_preferred_lft>\S+))?
    )?
)+
"""

COMPILED_IP_ADDR_REGEX = re.compile(IP_ADDR_REGEX, re.VERBOSE)


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


def parse_all_ip_addr(ip_addr_str: str) -> Sequence[IpAddrInterface]:
  """Parses an entry in `ip addr show` output."""
  ip_addr_list: list[IpAddrInterface] = []

  trim_space = lambda s: s.strip() if s is not None else None
  physical_interface = (
      lambda s: s.split('@')[1] if s is not None and '@' in s else None
  )

  matches = COMPILED_IP_ADDR_REGEX.finditer(ip_addr_str)

  for match in matches:
    ip_addr_list.append(
        IpAddrInterface(
            id=int(match.group('interface_id')),
            name=match.group('interface_name').split('@')[0],
            flags=match.group('flags'),
            mtu=match.group('mtu'),
            qdisc=match.group('qdisc'),
            virtual_of=physical_interface(match.group('interface_name')),
            bridge=match.group('bridge'),
            state=match.group('state'),
            qlen=match.group('qlen'),
            link_type=match.group('link_type'),
            mac_address=match.group('mac_address'),
            broadcast_mac=match.group('broadcast_mac'),
            ipv4_address=match.group('ipv4_address'),
            broadcast_ipv4=match.group('broadcast_ipv4'),
            ipv4_scope=trim_space(match.group('ipv4_scope')),
            ipv4_valid_lft=match.group('ipv4_valid_lft'),
            ipv4_preferred_lft=match.group('ipv4_preferred_lft'),
            ipv6_address=match.group('ipv6_address'),
            ipv6_scope=trim_space(match.group('ipv6_scope')),
            ipv6_valid_lft=match.group('ipv6_valid_lft'),
            ipv6_preferred_lft=match.group('ipv6_preferred_lft'),
        )
    )
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
