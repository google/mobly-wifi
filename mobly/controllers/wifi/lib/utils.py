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

from collections.abc import Callable, Mapping, Sequence
import dataclasses
import datetime
import ipaddress
import string
import time
from typing import Any

from mobly import utils

from mobly.controllers.wifi.lib import errors
from mobly.controllers.wifi.lib import iw_utils
from mobly.controllers.wifi.utils import ip_utils

# Avoid directly importing OpenWrtDevice, which causes circular dependencies.
OpenWrtDevice = Any


@dataclasses.dataclass(frozen=True, kw_only=True)
class IpInterface:
  """IP Interface class for OpenWrt device.

  Attributes:
    id: The interface id.
    name: The interface name.
    type: The interface type.
    mac_address: The MAC address of the interface.
    state: The state of the interface.
    virtual_of: The interface that this interface is virtual of.
    bridge: The bridge of the interface.
    ip: The IPv4 address of the interface.
    subnet: The IPv4 subnet of the interface.
    iw_interface: The interface information from `iw dev` command if this
      interface is a wireless interface.
  """

  id: int
  name: str
  type: str
  mac_address: str
  state: str
  virtual_of: str | None = None
  bridge: str | None = None
  ip: ipaddress.IPv4Address | None = None
  subnet: ipaddress.IPv4Network | None = None
  iw_interface: iw_utils.Interface | None = None


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


def get_interface_ip_iw_map(
    device: OpenWrtDevice,
) -> Mapping[str, IpInterface]:
  """Gets all interfaces and their information.

  This method also correlates the information from `iw dev` command with the
  information from `ip addr show` command to get the wireless interface
  information on matched interface names.

  If an interface does not have an IP address but is part of a bridge, it
  inherits the IP address and subnet from its bridge interface.

  Args:
    device: The OpenWrtDevice instance.

  Returns:
    A mapping of interface name to interface information.
  """
  interfaces: Sequence[ip_utils.IpAddrInterface] = (
      ip_utils.get_all_ip_addr_interfaces(device)
  )
  iw_interfaces = iw_utils.get_all_interfaces(device)
  iw_interfaces_map = {interface.name: interface for interface in iw_interfaces}
  # IP address is in the format of `ip_addr/mask_len`.
  parse_ipv4_addr = (
      lambda ip_addr: ipaddress.IPv4Address(ip_addr.split('/')[0])
      if ip_addr is not None
      else None
  )

  parse_subnet_addr = (
      lambda subnet_addr: ipaddress.IPv4Network(subnet_addr, strict=False)
      if subnet_addr is not None
      else None
  )

  pre_interfaces = {
      intf.name: IpInterface(
          id=intf.id,
          name=intf.name,
          type=intf.link_type,  # pyrefly: ignore[bad-argument-type]
          mac_address=intf.mac_address,  # pyrefly: ignore[bad-argument-type]
          state=intf.state,  # pyrefly: ignore[bad-argument-type]
          virtual_of=intf.virtual_of,
          bridge=intf.bridge,
          ip=parse_ipv4_addr(intf.ipv4_address),
          subnet=parse_subnet_addr(intf.ipv4_address),
          iw_interface=iw_interfaces_map.get(intf.name),
      )
      for intf in interfaces
  }

  final_interfaces = {}
  for name, intf in pre_interfaces.items():
    ip = intf.ip
    subnet = intf.subnet
    if ip is None and intf.bridge is not None:
      bridge_intf = pre_interfaces.get(intf.bridge)
      if bridge_intf:
        ip = bridge_intf.ip
        subnet = bridge_intf.subnet
    final_interfaces[name] = dataclasses.replace(intf, ip=ip, subnet=subnet)

  return final_interfaces


def get_ap_ip_and_subnet(
    device: OpenWrtDevice,
    ssid: str,
    mac_address: str | None = None,
) -> tuple[ipaddress.IPv4Address, ipaddress.IPv4Network]:
  """Gets the AP's IP address and subnet of the given SSID.

  Args:
    device: The OpenWrtDevice instance.
    ssid: The target SSID of the AP to get the IP and subnet from.
    mac_address: The mac address of the AP to get the IP and subnet. This
      argument is used to distinguish between multiple non-bridged APs with the
      same SSID.

  Returns:
    A tuple of the AP's IP address and subnet of the given SSID.

  Raises:
    errors.BaseError: If the target IP or subnet is not found.
  """
  intf_ip_iw_map = get_interface_ip_iw_map(device)

  def is_interface_matched(intf: IpInterface) -> bool:
    iw = intf.iw_interface
    if iw is None or iw.ssid is None:
      return False
    ssid_matches = iw.ssid == ssid
    mac_matches = mac_address is None or intf.mac_address == mac_address
    return ssid_matches and mac_matches

  for intf in intf_ip_iw_map.values():
    if is_interface_matched(intf):
      if intf.ip is None:
        raise errors.BaseError(
            f'Failed to get target IP for SSID {ssid}, interface {intf}'
        )
      if intf.subnet is None:
        raise errors.BaseError(
            f'Failed to get subnet for SSID {ssid}, interface {intf}'
        )
      return (intf.ip, intf.subnet)
  raise errors.BaseError(
      f'Failed to find a matched SSID {ssid} with mac address'
      f' {mac_address} from broadcasting SSIDs'
  )
