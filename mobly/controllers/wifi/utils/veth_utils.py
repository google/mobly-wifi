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

"""Utilities for handling virtual ethernet interfaces on an OpenWrt device.

Supports only a single veth pair per device.
"""

import logging
from typing import Any, Tuple

from mobly.controllers.wifi import openwrt_device
from mobly.controllers.wifi.lib import constants
from mobly.controllers.wifi.utils import ip_utils

OpenWrtDevice = Any

REQUESTED_VETH_NAME = 'vethA0'
REQUESTED_VETH_PEER_NAME = 'vethB0'
VETH_PREFIX = 'veth'


class VethError(Exception):
  """Error class for veth utilities."""


def clean_up_veth_and_create_new_pair(
    device: openwrt_device.OpenWrtDevice,
) -> Tuple[str, str]:
  """Creates and brings up a new veth pair.

  Deletes any existing veth interfaces to ensure a clean state.

  Args:
    device: The OpenWrtDevice to create the veth pair on.

  Returns:
    A tuple containing the names of the two veth interfaces.

  Raises:
    VethError: If the veth pair cannot be created.
  """
  release_veth_interfaces(device)
  logging.debug(
      'Requesting veth pair with names: %s and %s',
      REQUESTED_VETH_NAME,
      REQUESTED_VETH_PEER_NAME,
  )
  device.ssh.execute_command(
      constants.Commands.IP_LINK_ADD_VETH_PAIR.format(
          veth=REQUESTED_VETH_NAME, veth_peer=REQUESTED_VETH_PEER_NAME
      )
  )
  # OpenWrt devices do not respect the requested veth peer name, (using veth0 by
  # default, or vethX+1 if vethX is taken), so we need to determine the actual
  # veth interface names rather than using the requested names.
  interfaces = ip_utils.get_all_ip_addr_interfaces(device)
  veth_interface_names = [
      iface.name for iface in interfaces if iface.name.startswith(VETH_PREFIX)
  ]
  if len(veth_interface_names) != 2:
    raise VethError(
        f'Failed to create veth pair {REQUESTED_VETH_NAME}'
        f'/{REQUESTED_VETH_PEER_NAME}, expected 2 veth interfaces, got'
        f' {len(veth_interface_names)}.'
    )
  veth = veth_interface_names[0]
  veth_peer = veth_interface_names[1]
  logging.debug(
      'Got veth pair with actual names: %s and %s',
      veth,
      veth_peer,
  )
  device.ssh.execute_command(
      constants.Commands.IP_LINK_UP.format(interface=veth)
  )
  device.ssh.execute_command(
      constants.Commands.IP_LINK_UP.format(interface=veth_peer)
  )
  return veth, veth_peer


def release_veth_interfaces(device: openwrt_device.OpenWrtDevice) -> None:
  """Deletes all veth interfaces on the device.

  Args:
    device: The OpenWrtDevice to release the veth interfaces on.
  """
  interfaces = ip_utils.get_all_ip_addr_interfaces(device)
  veth_interfaces = [
      iface for iface in interfaces if iface.name.startswith(VETH_PREFIX)
  ]

  while veth_interfaces:
    veth = veth_interfaces.pop(0)
    device.ssh.execute_command(
        constants.Commands.IP_LINK_DELETE.format(interface=veth.name)
    )
    # Deleting a veth interface will also delete the peer interface, so remove
    # the peer interface from veth_interfaces.
    veth_interfaces = [
        iface for iface in veth_interfaces if iface.virtual_of != veth.name
    ]
