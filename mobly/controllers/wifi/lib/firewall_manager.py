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

"""The module for managing firewall rules on OpenWrt devices."""

from __future__ import annotations

import enum
from typing import Protocol

from mobly.controllers.wifi.lib import ssh as ssh_lib
from mobly.controllers.wifi.lib import constants


@enum.unique
class FirewallType(enum.StrEnum):
  """The firewall backend type."""

  IPTABLES = 'iptables'
  NFTABLES = 'nftables'


@enum.unique
class FirewallAction(enum.StrEnum):
  """The action to perform on a firewall rule."""

  INSERT = 'insert'
  DELETE = 'delete'


class FirewallProtocol(Protocol):
  """Protocol for firewall operations on OpenWrt devices."""

  def allow_ip_forward(self) -> None:
    """Enables IP forwarding in the kernel."""
    ...

  def enable_nat(self, interface: str) -> None:
    """Enables NAT (masquerade) on the specified outgoing interface."""
    ...

  def forward_traffic(
      self,
      in_interface: str,
      out_interface: str,
      action: FirewallAction = FirewallAction.INSERT,
  ) -> None:
    """Allows or removes forwarding of all traffic between interfaces."""
    ...

  def forward_known_traffic(
      self,
      in_interface: str,
      out_interface: str,
      action: FirewallAction = FirewallAction.INSERT,
  ) -> None:
    """Allows or removes forwarding of established/related traffic between interfaces."""
    ...


class IptablesFirewall:
  """Firewall implementation using iptables."""

  def __init__(self, ssh: ssh_lib.SSHProxy):
    self._ssh = ssh

  def allow_ip_forward(self) -> None:
    """Enables IP forwarding in the kernel."""
    self._ssh.execute_command(
        command=constants.Commands.FIREWALL_ENABLE_IP_FORWARD,
        timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
    )

  def enable_nat(self, interface: str) -> None:
    """Enables NAT (masquerade) on the specified outgoing interface."""
    self._ssh.execute_command(
        command=constants.Commands.FIREWALL_ENABLE_NAT.format(
            interface=interface
        ),
        timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
    )

  def forward_traffic(
      self,
      in_interface: str,
      out_interface: str,
      action: FirewallAction = FirewallAction.INSERT,
  ) -> None:
    """Allows or removes forwarding of all traffic between interfaces."""
    iptables_action = (
        constants.IptablesAction.INSERT
        if action == FirewallAction.INSERT
        else constants.IptablesAction.DELETE
    )
    self._ssh.execute_command(
        command=constants.Commands.FIREWALL_FORWARD_TRAFFIC.format(
            action=iptables_action,
            in_interface=in_interface,
            out_interface=out_interface,
        ),
        timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
        ignore_error=(action == FirewallAction.DELETE),
    )

  def forward_known_traffic(
      self,
      in_interface: str,
      out_interface: str,
      action: FirewallAction = FirewallAction.INSERT,
  ) -> None:
    """Allows or removes forwarding of established/related traffic between interfaces."""
    iptables_action = (
        constants.IptablesAction.INSERT
        if action == FirewallAction.INSERT
        else constants.IptablesAction.DELETE
    )
    self._ssh.execute_command(
        command=constants.Commands.FIREWALL_FORWARD_KNOWN_TRAFFIC.format(
            action=iptables_action,
            in_interface=in_interface,
            out_interface=out_interface,
        ),
        timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
        ignore_error=(action == FirewallAction.DELETE),
    )


class NftablesFirewall:
  """Firewall implementation using nftables."""

  def __init__(self, ssh: ssh_lib.SSHProxy):
    self._ssh = ssh

  def allow_ip_forward(self) -> None:
    """Enables IP forwarding in the kernel."""
    self._ssh.execute_command(
        command=constants.Commands.FIREWALL_ENABLE_IP_FORWARD,
        timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
    )

  def enable_nat(self, interface: str) -> None:
    """Enables NAT (masquerade) on the specified outgoing interface."""
    self._ssh.execute_command(
        command=constants.Commands.FIREWALL_NFTABLES_ENABLE_NAT.format(
            interface=interface
        ),
        timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
    )

  def forward_traffic(
      self,
      in_interface: str,
      out_interface: str,
      action: FirewallAction = FirewallAction.INSERT,
  ) -> None:
    """Allows or removes forwarding of all traffic between interfaces."""
    nftables_action = (
        constants.NftablesAction.INSERT
        if action == FirewallAction.INSERT
        else constants.NftablesAction.DELETE
    )
    self._ssh.execute_command(
        command=constants.Commands.FIREWALL_NFTABLES_FORWARD_TRAFFIC.format(
            action=nftables_action,
            in_interface=in_interface,
            out_interface=out_interface,
        ),
        timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
        ignore_error=(action == FirewallAction.DELETE),
    )

  def forward_known_traffic(
      self,
      in_interface: str,
      out_interface: str,
      action: FirewallAction = FirewallAction.INSERT,
  ) -> None:
    """Allows or removes forwarding of established/related traffic between interfaces."""
    nftables_action = (
        constants.NftablesAction.INSERT
        if action == FirewallAction.INSERT
        else constants.NftablesAction.DELETE
    )
    self._ssh.execute_command(
        command=constants.Commands.FIREWALL_NFTABLES_FORWARD_KNOWN_TRAFFIC.format(
            action=nftables_action,
            in_interface=in_interface,
            out_interface=out_interface,
        ),
        timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
        ignore_error=(action == FirewallAction.DELETE),
    )


class Firewall:
  """Proxy firewall manager that delegates to Iptables or Nftables implementations."""

  def __init__(
      self,
      ssh: ssh_lib.SSHProxy,
      firewall_type: FirewallType | None = None,
  ):
    self._ssh = ssh
    self._firewall_type = firewall_type
    self._delegate: FirewallProtocol | None = None

  def _get_delegate(self) -> FirewallProtocol:
    """Returns the active delegation firewall."""
    if self._delegate is not None:
      return self._delegate

    if self._firewall_type == FirewallType.NFTABLES:
      self._delegate = NftablesFirewall(self._ssh)
    elif self._firewall_type == FirewallType.IPTABLES:
      self._delegate = IptablesFirewall(self._ssh)
    else:
      cmd_results = ssh_lib.CommandResults()
      self._ssh.execute_command(
          'command -v nft',
          timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
          ignore_error=True,
          command_results_collector=cmd_results,
      )
      if cmd_results.exit_code == 0:
        self._delegate = NftablesFirewall(self._ssh)
      else:
        self._delegate = IptablesFirewall(self._ssh)

    return self._delegate

  def allow_ip_forward(self) -> None:
    """Enables IP forwarding in the kernel."""
    self._get_delegate().allow_ip_forward()

  def enable_nat(self, interface: str) -> None:
    """Enables NAT (masquerade) on the specified outgoing interface."""
    self._get_delegate().enable_nat(interface)

  def forward_traffic(
      self,
      in_interface: str,
      out_interface: str,
      action: FirewallAction = FirewallAction.INSERT,
  ) -> None:
    """Allows or removes forwarding of all traffic between interfaces."""
    self._get_delegate().forward_traffic(in_interface, out_interface, action)

  def forward_known_traffic(
      self,
      in_interface: str,
      out_interface: str,
      action: FirewallAction = FirewallAction.INSERT,
  ) -> None:
    """Allows or removes forwarding of established/related traffic between interfaces."""
    self._get_delegate().forward_known_traffic(
        in_interface, out_interface, action
    )
