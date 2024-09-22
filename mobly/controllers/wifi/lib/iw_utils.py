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

"""Utilities to wrap around running the `iw` prgoram on AP devices.

See following file for an example of the `iw phy` output:
//testing/mobly/platforms/wifi/test_data/iw_phy_output.txt
"""

import dataclasses
import enum
import re
from typing import Any, Self, Sequence

from mobly.controllers.wifi.lib import constants
from mobly.controllers.wifi.lib import errors

OpenWrtDevice = Any

_FREQUENCY_INFO_RE = re.compile(
    r'.*\* \d+(\.\d)? MHz \[(?P<channel>\d+)\](?: \([0-9.]+ dBm\))?(?:'
    r' \((?P<flags>[a-zA-Z, ]+)\))?.*'
)
_FREQUENCY_INFO_RE_GROUP_CHANNEL = 'channel'
_FREQUENCY_INFO_RE_GROUP_FLAGS = 'flags'

_BAND_RE = re.compile(r'Band (?P<num>\d+):')
_BAND_RE_GROUP_NUM = 'num'

_PHY_NAME_RE = re.compile(r'Wiphy (?P<name>\S+)')
_PHY_NAME_RE_GROUP_NAME = 'name'

_PHY_INDEX_RE = re.compile(r'wiphy index: (?P<phyindex>\d+)')
_PHY_INDEX_RE_GROUP_PHYINDEX = 'phyindex'

_PREFIX_TAB_CHARACTERS_RE = re.compile(r'^\t+')

_TEXT_LABEL_FREQUENCIES = 'Frequencies:'

_STATION_TITLE_RE = re.compile(
    r'^Station (?P<mac_address>[:0-9a-fA-F]+) \(on \S+\)'
)
_STATION_TITLE_RE_GROUP = 'mac_address'

_ASSOCIATED_AT_RE = re.compile(r'associated at:\s*(?P<timestamp>\d+) ms')
_ASSOCIATED_AT_RE_GROUP = 'timestamp'

_IW_DEV_RE = re.compile(
    r'Interface\s+(?P<name>.*)(.|\n)*?'
    r'addr\s+(?P<addr>.*)(.|\n)*?'
    r'(ssid\s+(?P<ssid>.*)(.|\n)*?)?'
    r'type\s+(?P<type>.*)'
)


class IwOutputParsingError(errors.BaseError):
  """Failed to parse the output of the `iw` command."""


class NoSuchStationError(errors.BaseError):
  """Failed to find the specified station."""


@enum.unique
class ChannelFlags(enum.StrEnum):
  """Channel flags in the `iw phy` output."""

  RADAR_DETECTION = 'radar detection'


@dataclasses.dataclass(frozen=True, eq=True, order=True)
class Channel:
  """Channel information in the `Frequencies` section of `iw phy` output."""

  num: int
  flags: Sequence[str]


@dataclasses.dataclass(frozen=True, eq=True, order=True)
class Band:
  """Band information in the `Bands` section of `iw phy` output."""

  num: int
  channels: Sequence[Channel]


@dataclasses.dataclass(frozen=True)
class Interface:
  """Interface information in the `iw dev` output.

  Attributes:
    name: The name of the interface.
    addr: The MAC address of the interface.
    type: Specify the operating mode of the interface.
    ssid: The SSID of the interface, None if the interface is not a broadcasting
      Wi-Fi.
  """

  name: str
  addr: str
  type: str
  ssid: str | None = None


@dataclasses.dataclass(frozen=True, eq=True, order=True)
class Phy:
  """Wireless hardware device information in the `iw phy` output."""

  name: str
  phyindex: int
  bands: Sequence[Band]


@dataclasses.dataclass(frozen=True)
class Station:
  """Station information in the `iw dev {devname} station dump/get` output.

  Attributes:
    mac_address: The MAC address of the station.
    associated_at_timestamp_ms: The timestamp when the station associated with
      the AP.
  """

  mac_address: str
  associated_at_timestamp_ms: int


@dataclasses.dataclass(frozen=True, eq=True, order=True)
class _TreeNode:
  """The class for representing `iw` output into Tree structure.

  See docstring of `_parse_indented_text` for parse logic.
  """

  text: str | None
  indent_level: int
  children: list[Self] = dataclasses.field(default_factory=list)

  def find_child_by_regex(
      self, *, pattern: re.Pattern[str]
  ) -> tuple[Self, re.Match[str]]:
    """Finds the direct child of which the text matches the given pattern."""
    matched_children = []
    for c in self.children:
      if (match := pattern.match(c.text)) is not None:
        matched_children.append((c, match))
    if not matched_children:
      raise IwOutputParsingError(
          f'Did not find child with pattern: "{pattern}"'
      )
    if len(matched_children) > 1:
      raise IwOutputParsingError(
          f'Found multiple children with pattern: "{pattern}"'
      )
    return matched_children[0]

  def find_children_by_regex(
      self, *, pattern: re.Pattern[str]
  ) -> Sequence[Self]:
    """Finds all direct children of which the text match the regex pattern."""
    return [c for c in self.children if pattern.match(c.text)]

  def find_child(self, *, text: str) -> Self:
    """Finds the direct child of which the text equals the given text."""
    matched_children = [c for c in self.children if text == c.text]
    if not matched_children:
      raise IwOutputParsingError(f'Did not find child with text: "{text}"')
    if len(matched_children) > 1:
      raise IwOutputParsingError(f'Found multiple children with text: "{text}"')
    return matched_children[0]


def _get_indent_level(line: str) -> int:
  r"""Returns the indent level of the given line.

  The indent level means the number of `\t` characters at the start of this
  line.

  Args:
    line: The line to calculate indent level.

  Returns:
    The indent level.
  """
  prefix = _PREFIX_TAB_CHARACTERS_RE.match(line)
  if prefix is None:
    return 0
  return len(prefix[0])


def _recursively_parse_to_tree(
    lines: Sequence[str], parent_node: _TreeNode
) -> Sequence[str]:
  """Recursively parses the lines into a Tree.

  This function tries to parse lines `lines` to nodes in the subtree of node
  `parent_node`. `lines` may contain lines that are out of the `parent_node`
  subtree, this will return those lines.

  Args:
    lines: All the lines to be parsed.
    parent_node: The node that is considered the root node of the subtree.

  Returns:
    Return the lines that are out of the scope of `parent_node` subtree.

  Raises:
    IwOutputParsingError: Failed to parse the lines.
  """
  while lines:
    line = lines[0]
    if not line:
      lines = lines[1:]
      continue

    current_indent_level = _get_indent_level(line)

    line = line.strip()
    node = _TreeNode(text=line, indent_level=current_indent_level)

    if current_indent_level > parent_node.indent_level + 2:
      raise IwOutputParsingError(
          'Indented text parse error with a larger than 2 indent level'
          f' difference. Line: "{line}", parent_node: "{parent_node}"'
      )

    if current_indent_level == parent_node.indent_level + 1:
      parent_node.children.append(node)
      lines = lines[1:]
      continue

    if current_indent_level == parent_node.indent_level + 2:
      # This clause means current line is a child node of the last parsed line,
      # so we need to call _recursively_parse_to_tree to parse this line, with
      # last node as parent_node.
      if not parent_node.children:
        raise IwOutputParsingError(
            f'Indented text parse error with line "{line}", parent_node'
            f' "{parent_node}"'
        )

      child_node = parent_node.children[-1]
      child_node.children.append(node)
      lines = _recursively_parse_to_tree(lines[1:], child_node)
      continue

    # This clause means current line is not within the subtree of the
    # `parent_node`, so directly return.
    return lines

  return lines


def _parse_indented_text(text: str) -> _TreeNode:
  r"""Parses the indented text into a Tree.

  Following is the example of indented text to parse:
  ```
  Wiphy phy1
  \twiphy index: 1
  \tCapabilities: 0x9ff
  \t\tRX LDPC
  \t\tHT20
  ```

  The structure of the text is defined by the amount of `\t` characters at the
  start of each line. So we will parse the text into the following tree:

  ```
  _TreeNode(    # root
      text=None,
      indent_level=-1,
      children=[
        _TreeNode(
            text='Wiphy phy1',
            indent_level=0,
            children=[
                _TreeNode(
                    text='wiphy indext: 1',
                    indent_level=1,
                    children=[],
                ),
                _TreeNode(
                    text='Capabilities: 0x9ff',
                    indent_level=1,
                    children=[
                        _TreeNode(text='RX LDPC', indent_level=2, children=[]),
                        _TreeNode(text='HT20', indent_level=2, children=[]),
                    ],
                ),
            ],
        ),
      ],
  )
  ```
  Args:
    text: The indented text to parse.

  Returns:
    The root node of the parsed Tree.
  """
  root_node = _TreeNode(text=None, indent_level=-1)
  _recursively_parse_to_tree(
      lines=text.strip().splitlines(), parent_node=root_node
  )
  return root_node


def _parse_tree_to_channels(node: _TreeNode) -> Sequence[Channel]:
  """Parses the tree root at the given `node` to be channels."""
  channels = []
  for child in node.children:
    match = _FREQUENCY_INFO_RE.match(child.text)
    if match is None:
      continue
    channel = int(match.group(_FREQUENCY_INFO_RE_GROUP_CHANNEL))
    flags_match = match.group(_FREQUENCY_INFO_RE_GROUP_FLAGS)
    flags = []
    if flags_match is not None:
      flags = list(map(lambda s: s.strip(), flags_match.split(',')))
    channels.append(Channel(num=channel, flags=flags))
  return channels


def _parse_tree_to_band(node: _TreeNode) -> Band:
  """Parses the tree root at the given `node` to be a band."""
  match = _BAND_RE.match(node.text)
  if match is None:
    raise IwOutputParsingError(
        f'Did not find Band number in node: "{node.text}"'
    )
  num = int(match.group(_BAND_RE_GROUP_NUM))
  channels = _parse_tree_to_channels(
      node.find_child(text=_TEXT_LABEL_FREQUENCIES)
  )
  return Band(num=num, channels=channels)


def get_all_phys(device: 'OpenWrtDevice') -> Sequence[Phy]:
  """Gets all the wireless hardware devices on the given AP device."""
  cmd = constants.Commands.IW_PHY
  output = device.ssh.execute_command(
      command=cmd,
      timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
  )
  device.log.debug('Parsing command "%s" output to a tree.', cmd)
  tree_root = _parse_indented_text(output)

  device.log.debug('Parsing the tree to structured data types.')
  phys = []
  for node in tree_root.children:
    phy_match = _PHY_NAME_RE.match(node.text)
    if phy_match is None:
      raise IwOutputParsingError(
          f'Did not find Wiphy name in node: "{node.text}"'
      )
    phy_name = phy_match.group(_PHY_NAME_RE_GROUP_NAME)
    _, phyindex_match = node.find_child_by_regex(pattern=_PHY_INDEX_RE)
    phyindex = int(phyindex_match.group(_PHY_INDEX_RE_GROUP_PHYINDEX))

    bands = []
    for node in node.find_children_by_regex(pattern=_BAND_RE):
      bands.append(_parse_tree_to_band(node))
    phys.append(Phy(name=phy_name, phyindex=phyindex, bands=bands))
  return phys


def get_all_dfs_channels(phy: Phy) -> set[int]:
  """Gets all DFS channels of the given wireless hardware device."""
  dfs_channels = set()
  for band in phy.bands:
    for channel in band.channels:
      if ChannelFlags.RADAR_DETECTION in channel.flags:
        dfs_channels.add(channel.num)
  return dfs_channels


def get_phy_by_channel(phys: Sequence[Phy], channel: int) -> Phy:
  """Gets the wireless hardware device that can supports the given channel."""
  for phy in phys:
    for band in phy.bands:
      for c in band.channels:
        if c.num == channel:
          return phy
  raise IwOutputParsingError(
      'Did not find a wireless hardware device that supports channel'
      f' "{channel}". All devices: {phys}'
  )


def _parse_iw_station_output(output: str) -> Sequence[Station]:
  """Parses the iw output related to station information.

  Example output of iw station dump/get:

  ```
  Station ae:d9:f5:47:9a:c0 (on managed0)
      inactive time: 36 ms
      rx bytes: 20164
      ...
      connected time: 8 seconds
      associated at [boottime]: 42.448s
      associated at: 1713791172733 ms
      current time: 1713791180538 ms
  ```

  Args:
    output: The iw output.

  Returns:
    A sequence of station.

  Raises:
    IwOutputParsingError: if failed to parse the output.
  """
  tree_root = _parse_indented_text(output)
  results = []
  for node in tree_root.children:
    station_title_match = _STATION_TITLE_RE.match(node.text)
    if station_title_match is None:
      raise IwOutputParsingError(
          f'Did not find Station mac address in node: "{node.text}"'
      )
    station_mac_address = station_title_match.group(_STATION_TITLE_RE_GROUP)

    _, match = node.find_child_by_regex(pattern=_ASSOCIATED_AT_RE)
    timestamp = int(match.group(_ASSOCIATED_AT_RE_GROUP))

    results.append(
        Station(
            mac_address=station_mac_address,
            associated_at_timestamp_ms=timestamp,
        )
    )
  return results


def get_all_known_stations(
    device: 'OpenWrtDevice', interface: str
) -> Sequence[Station]:
  """Gets all the known stations on the given wireless interface."""
  cmd = constants.Commands.IW_DEV_STATION_DUMP.format(interface=interface)
  output = device.ssh.execute_command(
      command=cmd,
      timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
  )
  return _parse_iw_station_output(output)


def get_station_info(
    device: 'OpenWrtDevice', interface: str, mac_address: str
) -> Station:
  """Gets info for the station with the MAC address on the given interface.

  Args:
    device: The AP device controller.
    interface: The interface that the station is associated with.
    mac_address: The MAC address of the station.

  Returns:
    The station information.

  Raises:
    NoSuchStationError: Failed to find the specified station.
  """
  cmd = constants.Commands.IW_DEV_STATION_GET.format(
      interface=interface, station_mac_address=mac_address
  )
  output = device.ssh.execute_command(
      command=cmd,
      timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
      ignore_error=True,
  )
  if not output:
    raise NoSuchStationError(
        f'Did not find station with mac address "{mac_address}". Got iw command'
        f' output: {output}'
    )
  stations = _parse_iw_station_output(output)
  # The output of the above command will contain one station at most.
  return stations[0]


def get_all_interfaces(device: 'OpenWrtDevice') -> Sequence[Interface]:
  """Gets all interfaces on the given AP device."""
  output = device.ssh.execute_command(
      command=constants.Commands.IW_DEV,
      timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
  )
  return [
      Interface(**match.groupdict()) for match in _IW_DEV_RE.finditer(output)
  ]
