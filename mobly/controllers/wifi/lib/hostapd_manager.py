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

"""The module for controlling hostpad on AP devices.

The responsibility of this module mainly include:
* Generate hostapd configuration files on AP devices.
* Start/Stop hostpad processes on AP devices.
"""

from collections.abc import Iterable, Sequence
import contextlib
import dataclasses
import datetime
import hashlib
import logging
import os
import typing
from typing import Any

import immutabledict
from mobly import logger as mobly_logger

from mobly.controllers.wifi.lib import ssh as ssh_lib
from mobly.controllers.wifi.lib import constants
from mobly.controllers.wifi.lib import errors
from mobly.controllers.wifi.lib import iw_utils
from mobly.controllers.wifi.lib import ssid as ssid_lib
from mobly.controllers.wifi.lib import utils
from mobly.controllers.wifi.lib import wifi_configs
from mobly.controllers.wifi.utils import ip_utils

OpenWrtDevice = Any

# The network bridge set up by OpenWrt to bridge wireless networks with the wide
# area network (WAN).
_NETWORK_BRIGE_CONNECTING_WAN = 'br-lan'


_WIFI_START_WAIT_TIME = datetime.timedelta(seconds=30)
# DFS channels require 60s extra start time to check channel availability.
_WIFI_START_WAIT_TIME_DFS = datetime.timedelta(seconds=180)
_WIFI_START_CHECK_INTERVAL = datetime.timedelta(seconds=5)
_WIFI_STOP_WAIT_TIME = datetime.timedelta(seconds=30)


_WIFI_CONFIG_TO_HW_MODE = immutabledict.immutabledict({
    constants.Ieee80211Standards.A: {
        wifi_configs.BandType.BAND_5G: 'a',
    },
    constants.Ieee80211Standards.B: {
        wifi_configs.BandType.BAND_2G: 'b',
    },
    constants.Ieee80211Standards.G: {
        wifi_configs.BandType.BAND_2G: 'g',
    },
    constants.Ieee80211Standards.N: {
        wifi_configs.BandType.BAND_2G: 'g',
        wifi_configs.BandType.BAND_5G: 'a',
    },
    constants.Ieee80211Standards.AC: {
        wifi_configs.BandType.BAND_2G: 'g',
        wifi_configs.BandType.BAND_5G: 'a',
    },
    constants.Ieee80211Standards.AX: {
        wifi_configs.BandType.BAND_2G: 'g',
        wifi_configs.BandType.BAND_5G: 'a',
    },
})

# These default capabilities are enabled to improve the throughput. This is a
# subset of the default settings of UCI.
_DEFAULT_HT_CAPAB = {
    wifi_configs.BandType.BAND_2G: (
        # Enable short guard interval.
        wifi_configs.HostapdHTCapab.SHORT_GI_20,
        wifi_configs.HostapdHTCapab.SHORT_GI_40,
    ),
    wifi_configs.BandType.BAND_5G: (
        # Enable short guard interval.
        wifi_configs.HostapdHTCapab.SHORT_GI_20,
        wifi_configs.HostapdHTCapab.SHORT_GI_40,
        # Enable LDPC codes for error correction. 5GHz only.
        wifi_configs.HostapdHTCapab.LDPC,
    ),
}
_DEFAULT_VHT_CAPAB = {
    wifi_configs.BandType.BAND_2G: (),
    wifi_configs.BandType.BAND_5G: (
        # Enable short guard interval.
        wifi_configs.HostapdVHTCapab.SHORT_GI_80,
        # Enable LDPC codes when receiving and decoding.
        wifi_configs.HostapdVHTCapab.RXLDPC,
    ),
}

# We set fragm_threshold to -1 because the AP might not support setting
# fragmentation threshold when it is not using our custom OpenWrt image. And I
# did not find a way to dynamically check whether setting fragmentation
# threshold is supported or not.
_IS_CUSTOM_OPENWRT_TO_DEFAULT_FRAGM_THRESHOLD = {
    True: 2346,
    False: -1,
}

MOBILITY_DOMAIN_LENGTH = 4
MOBILITY_DOMAIN_HOSTAPD_KEY = 'mobility_domain'
NAS_IDENTIFIER_HOSTAPD_KEY = 'nas_identifier'
FT_PSK_GENERATE_LOCAL_HOSTAPD_KEY = 'ft_psk_generate_local'


def get_pure_mode_hostapd_options(
    htmode: wifi_configs.Mode,
) -> tuple[str, str] | None:
  """Returns the hostapd options for pure mode APs."""
  match htmode:
    case (
        wifi_configs.Mode.EHT20
        | wifi_configs.Mode.EHT40
        | wifi_configs.Mode.EHT80
        | wifi_configs.Mode.EHT160
        | wifi_configs.Mode.EHT80_80
        | wifi_configs.Mode.EHT320
    ):
      return 'require_eht', '1'
    case (
        wifi_configs.Mode.HE20
        | wifi_configs.Mode.HE40
        | wifi_configs.Mode.HE80
        | wifi_configs.Mode.HE80_80
        | wifi_configs.Mode.HE160
    ):
      return 'require_he', '1'
    case (
        wifi_configs.Mode.VHT20
        | wifi_configs.Mode.VHT40
        | wifi_configs.Mode.VHT80
        | wifi_configs.Mode.VHT80_80
        | wifi_configs.Mode.VHT160
    ):
      return 'require_vht', '1'
    case (
        wifi_configs.Mode.HT20
        | wifi_configs.Mode.HT40
        | wifi_configs.Mode.HT40_MINUS
        | wifi_configs.Mode.HT40_PLUS
    ):
      return 'require_ht', '1'
    case _:
      return None


def _get_default_ht_capab(
    wifi_config: wifi_configs.WiFiConfig,
) -> Sequence[str]:
  """Gets default `ht_capab` configuration."""
  return _DEFAULT_HT_CAPAB[wifi_config.band_type]


def _get_default_vht_capab(
    wifi_config: wifi_configs.WiFiConfig,
) -> Sequence[str]:
  """Gets default `vht_capab` configuration."""
  return _DEFAULT_VHT_CAPAB[wifi_config.band_type]


def _get_default_he_capab(
    wifi_config: wifi_configs.WiFiConfig,
) -> Sequence[str]:
  """Gets default `he_capab` configuration."""
  del wifi_config  # Unused.
  return []


def _get_default_capabilities(
    wifi_config: wifi_configs.WiFiConfig,
    standard: wifi_configs.Ieee80211Standards,
) -> Sequence[str]:
  """Gets default capabilities based on standard."""
  if standard == wifi_configs.Ieee80211Standards.AC:
    return _get_default_vht_capab(wifi_config)
  elif standard == wifi_configs.Ieee80211Standards.AX:
    return _get_default_he_capab(wifi_config)
  return []


def _get_center_channel_with_width_80mhz(
    channel_20mhz: int, band: wifi_configs.BandType
) -> int:
  """Gets the center channel of a segment of width 80MHz."""
  if band == wifi_configs.BandType.BAND_6G:
    return 7 + 16 * ((channel_20mhz - 1) // 16)

  match channel_20mhz:
    case 36 | 40 | 44 | 48:
      return 42
    case 52 | 56 | 60 | 64:
      return 58
    case 100 | 104 | 108 | 112:
      return 106
    case 116 | 120 | 124 | 128:
      return 122
    case 132 | 136 | 140 | 144:
      return 138
    case 149 | 153 | 157 | 161:
      return 155
    case _:
      raise errors.ConfigError(
          'Got unsupported 20MHz channel when using channel width 80MHz:'
          f' {channel_20mhz}'
      )


def _get_center_channel_with_width_160mhz(
    channel_20mhz: int, band: wifi_configs.BandType
) -> int:
  """Gets the center channel of a segment of width 160MHz."""
  if band == wifi_configs.BandType.BAND_6G:
    return 15 + 32 * ((channel_20mhz - 1) // 32)

  match channel_20mhz:
    case 36 | 40 | 44 | 48 | 52 | 56 | 60 | 64:
      return 50
    case 100 | 104 | 108 | 112 | 116 | 120 | 124 | 128:
      return 114
    case _:
      raise errors.ConfigError(
          'Got unsupported 20MHz channel when using channel width 160MHz:'
          f' {channel_20mhz}'
      )


@dataclasses.dataclass(frozen=True)
class HostapdNeighbor:
  """Representation of a Neighbor AP for BSS Transition Management.

  Attributes:
    bssid: The BSSID of the neighbor AP.
    op_class: The Operating Class of the neighbor AP.
    channel: The channel number of the neighbor AP.
    phy_type: The PHY type (dot11PhyType) of the neighbor AP.
    bssid_info: The BSSID Information field (32-bit int, default 0x00000003).
  """

  bssid: str
  op_class: int
  channel: int
  phy_type: int
  bssid_info: int = 0x00000003

  @classmethod
  def from_wifi_info(
      cls,
      wifi_info: wifi_configs.WifiInfo,
      bssid_info: int = 0x00000003,
  ) -> 'HostapdNeighbor':
    """Creates a HostapdNeighbor from a single-link WifiInfo."""
    if len(wifi_info.links) != 1:
      raise errors.ConfigError(
          f'Cannot create HostapdNeighbor: WifiInfo {wifi_info.ssid} has'
          f' {len(wifi_info.links)} links.'
      )
    link = wifi_info.links[0]
    return cls.from_wifi_link_info(link, bssid_info=bssid_info)

  @classmethod
  def from_wifi_info_links(
      cls,
      wifi_info: wifi_configs.WifiInfo,
      bssid_info: int = 0x00000003,
  ) -> list['HostapdNeighbor']:
    """Creates a list of HostapdNeighbor objects for all links in WifiInfo."""
    return [
        cls.from_wifi_link_info(link, bssid_info=bssid_info)
        for link in wifi_info.links
    ]

  @classmethod
  def from_wifi_link_info(
      cls,
      link: wifi_configs.WifiLinkInfo,
      bssid_info: int = 0x00000003,
  ) -> 'HostapdNeighbor':
    """Creates a HostapdNeighbor from a WifiLinkInfo."""
    if link.channel is None:
      raise errors.ConfigError(
          f'Cannot create HostapdNeighbor: link {link.bssid} has no channel.'
      )
    if link.op_class is None:
      raise errors.ConfigError(
          f'Cannot create HostapdNeighbor: link {link.bssid} has no op_class.'
      )
    return cls(
        bssid=link.bssid,
        op_class=link.op_class,
        channel=link.channel,
        phy_type=int(link.phy_type),
        bssid_info=bssid_info,
    )

  def to_cli_string(self) -> str:
    """Formats the neighbor as hostapd_cli parameter string."""
    return f'{self.bssid},0x{self.bssid_info:08x},{self.op_class},{self.channel},{int(self.phy_type)}'


Neighbor = HostapdNeighbor


@dataclasses.dataclass(frozen=True)
class HostapdBssTmReqParams:
  """Parameters for a BSS Transition Management Request.

  Attributes:
    client_mac_address: The MAC address of the client station.
    neighbors: Optional. A sequence of HostapdNeighbor objects for preferred
      neighbor APs.
    disassoc_imminent: If True, the AP will indicate imminent disassociation.
    disassoc_timer: Time before the AP disassociates the STA. Required and must
      be > 0 when disassoc_imminent is True.
    reassoc_delay: Delay before STA is permitted to reassociate. Assumes MBO is
      enabled on the AP if this is used, since this is an MBO attribute. Only
      valid if disassoc_imminent is True.
    bss_term_duration: Duration for which the current BSS will be unavailable.
      TSF is assumed to be 0 (immediate).
  """

  client_mac_address: str
  neighbors: Sequence[HostapdNeighbor] = dataclasses.field(default_factory=list)
  disassoc_imminent: bool = False
  disassoc_timer: datetime.timedelta | None = None
  reassoc_delay: datetime.timedelta | None = None
  bss_term_duration: datetime.timedelta | None = None

  def __post_init__(self):
    if self.disassoc_imminent and (
        self.disassoc_timer is None
        or self.disassoc_timer <= datetime.timedelta(0)
    ):
      raise errors.ConfigError(
          'disassoc_timer must be set and greater than 0 when'
          f' disassoc_imminent is True (got {self.disassoc_timer}).'
      )

  @property
  def disassoc_timer_100ms(self) -> int | None:
    """Returns disassoc_timer in units of 100ms."""
    if self.disassoc_timer is None:
      return None
    return int(self.disassoc_timer.total_seconds() * 10)

  @property
  def reassoc_delay_sec(self) -> int | None:
    """Returns reassoc_delay in seconds."""
    if self.reassoc_delay is None:
      return None
    return int(self.reassoc_delay.total_seconds())

  @property
  def bss_term_minutes(self) -> int | None:
    """Returns bss_term_duration in minutes."""
    if self.bss_term_duration is None:
      return None
    return int(self.bss_term_duration.total_seconds() / 60)


class HostapdConfig:
  """The hostapd configurations.

  When we need to start a WiFi network, we need to transform the user specified
  configurations to a hostapd configuration file. This class representes the
  hostapd configuration file.

  Attributes:
    channel: The WiFi channel.
    ssid: The WiFi SSID.
    password: The WiFi password.
    interface: The name of the network interface that the WiFi network is using.
    bridge: The name of the bridge interface.
    config_content: The content of the hostapd configuration file.
  """

  channel: int
  ssid: str
  password: str | None
  interface: str
  bridge: str | None = None

  _raw: dict[str, str | Iterable[str]]

  def __init__(
      self,
      interface: str,
      dfs_channels: set[int],
      is_custom_openwrt: bool,
      ctrl_socket_path: str,
      bridge: str | None = None,
  ):
    self._dfs_channels = dfs_channels
    self._raw = {}
    self.update('logger_syslog', '-1')
    self.update('logger_syslog_level', '0')
    self.update('rts_threshold', '-1')
    self.update('driver', 'nl80211')
    self.update(
        'fragm_threshold',
        str(_IS_CUSTOM_OPENWRT_TO_DEFAULT_FRAGM_THRESHOLD[is_custom_openwrt]),
    )
    self.set_interface(interface)
    # Set control interface for hostapd_cli
    self.update('ctrl_interface', ctrl_socket_path)
    # Common group for hostapd_cli, 0 means root/admin.
    self.update('ctrl_interface_group', '0')
    if bridge is not None:
      self.set_bridge(bridge)

  def update(self, key: str, value: str):
    self._raw[key] = value

  def get(self, key: str) -> str | None:
    """Gets the string value for the given key.

    Use method `get_list()` for a multi-value key. This applies
    to custom hostapd configuration options, which can have multiple values.

    Args:
      key: The key of the configuration.

    Returns:
      The string value for the given key. None if the key is not found.

    Raises:
      ConfigError: If the value is not a string.
    """
    value = self._raw.get(key)
    if not value:
      return None
    if isinstance(value, str):
      return value
    raise errors.ConfigError(
        f'Got key "{key}" that corresponds to multiple values. This method'
        ' only supports single-value keys. Use get_list for multi-value'
        ' keys instead.'
    )

  def get_list(self, key: str) -> Iterable[str] | None:
    """Gets the list of values for the given key.

    Use method `get()` for a single-value key. This applies
    to most hostapd configuration options that expect only a single value.

    Args:
      key: The key of the configuration.

    Returns:
      The list of values for the given key. None if the key is not found.

    Raises:
      ConfigError: If the value is a string.
    """
    value = self._raw.get(key)
    if value is None:
      return None
    if isinstance(value, str):
      raise errors.ConfigError(
          f'Got a string value "{value}" for key "{key}". Expected a list. Use'
          ' method `get()` instead.'
      )
    else:
      return value

  def _get_default_mobility_domain(
      self, wifi_config: wifi_configs.WiFiConfig
  ) -> str | None:
    """Gets the default mobility domain for the given WiFi config."""
    if not wifi_config.ssid:
      raise errors.ConfigError('Got empty SSID for mobility domain generation.')

    if MOBILITY_DOMAIN_HOSTAPD_KEY in wifi_config.custom_hostapd_configs:
      return None

    return hashlib.md5(wifi_config.ssid.encode()).hexdigest()[
        :MOBILITY_DOMAIN_LENGTH
    ]

  def _get_default_nas_identifier(
      self, wifi_config: wifi_configs.WiFiConfig
  ) -> str | None:
    """Gets the default NAS identifier for the given WiFi config."""
    if NAS_IDENTIFIER_HOSTAPD_KEY in wifi_config.custom_hostapd_configs:
      return None

    if not wifi_config.bssid:
      raise errors.ConfigError('Got empty BSSID for NAS identifier generation.')

    return wifi_config.bssid.replace(':', '')

  def _prepare_key_mgmt_for_fast_transition(
      self, wifi_config: wifi_configs.WiFiConfig
  ) -> None:
    """Prepares the key management configuration for fast transition."""
    if not wifi_config.encryption_config:
      return
    ft_key_mgmt = wifi_config.encryption_config.get_ft_key_mgmt()
    if not ft_key_mgmt:
      return
    key_mgmt_str = self.get('wpa_key_mgmt') or ''
    current_key_mgmt = key_mgmt_str.split()
    for ft_km in sorted(ft_key_mgmt):
      ft_km_str = str(ft_km)
      if ft_km_str not in current_key_mgmt:
        current_key_mgmt.append(ft_km_str)
      self.update('wpa_key_mgmt', ' '.join(current_key_mgmt))

  def _prepare_fast_transition(
      self, wifi_config: wifi_configs.WiFiConfig
  ) -> None:
    """Prepares the fast transition configuration.

    If the AP is configured to support fast transition, we need to set the
    mobility domain, NAS identifier and enable local PSK generation.

    Args:
      wifi_config: The WiFi config.
    """
    if not wifi_config.ft:
      return
    mobility_domain = self._get_default_mobility_domain(wifi_config)
    if mobility_domain is not None:
      self.update(MOBILITY_DOMAIN_HOSTAPD_KEY, mobility_domain)

    nas_identifier = self._get_default_nas_identifier(wifi_config)
    if nas_identifier is not None:
      self.update(NAS_IDENTIFIER_HOSTAPD_KEY, nas_identifier)

    if (
        FT_PSK_GENERATE_LOCAL_HOSTAPD_KEY
        not in wifi_config.custom_hostapd_configs
    ):
      self.update(FT_PSK_GENERATE_LOCAL_HOSTAPD_KEY, '1')

    self._prepare_key_mgmt_for_fast_transition(wifi_config)

  def update_from_wifi_config(self, wifi_config: wifi_configs.WiFiConfig):
    """Updates this object according to the `WiFiConfig` object."""
    self.set_ssid(wifi_config.ssid)  # pyrefly: ignore[bad-argument-type]
    if wifi_config.bssid:
      self.update('bssid', wifi_config.bssid)

    # TODO: Better API is returning a dict / hostapd_conf and merge
    # it.
    self._update_encryption_configs(wifi_config)
    self.set_channel(wifi_config.channel)
    self._update_dfs_channel_config(wifi_config)

    self.update('ieee80211d', '1')  # Required when country_code is set.
    self.update('country_code', wifi_config.country_code)
    self.update('hw_mode', self._get_hw_mode(wifi_config))
    self._update_according_to_wifi_standard(wifi_config)

    if not wifi_config.access_wan_through_nat:
      self.update('bridge', _NETWORK_BRIGE_CONNECTING_WAN)

    if wifi_config.pmf is not None:
      self.update('ieee80211w', str(wifi_config.pmf.value))

    if wifi_config.hidden:
      self.update('ignore_broadcast_ssid', '1')

    for key, value in wifi_config.custom_hostapd_configs.items():
      if isinstance(value, str):
        self.update(key, value)
      else:
        self._raw[key] = [str(v) for v in value]

    if wifi_config.pure_mode:
      pure_mode_options = get_pure_mode_hostapd_options(wifi_config.ht_mode)  # pyrefly: ignore[bad-argument-type]
      if pure_mode_options is not None:
        key, value = pure_mode_options
        self.update(key, value)

    if wifi_config.ft:
      self._prepare_fast_transition(wifi_config)

  def set_ssid(self, value: str):
    """Sets the SSID for the hostapd configuration.

    SSIDs are stored in the `ssid2` field of the hostapd configuration.
    If the SSID is already in a printf-escaped format (e.g., starting with
    'P"' and ending with '"'), it's used directly. Otherwise, the SSID is
    wrapped in double quotes. The printf-escaped format is mentioned in
    the hostapd document:
    https://git.w1.fi/cgit/hostap/plain/hostapd/hostapd.conf

    printf_encode used for printf_escaped format in hostapd can be found at:
    https://w1.fi/cgit/hostap/tree/src/utils/common.c?h=hostap_2_10#n477

    Args:
      value: The SSID string.
    """
    self.ssid = value
    # SSIDs in printf-escape format are already wrapped in quotes, so they
    # don't need additional quoting.
    if ssid_lib.is_printf_encoded_ssid(value):
      self.update('ssid2', value)
    elif ssid_lib.needs_printf_encoding(value):
      self.update('ssid2', ssid_lib.encode_printf_ssid(value))
    else:
      self.update('ssid2', f'"{value}"')

  def set_password(self, value: str | None):
    self.password = value

  def set_interface(self, value: str):
    self.interface = value
    self.update('interface', value)

  def set_channel(self, value: int):
    self.channel = value
    self.update('channel', str(value))

  def set_bridge(self, value: str):
    self.bridge = value
    self.update('bridge', value)

  def is_using_a_dfs_channel(self) -> bool:
    """Returns true if the channel is a DFS channel."""
    return self.channel in self._dfs_channels

  @property
  def config_content(self) -> str:
    lines = []
    for key, value in self._raw.items():
      if isinstance(value, str):
        lines.append(f'{key}={value}')
      else:
        for v in value:
          lines.append(f'{key}={v}')
    return '\n'.join(lines)

  def write_to_file(self, filepath: str, content: str) -> None:
    """Writes the configurations to the given host filepath."""
    with open(filepath, 'w') as f:
      f.write(content)

  def _get_hw_mode(self, wifi_config: wifi_configs.WiFiConfig) -> str:
    """Get the hwmode."""
    band_type_to_hw_mode = _WIFI_CONFIG_TO_HW_MODE.get(wifi_config.standard)
    if band_type_to_hw_mode is None:
      raise errors.ConfigError(
          f'Got unknown WiFi standard: {wifi_config.standard}'
      )

    hw_mode = band_type_to_hw_mode.get(wifi_config.band_type)
    if hw_mode is None:
      raise errors.ConfigError(
          f'Got unsupported band type "{wifi_config.band_type}" under WiFi'
          f' standard "{wifi_config.standard}"'
      )
    return hw_mode

  def _update_dfs_channel_config(self, wifi_config: wifi_configs.WiFiConfig):
    if not self.is_using_a_dfs_channel():
      return
    if wifi_config.country_code is None:
      raise errors.ConfigError(
          'Country code must be set when using a DFS channel.'
      )

    # This is required for ieee80211h
    self.update('ieee80211d', '1')
    # This enables radar detection and DFS support.
    self.update('ieee80211h', '1')

  def _update_according_to_wifi_standard(
      self, wifi_config: wifi_configs.WiFiConfig
  ):
    self._update_11n_configs(wifi_config)
    self._update_11ac_configs(wifi_config)
    self._update_11ax_configs(wifi_config)

  def _update_11n_configs(self, wifi_config: wifi_configs.WiFiConfig):
    """Updates 802.11N related configurations."""
    if wifi_config.standard not in constants.STANDARDS_SUPPORT_HT_CAPAB:
      return
    self.update('ieee80211n', '1')
    self.update('wmm_enabled', '1')  # Required when HT capabilities are used.
    if ht_capab := self._get_ht_capab(wifi_config):
      self.update('ht_capab', ht_capab)

  def _get_ht_capab(self, wifi_config: wifi_configs.WiFiConfig) -> str:
    """Gets the value for `ht_capab` in hostapd config file."""
    ht_capab = wifi_config.ht_capab
    if ht_capab is None:
      ht_capab = list(_get_default_ht_capab(wifi_config))
    if wifi_config.width != wifi_configs.ChannelWidth.WIDTH_20:
      capab = wifi_configs.CHANNEL_HOSTAPD_HT40_MODE.get(wifi_config.channel)
      if capab is not None and capab not in ht_capab:
        ht_capab = ht_capab + [capab]  # pyrefly: ignore[unsupported-operation]
    return ''.join(ht_capab)

  def _update_oper_configs(
      self,
      wifi_config: wifi_configs.WiFiConfig,
      prefix: str,
      standard: wifi_configs.Ieee80211Standards,
      capab: Sequence[str] | None,
  ):
    """Updates operating center frequency and capability configurations."""
    if wifi_config.band_type != wifi_configs.BandType.BAND_2G:
      center_channel_seg0 = None
      if wifi_config.width in (
          wifi_configs.ChannelWidth.WIDTH_80,
          wifi_configs.ChannelWidth.WIDTH_80_80,
      ):
        center_channel_seg0 = _get_center_channel_with_width_80mhz(
            wifi_config.channel, wifi_config.band_type
        )
      elif wifi_config.width == wifi_configs.ChannelWidth.WIDTH_160:
        center_channel_seg0 = _get_center_channel_with_width_160mhz(
            wifi_config.channel, wifi_config.band_type
        )

      center_channel_seg1 = None
      if wifi_config.width == wifi_configs.ChannelWidth.WIDTH_80_80:
        center_channel_seg1 = wifi_config.custom_hostapd_configs.get(
            f'{prefix}_oper_centr_freq_seg1_idx', None
        )

      if center_channel_seg0 is not None:
        self.update(
            f'{prefix}_oper_centr_freq_seg0_idx', str(center_channel_seg0)
        )

      if center_channel_seg1 is not None:
        self.update(
            f'{prefix}_oper_centr_freq_seg1_idx', str(center_channel_seg1)
        )
      elif wifi_config.width == wifi_configs.ChannelWidth.WIDTH_80_80:
        raise errors.ConfigError(
            f'For 80+80MHz configuration, {prefix}_oper_centr_freq_seg1_idx'
            ' should be provided in custom_hostapd_configs.',
        )

    # Capabilities
    if capab is None:
      capab = _get_default_capabilities(wifi_config, standard)
    if capab:
      self.update(f'{prefix}_capab', ''.join(capab))

  def _update_11ac_configs(self, wifi_config: wifi_configs.WiFiConfig):
    """Updates 802.11AC related configurations."""
    if wifi_config.standard not in constants.STANDARDS_SUPPORT_VHT_CAPAB:
      return
    self.update('ieee80211ac', '1')

    width = typing.cast(wifi_configs.ChannelWidth, wifi_config.width)
    self.update('vht_oper_chwidth', width.to_hostapd_enum())

    self._update_oper_configs(
        wifi_config,
        'vht',
        wifi_configs.Ieee80211Standards.AC,
        wifi_config.vht_capab,
    )

  def _update_11ax_configs(self, wifi_config: wifi_configs.WiFiConfig):
    """Updates 802.11AX related configurations."""
    if wifi_config.standard not in constants.STANDARDS_SUPPORT_HE_CAPAB:
      return
    self.update('ieee80211ax', '1')

    width = typing.cast(wifi_configs.ChannelWidth, wifi_config.width)
    self.update('he_oper_chwidth', width.to_hostapd_enum())

    self._update_oper_configs(
        wifi_config,
        'he',
        wifi_configs.Ieee80211Standards.AX,
        wifi_config.he_capab,
    )

  def _update_encryption_configs(self, wifi_config: wifi_configs.WiFiConfig):
    """Updates the encryption configuration."""
    # Feed this to the encryption config checking.
    if wifi_config.pmf is not None:
      self.update('ieee80211w', str(wifi_config.pmf.value))
    wifi_config.encryption_config.update_hostapd_conf(hostapd_conf=self)


class HostapdCli:
  """Wrapper for hostapd_cli command execution."""

  def __init__(
      self,
      interface: str,
      ctrl_path: str,
      ssh: Any,
      log: logging.Logger | mobly_logger.PrefixLoggerAdapter | None = None,
  ):
    self._interface = interface
    self._ctrl_path = ctrl_path
    self._ssh = ssh
    self._log = log or logging.getLogger(__name__)

  def _run_command(self, command_args: Sequence[str]) -> str:
    full_command_str = constants.Commands.HOSTAPD_CLI.format(
        ctrl_path=self._ctrl_path,
        interface=self._interface,
        command_args=' '.join(command_args),
    )
    self._log.debug('Executing hostapd_cli command: %s', full_command_str)
    output = self._ssh.execute_command(
        command=full_command_str,
        timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
    )
    return output.strip()

  def set_property(self, property_name: str, value: str) -> None:
    """Sets the property of the hostapd daemon.

    This function executes the `hostapd_cli set` command to modify a specific
    property of the running hostapd instance.

    Args:
      property_name: The name of the property to set. (e.g.,
        'mbo_assoc_disallow')
      value: The value to assign to the property.

    Raises:
      errors.HostapdSetPropertyError: If setting the property fails.
    """
    command_args = ['set', property_name, value]
    try:
      output = self._run_command(command_args)
    except (ssh_lib.ExecuteCommandError, errors.BaseError) as e:
      raise errors.HostapdSetPropertyError(
          f'Failed to set hostapd property {property_name} to {value}.'
      ) from e
    if output != 'OK':
      raise errors.HostapdSetPropertyError(
          f'Failed to set hostapd property {property_name} to {value}.'
          f' Output: {output}'
      )

  def channel_switch(
      self,
      *,
      target_frequency: int,
      beacon_count: int,
      optional_args: Sequence[str] | None = None,
  ) -> str:
    """Performs a chan_switch from the current channel to the target frequency.

    Args:
      target_frequency: The target frequency to switch to.
      beacon_count: The number of beacons to send before switching channels.
      optional_args: Optional arguments to pass to the hostapd_cli command.

    Returns:
      The stdout from the hostapd_cli command.
    Raises:
      errors.HostapdChannelSwitchError: If the channel switch fails.
    """
    command_args = [
        'chan_switch',
        str(beacon_count),
        str(target_frequency),
    ]
    if optional_args:
      command_args.extend(optional_args)

    return self._run_command(command_args)

  def send_bss_tm_request(self, params: HostapdBssTmReqParams) -> str:
    """Sends a BSS Transition Management Request to a client.

    Args:
      params: The parameters for the BSS TM Request.

    Returns:
      The stdout from the hostapd_cli command.
    """
    command_args = ['BSS_TM_REQ', params.client_mac_address]

    for neighbor in params.neighbors:
      command_args.append(f'neighbor={neighbor.to_cli_string()}')
    if params.neighbors:
      command_args.append('pref=1')

    if params.disassoc_imminent:
      command_args.append('disassoc_imminent=1')
      if params.disassoc_timer_100ms is not None:
        command_args.append(f'disassoc_timer={params.disassoc_timer_100ms}')
      if params.reassoc_delay_sec is not None:
        command_args.append(f'mbo=3:{params.reassoc_delay_sec}:0')
    elif (
        params.disassoc_timer_100ms is not None
        or params.reassoc_delay_sec is not None
    ):
      self._log.warning(
          'disassoc_timer or reassoc_delay specified without'
          ' disassoc_imminent=True. These parameters might be ignored by'
          ' hostapd.'
      )

    if params.bss_term_minutes is not None and params.bss_term_minutes > 0:
      command_args.append(f'bss_term=0,{params.bss_term_minutes}')

    return self._run_command(command_args)

  def deauthenticate(
      self,
      mac_address: str = constants.BROADCAST_MAC_ADDRESS,
      reason_code: int = constants.DEFAULT_DEAUTH_REASON_CODE,
  ) -> str:
    """Deauthenticates a client station or all stations (broadcast).

    Args:
      mac_address: The MAC address of the station to deauthenticate. Defaults to
        'ff:ff:ff:ff:ff:ff' (broadcast to all connected stations).
      reason_code: The IEEE 802.11 reason code. Defaults to 3 (DEAUTH_LEAVING).

    Returns:
      The stdout from the hostapd_cli command.
    """
    command_args = ['deauthenticate', mac_address, f'reason={reason_code}']
    return self._run_command(command_args)

  def stop(self) -> bool:
    """Stops the interface for which the hostapd instance is running.

    Returns:
      True if the interface was stopped successfully, False otherwise.
    """
    output = self._run_command(['disable'])
    return output == 'OK'


class HostapdManager:
  """The class for managing one hostapd instance on the AP device."""

  def __init__(
      self,
      device: 'OpenWrtDevice',
      wifi_id: int,
      phy: iw_utils.Phy,
      interface: str,
      wifi_config: wifi_configs.WiFiConfig,
      bridge: str | None = None,
      base_logger: (
          logging.Logger | mobly_logger.PrefixLoggerAdapter | None
      ) = None,
  ):
    """Constructor.

    Args:
      device: The AP device controller object.
      wifi_id: The unique ID of the WiFi network to start.
      phy: The wireless hardware device that the WiFi network is using.
      interface: The name of the network interface that the WiFi network is
        using.
      wifi_config: The WiFi configurations.
      bridge: The name of the bridge interface.
      base_logger: The base logger. Based on that logger, this class will prefix
        each log entry with string "[HostapdManager]".
    """
    self._device = device
    self._wifi_id = wifi_id
    self._wifi_config = wifi_config
    self._phy = phy
    self._interface = interface
    self._bridge = bridge
    self._bssid = None

    self._hostapd_config = None
    self._hostapd_cli = None
    self._wifi_info = None
    self._remote_process = None
    self._identifier = f'wifi{self._wifi_id},{self._interface}'

    base_logger = base_logger or device.log
    self._log = mobly_logger.PrefixLoggerAdapter(
        base_logger,
        {
            mobly_logger.PrefixLoggerAdapter.EXTRA_KEY_LOG_PREFIX: (
                f'[HostapdManager|wifi{self._wifi_id}]'
            )
        },
    )
    self._local_work_dir = self._device.log_path
    self._remote_work_dir = self._device.remote_work_dir

    if self._wifi_config.ap_type != wifi_configs.ApType.AP:
      raise errors.ConfigError(
          f'Unsupported AP type: {self._wifi_config.ap_type}'
      )

  def start(self) -> wifi_configs.WifiInfo:
    """Starts this hostapd manager instance."""
    self._log.debug('Starting a remote hostapd instance.')
    try:
      return self._start()
    except (errors.BaseError, ssh_lib.SSHRemoteError):
      self._log.error('Stopping due to start failure.')
      with contextlib.suppress(errors.BaseError, ssh_lib.SSHRemoteError):
        self.stop()
      raise

  def _start(self) -> wifi_configs.WifiInfo:
    """Starts a hostapd process using given configs on the AP device."""
    dfs_channels = iw_utils.get_all_dfs_channels(self._phy)
    self._log.debug(
        'All DFS channels on phy %s: %s', self._phy.name, sorted(dfs_channels)
    )

    self._hostapd_config = HostapdConfig(
        interface=self._interface,
        dfs_channels=dfs_channels,
        is_custom_openwrt=self._device.device_info.is_cros_image,
        ctrl_socket_path=self._remote_work_dir,
        bridge=self._bridge,
    )
    self._hostapd_config.update_from_wifi_config(self._wifi_config)

    self._bssid = None
    conf_remote_path = self._generate_remote_config_file()
    self._start_hostpad_process(conf_remote_path)

    self._hostapd_cli = HostapdCli(
        interface=self._interface,
        ctrl_path=self._get_ctrl_socket_path(),
        ssh=self._device.ssh,
        log=self._log,
    )

    self._bssid = typing.cast(str, self._bssid)
    link = wifi_configs.WifiLinkInfo(
        bssid=self._bssid,
        channel=self._hostapd_config.channel,
        frequency=wifi_configs.get_frequency(
            self._hostapd_config.channel, self._wifi_config.band_type
        ),
        width=self._wifi_config.width,
        ht_mode=self._wifi_config.ht_mode,
        standard=self._wifi_config.standard,
        band_type=self._wifi_config.band_type,
    )
    self._wifi_info = wifi_configs.WifiInfo(
        id=self._wifi_id,
        ssid=(
            ssid_lib.decode_printf_ssid(self._hostapd_config.ssid)
            or self._hostapd_config.ssid
        ),
        password=self._hostapd_config.password,
        interface=self._interface,
        phy_name=self._phy.name,
        links=(link,),
        bridge=self._bridge,
        hidden=self._wifi_config.hidden,
        encryption_config=self._wifi_config.encryption_config,
        ap_type=self._wifi_config.ap_type,
    )

    return self._wifi_info

  def _generate_remote_config_file(self) -> str:
    """Generates the hostapd config file on the AP device."""
    filename = self._get_conf_filename()
    local_path = self._get_local_path(filename)
    remote_path = self._get_remote_path(filename)

    self._hostapd_config = typing.cast(HostapdConfig, self._hostapd_config)
    config_content = self._hostapd_config.config_content
    self._hostapd_config.write_to_file(local_path, config_content)
    self._device.push_file(local_path, remote_path)

    # Rename the local file so it can be directly opened in a web browser.
    os.rename(local_path, f'{local_path}.txt')
    return remote_path

  def _start_hostpad_process(
      self,
      conf_remote_path: str,
  ):
    """Starts the hostapd process and waits until the WiFi is ready."""
    log_file_path = self._get_local_path(self._get_log_filename())
    command = constants.Commands.HOSTAPD_START.format(
        conf_path=conf_remote_path,
    )
    proc = self._device.ssh.start_remote_process(
        command, get_pty=True, output_file_path=log_file_path
    )
    self._remote_process = proc

    self._hostapd_config = typing.cast(HostapdConfig, self._hostapd_config)
    wait_timeout = (
        _WIFI_START_WAIT_TIME_DFS
        if self._hostapd_config.is_using_a_dfs_channel()
        else _WIFI_START_WAIT_TIME
    )
    if not utils.wait_for_predicate(
        predicate=self._is_wifi_ready,
        timeout=wait_timeout,
        interval=_WIFI_START_CHECK_INTERVAL,
    ):
      raise errors.HostapdStartError(
          'Failed to start hostapd. Please check the hostapd log'
          f' {self._get_log_filename()} and config {self._get_conf_filename()}.'
      )

    self._log.debug('Started remote hostapd process.')

  def _is_wifi_ready(self):
    """Returns whether the WiFi is ready.

    If WiFi is ready, `self._bssid` will be set to the BSSID of the WiFi
    network.
    """
    if self._remote_process is None:
      raise errors.HostapdStartError(
          'Hostapd process is not set. Please check whether hostapd object'
          ' has not been started or is already stopped.'
      )
    if self._remote_process.poll() is not None:
      raise errors.HostapdStartError(
          'Hostapd process has exited unexpectedly on the AP device. Please'
          f' check the hostapd log file {self._get_log_filename()} and conf'
          f' file {self._get_conf_filename()}'
      )

    cmd = constants.Commands.IP_LINK_SHOW.format(interface=self._interface)
    stdout = self._device.ssh.execute_command(
        command=cmd,
        timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
        ignore_error=True,
    )
    if 'state UP' not in stdout:
      return False

    intfs_all = ip_utils.parse_all_ip_addr(stdout)
    if len(intfs_all) != 1:
      raise errors.HostapdStartError(
          f'Got unexpected number of interfaces in "{cmd}" output: {intfs_all}.'
      )
    intf = intfs_all[0]
    self._bssid = intf.mac_address
    self._log.debug('WiFi AP is ready. Interface info: %s', intf)
    return True

  def __del__(self):
    self.stop()

  def stop(self):
    """Stops the remote hostapd process."""
    if self._remote_process is None:
      return

    self._log.debug(
        'Stopping hostapd process %d.',
        self._remote_process.pid,
    )
    self._bssid = None
    proc = self._remote_process
    self._remote_process = None
    proc.terminate(
        timeout=_WIFI_STOP_WAIT_TIME.total_seconds(), assert_process_exit=True
    )

  def _get_ctrl_socket_path(self) -> str:
    """Gets the path of the control socket.

    Raises:
      errors.ConfigError: If the control socket path is not set.

    Returns:
      The path of the control socket.
    """
    self._hostapd_config = typing.cast(HostapdConfig, self._hostapd_config)
    ctrl_interface = self._hostapd_config.get('ctrl_interface')
    if ctrl_interface is None:
      raise errors.ConfigError('ctrl_interface is not set.')
    return ctrl_interface

  def _get_remote_path(self, filename: str) -> str:
    return os.path.join(self._remote_work_dir, filename)

  def _get_local_path(self, filename: str) -> str:
    return os.path.join(self._local_work_dir, filename)

  def _get_conf_filename(self) -> str:
    return f'{self._identifier},hostapd.conf'

  def _get_log_filename(self) -> str:
    return f'{self._identifier},hostapd.log'

  def send_bss_tm_request(self, params: HostapdBssTmReqParams) -> str:
    """Sends a BSS Transition Management Request to a client.

    Args:
      params: The parameters for the BSS TM Request.

    Returns:
      The stdout from the hostapd_cli command.
    """
    if self._remote_process is None or self._remote_process.poll() is not None:
      raise errors.BaseError(
          'Hostapd process is not running. Cannot execute hostapd_cli command.'
      )
    if self._hostapd_cli is None:
      raise errors.BaseError('HostapdCli is not initialized.')
    return self._hostapd_cli.send_bss_tm_request(params)

  def set_hostapd_property(self, property_name: str, value: str) -> None:
    """Sets the property of the hostapd daemon.

    This function executes the `hostapd_cli set` command to modify a specific
    property of the running hostapd instance.

    Args:
      property_name: The name of the property to set. (e.g.,
        'mbo_assoc_disallow')
      value: The value to assign to the property.

    Raises:
      errors.HostapdSetPropertyError: If setting the property fails.
    """
    if self._remote_process is None or self._remote_process.poll() is not None:
      raise errors.BaseError(
          'Hostapd process is not running. Cannot execute hostapd_cli command.'
      )
    if self._hostapd_cli is None:
      raise errors.BaseError('HostapdCli is not initialized.')
    self._hostapd_cli.set_property(property_name, value)

  def channel_switch(
      self,
      target_channel: int,
      beacon_count: int,
      optional_args: Sequence[str] | None = None,
  ) -> None:
    """Performs a channel switch from the current channel to the target channel.

    Args:
      target_channel: The target channel to switch to.
      beacon_count: The number of beacons to send before switching channels.
      optional_args: Optional arguments to pass to the hostapd_cli command.

    Raises:
      errors.HostapdChannelSwitchError: If the channel switch fails.
    """
    target_frequency = wifi_configs.get_frequency(
        target_channel, self._wifi_config.band_type
    )
    if target_frequency is None:
      raise errors.HostapdChannelSwitchError(
          f'Target channel {target_channel} is not a valid channel for band'
          f' {self._wifi_config.band_type}.'
      )
    if self._remote_process is None or self._remote_process.poll() is not None:
      raise errors.BaseError(
          'Hostapd process is not running. Cannot execute hostapd_cli command.'
      )
    if self._hostapd_cli is None:
      raise errors.BaseError('HostapdCli is not initialized.')

    try:
      output = self._hostapd_cli.channel_switch(
          target_frequency=target_frequency,
          beacon_count=beacon_count,
          optional_args=optional_args,
      )
    except (ssh_lib.ExecuteCommandError, errors.BaseError) as e:
      raise errors.HostapdChannelSwitchError(
          f'Failed to switch channel to {target_channel}.'
      ) from e
    if output.strip() != 'OK':
      raise errors.HostapdChannelSwitchError(
          f'Failed to switch channel to {target_channel}. Output: {output}'
      )

  def turn_off_radio(self) -> None:
    """Turns off radio transmission via hostapd_cli disable to simulate AP power-off.

    This command stops beacon and frame transmissions on the wireless interface
    immediately without sending deauthentication frames to connected clients
    prior to stopping.

    Raises:
      errors.BaseError: If hostapd process is not running, HostapdCli is not
        initialized, or the disable command failed.
    """
    if self._remote_process is None or self._remote_process.poll() is not None:
      raise errors.BaseError(
          'Hostapd process is not running. Cannot execute hostapd_cli command.'
      )
    if self._hostapd_cli is None:
      raise errors.BaseError('HostapdCli is not initialized.')
    if not self._hostapd_cli.stop():
      raise errors.BaseError(
          f'Failed to turn off radio on interface {self._interface}'
      )

