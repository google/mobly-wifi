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

"""Configuration classes for the AP controller module."""

from collections.abc import Mapping, Sequence
import dataclasses
import enum

import immutabledict
from mobly import utils

from mobly.controllers.wifi.lib import constants
from mobly.controllers.wifi.lib import errors
from mobly.controllers.wifi.lib.encryption import base_encryption_config
from mobly.controllers.wifi.lib.encryption import wpa


# TODO(b/310813723): move Ieee80211Standards from constants to this module.
Ieee80211Standards = constants.Ieee80211Standards


@enum.unique
class ChannelWidth(enum.StrEnum):
  """The supported channel widths."""

  WIDTH_20 = '20MHz'
  WIDTH_40 = '40MHz'
  WIDTH_80 = '80MHz'

  def to_hostapd_enum(self) -> str:
    """Converts the channel width to a hostapd width enum."""
    match self:
      case ChannelWidth.WIDTH_20:
        return '0'
      case ChannelWidth.WIDTH_40:
        return '0'
      case ChannelWidth.WIDTH_80:
        return '1'


# For these channels, they support both HT40+ and HT40- so we cannot auto detect
# HT mode for them.
CHANNELS_HT40_PLUS_AND_MINUS = frozenset([5, 6, 7, 8, 9])

# Channels that only supports HT40+.
CHANNELS_HT40_PLUS = frozenset(
    [1, 2, 3, 4, 36, 44, 52, 60, 100, 108, 116, 124, 132, 140, 149, 157]
)

# Channels that only supports HT40-.
CHANNELS_HT40_MINUS = frozenset(
    [10, 11, 12, 13, 40, 48, 56, 64, 104, 112, 120, 128, 136, 144, 153, 161]
)


@enum.unique
class HostapdHTCapab(enum.StrEnum):
  """HT capabilities that can be set to `ht_capab` field of hostapd config."""

  HT40_PLUS = '[HT40+]'
  HT40_MINUS = '[HT40-]'
  SHORT_GI_20 = '[SHORT-GI-20]'
  SHORT_GI_40 = '[SHORT-GI-40]'
  LDPC = '[LDPC]'


@enum.unique
class HostapdVHTCapab(enum.StrEnum):
  """VHT capabilities that can be set to `vht_capab` field of hostapd config."""

  SHORT_GI_80 = '[SHORT-GI-80]'
  SHORT_GI_160 = '[SHORT-GI-160]'
  RXLDPC = '[RXLDPC]'


# The dict that returns whether a channel supports HT40+ or HT40-.
CHANNEL_HOSTAPD_HT40_MODE = immutabledict.immutabledict({
    **{ch: HostapdHTCapab.HT40_PLUS for ch in CHANNELS_HT40_PLUS},
    **{ch: HostapdHTCapab.HT40_MINUS for ch in CHANNELS_HT40_MINUS},
})


@enum.unique
class BandType(str, enum.Enum):
  """Band types."""

  BAND_2G = '2G'
  BAND_5G = '5G'


@enum.unique
class PMF(enum.IntEnum):
  """The enum for the setting of "Protected Management Frames" (IEEE802.11w)."""

  DISABLED = 0
  OPTIONAL = 1
  REQUIRED = 2


def generate_wifi_ssid(band_type: BandType) -> str:
  """Generates a wifi SSID with a randome substring."""
  random_str = utils.rand_ascii_str(5)
  return f'OpenWRT-{band_type.value}-{random_str}'


def _get_default_width(band_type: BandType) -> ChannelWidth:
  """Gets the default width with a given band type."""
  match band_type:
    case BandType.BAND_2G:
      return ChannelWidth.WIDTH_20
    case BandType.BAND_5G:
      return ChannelWidth.WIDTH_80


@dataclasses.dataclass
class WiFiConfig:
  """The class for what settings are required for the WiFi we need to start."""

  # Default to WiFi 6.
  standard: constants.Ieee80211Standards = constants.Ieee80211Standards.AC

  # If None, will be automatically generated in _post_init_.
  ssid: str | None = dataclasses.field(default=None, init=True)

  country_code: str = 'US'

  encryption_config: base_encryption_config.BaseEncryptionConfig = (
      dataclasses.field(default_factory=wpa.gen_config_for_wpa2_ccmp)
  )

  # See `constant.CHANNEL_TO_FREQUENCY` for all supported channels.
  channel: int = 1

  # The channel width.
  # If None, will be automatically decided in _post_init_.
  width: ChannelWidth | None = dataclasses.field(default=None, init=True)

  # HT capabilities (supported starting from 802.11N).
  # Corresponds to `ht_capab` field of hostapd config file.
  ht_capab: Sequence[HostapdHTCapab] | None = None

  # VHT capabilities (supported starting from 802.11AC).
  # Corresponds to `vht_capab` field of hostapd config file.
  vht_capab: Sequence[HostapdVHTCapab] | None = None

  # The setting of "Protected Management Frames" (IEEE802.11w).
  pmf: PMF | None = None

  # Whether to access wide area network (WAN) through network address
  # translation(NAT). If true, each wireless network will be on its own subnet
  # with its own dhcp server, and traffic will only be routed to specific subnet
  # when needed. Otherwise, all wireless networks will be shared together with
  # the WAN and it assumes there's a DHCP server running in the WAN.
  access_wan_through_nat: bool = False

  custom_hostapd_configs: Mapping[str, str] = dataclasses.field(
      default_factory=dict
  )

  def __post_init__(self):
    if self.ssid is None:
      self.ssid = generate_wifi_ssid(self.band_type)
    if self.width is None:
      self.width = _get_default_width(self.band_type)

    self._check_validity()

  @property
  def band_type(self) -> BandType:
    """The band type."""
    if 1 <= self.channel <= 14:
      return BandType.BAND_2G
    elif 36 <= self.channel <= 177:
      return BandType.BAND_5G
    else:
      raise errors.ConfigError(
          f'Unsupported WiFi channel: {self.channel}. See'
          ' `constant.CHANNEL_TO_FREQUENCY` for all supported channels.'
      )

  def _check_validity(self):
    """Checks whether the configurations are valid."""
    channel = self.channel
    if channel not in constants.CHANNEL_TO_FREQUENCY:
      raise errors.ConfigError(
          f'Unsupported WiFi channel: {channel}. See'
          ' `constant.CHANNEL_TO_FREQUENCY` for all supported channels.'
      )

    # Check the validity of HT40 mode when width >= 40MHz.
    ht_capab = self.ht_capab or []
    if self.width != ChannelWidth.WIDTH_20:
      if channel in CHANNELS_HT40_PLUS_AND_MINUS:
        if not (
            HostapdHTCapab.HT40_PLUS in ht_capab
            or HostapdHTCapab.HT40_MINUS in ht_capab
        ):
          raise errors.ConfigError(
              f'Must specify ht_capab HT40+/HT40- with channel={channel} and '
              f'width={self.width}.'
          )

      if (
          channel in CHANNELS_HT40_MINUS
          and HostapdHTCapab.HT40_PLUS in ht_capab
      ):
        raise errors.ConfigError(
            f'Got wrong ht_capab {HostapdHTCapab.HT40_PLUS.value} with'
            f' channel={channel} and width={self.width}.'
        )

      if (
          channel in CHANNELS_HT40_PLUS
          and HostapdHTCapab.HT40_MINUS in ht_capab
      ):
        raise errors.ConfigError(
            f'Got wrong ht_capab {HostapdHTCapab.HT40_MINUS.value} with'
            f' channel={channel} and width={self.width}.'
        )

    # Check the validity of combination (width, standard).
    match (self.width, self.standard):
      case (ChannelWidth.WIDTH_20, _):
        pass
      case (
          ChannelWidth.WIDTH_40,
          (
              Ieee80211Standards.N
              | Ieee80211Standards.AC
              | Ieee80211Standards.AX
          ),
      ):
        pass
      case (
          ChannelWidth.WIDTH_80,
          (Ieee80211Standards.AC | Ieee80211Standards.AX),
      ):
        pass
      case _:
        raise errors.ConfigError(
            f'Got unsupported channel width {self.width} with standard'
            f' {self.standard}.'
        )


@dataclasses.dataclass
class WifiInfo:
  """The class for the information of a WiFi running on the AP device."""

  id: int
  ssid: str
  password: str | None
  interface: str
  phy_name: str
