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

from collections.abc import Iterable, Mapping, Sequence, Set
import dataclasses
import enum
import random
import re
from typing import Final

import immutabledict
from mobly import utils

from mobly.controllers.wifi.lib import constants
from mobly.controllers.wifi.lib import errors
from mobly.controllers.wifi.lib import iw_utils
from mobly.controllers.wifi.lib.encryption import base_encryption_config
from mobly.controllers.wifi.lib.encryption import open as open_sec
from mobly.controllers.wifi.lib.encryption import wep
from mobly.controllers.wifi.lib.encryption import wpa

# LAA and unicast MAC address regex.
# Reference:
# https://en.wikipedia.org/wiki/MAC_address#Ranges_of_group_and_locally_administered_addresses
_MAC_ADDRESS_REGEX = re.compile(
    r'[0-9a-fA-F][26aAeE]:([0-9a-fA-F]{2}:){4}[0-9a-fA-F]{2}'
)


# https://openwrt.org/docs/guide-user/network/wifi/basic#wi-fi_interfaces
@enum.unique
class ApType(enum.StrEnum):
  """The mode type of the WiFi interface."""

  AP = 'ap'
  STA = 'sta'
  ADHOC = 'adhoc'
  MONITOR = 'monitor'
  MESH = 'mesh'


# TODO: move Ieee80211Standards from constants to this module.
Ieee80211Standards = constants.Ieee80211Standards


@enum.unique
class BandType(enum.StrEnum):
  """Band types."""

  BAND_2G = '2G'
  BAND_5G = '5G'
  BAND_6G = '6G'


# A short summary:
# * US: 1 - 11, 36 - 64, 100 - 144, 149 - 173 are valid. 52 - 144 are DFS
#   channels.
# * Japan: 1 - 14, 36 - 64, 100 - 140 are valid. 52 - 140 are DFS channels.
CHANNEL_TO_FREQUENCY = immutabledict.immutabledict({
    BandType.BAND_2G: immutabledict.immutabledict({
        1: 2412,
        2: 2417,
        3: 2422,
        4: 2427,
        5: 2432,
        6: 2437,
        7: 2442,
        8: 2447,
        9: 2452,
        10: 2457,
        11: 2462,
        12: 2467,
        13: 2472,
        14: 2484,
    }),
    BandType.BAND_5G: immutabledict.immutabledict({
        36: 5180,
        38: 5190,
        40: 5200,
        42: 5210,
        44: 5220,
        46: 5230,
        48: 5240,
        52: 5260,
        56: 5280,
        60: 5300,
        64: 5320,
        100: 5500,
        104: 5520,
        108: 5540,
        112: 5560,
        116: 5580,
        120: 5600,
        124: 5620,
        128: 5640,
        132: 5660,
        136: 5680,
        140: 5700,
        144: 5720,
        149: 5745,
        153: 5765,
        157: 5785,
        161: 5805,
        165: 5825,
        169: 5845,
        173: 5865,
    }),
    BandType.BAND_6G: immutabledict.immutabledict({
        2: 5935,
        1: 5955,
        5: 5975,
        9: 5995,
        13: 6015,
        17: 6035,
        21: 6055,
        25: 6075,
        29: 6095,
        33: 6115,
        37: 6135,
        41: 6155,
        45: 6175,
        49: 6195,
        53: 6215,
        57: 6235,
        61: 6255,
        65: 6275,
        69: 6295,
        73: 6315,
        77: 6335,
        81: 6355,
        85: 6375,
        89: 6395,
        93: 6415,
        97: 6435,
        101: 6455,
        105: 6475,
        109: 6495,
        113: 6515,
        117: 6535,
        121: 6555,
        125: 6575,
        129: 6595,
        133: 6615,
        137: 6635,
        141: 6655,
        145: 6675,
        149: 6695,
        153: 6715,
        157: 6735,
        161: 6755,
        165: 6775,
        169: 6795,
        173: 6815,
        177: 6835,
        181: 6855,
        185: 6875,
        189: 6895,
        193: 6915,
        197: 6935,
        201: 6955,
        205: 6975,
        209: 6995,
        213: 7015,
        217: 7035,
        221: 7055,
        225: 7075,
        229: 7095,
        233: 7115,
    }),
})


def get_channel_and_band(frequency_mhz: int) -> tuple[int, BandType] | None:
  """Gets the channel and band from a given frequency."""
  for band, channels in CHANNEL_TO_FREQUENCY.items():
    for channel, freq in channels.items():
      if freq == frequency_mhz:
        return channel, band
  return None


def get_frequency(channel: int, band: BandType | None = None) -> int | None:
  """Gets the frequency for a given channel and band.

  For 6GHz channels, the band type must be specified.

  Args:
    channel: The WiFi channel number.
    band: The band type. If None, it will be inferred from the channel number,
      but this does not support 6GHz bands.

  Raises:
    errors.ConfigError: If the channel is not supported or the band is not
      specified for a 6GHz channel.

  Returns:
    The frequency in MHz for the given channel and band, or None if the
    combination is not valid.
  """
  if band is None:
    band = band_type_from_channel(channel)
  return CHANNEL_TO_FREQUENCY.get(band, {}).get(channel)


def is_valid_channel(channel: int, band: BandType | None = None) -> bool:
  """Checks whether a channel is valid for a given band.

  For 6GHz channels, the band type must be specified.

  Args:
    channel: The WiFi channel number.
    band: The band type. If None, it will be inferred from the channel number,
      but this does not support 6GHz bands.

  Returns:
    True if the channel is valid for the given band, False otherwise.
  """
  if band is None:
    band = band_type_from_channel(channel)
  return get_frequency(channel, band) is not None


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

START_FREQ_FOR_WIDTH_80_SEGMENTS = (
    5180,
    5260,
    5500,
    5580,
    5660,
    5745,
    5955,
    6035,
    6115,
    6195,
    6275,
    6355,
    6435,
    6515,
    6595,
    6675,
    6755,
    6835,
    6915,
    6995,
)

_HARDWARE_SUPPORT_HT20_HT40 = 'HT20/HT40'
_VHT_CAP_SUPPORT_WIDTH_80MHZ_RE = re.compile(
    'Supported Channel Width:.*(160|80)'
)


@enum.unique
class ChannelWidth(enum.StrEnum):
  """The supported channel widths."""

  WIDTH_20 = '20MHz'
  WIDTH_40 = '40MHz'
  WIDTH_80 = '80MHz'
  WIDTH_160 = '160MHz'
  WIDTH_320 = '320MHz'
  WIDTH_80_80 = '80+80MHz'

  def to_hostapd_enum(self) -> str:
    """Converts the channel width to a hostapd width enum."""
    match self:
      case ChannelWidth.WIDTH_20:
        return '0'
      case ChannelWidth.WIDTH_40:
        return '0'
      case ChannelWidth.WIDTH_80:
        return '1'
      case ChannelWidth.WIDTH_160:
        return '2'
      case ChannelWidth.WIDTH_80_80:
        return '3'
      case ChannelWidth.WIDTH_320:
        raise errors.ConfigError('320MHz is not supported in hostapd.')


@enum.unique
class Mode(enum.StrEnum):
  """Mode and bandwidth.

  https://openwrt.org/docs/guide-user/network/wifi/basic#htmodewi-fi_channel_width
  HE and EHT channel bandwidths are referenced from:
  https://source.chromium.org/chromiumos/_/chromium/chromiumos/platform/tast-tests/+/c08f089675cb02ee2df2d49657bca237e2c60de4:src/go.chromium.org/tast-tests/cros/remote/wificell/hostapd/config.go;l=239;bpv=0
  Split bands like 80+80 are not used in Bpi router.

  Within a standard, modes should be ordered by increasing channel width.
  """

  NOHT = 'NOHT'  # disables 11n
  HT20 = 'HT20'
  HT40 = 'HT40'
  # High Throughput 40MHz, 802.11n, control channel is below extension channel.
  HT40_MINUS = 'HT40-'
  # High Throughput 40MHz, 802.11n, control channel is above extension channel.
  HT40_PLUS = 'HT40+'
  # Everything below is not supported by current hostapd.
  VHT20 = 'VHT20'
  VHT40 = 'VHT40'
  VHT80 = 'VHT80'
  VHT80_80 = 'VHT80+80'
  VHT160 = 'VHT160'
  HE20 = 'HE20'
  HE40 = 'HE40'
  HE80 = 'HE80'
  HE80_80 = 'HE80+80'
  HE160 = 'HE160'
  EHT20 = 'EHT20'
  EHT40 = 'EHT40'
  EHT80 = 'EHT80'
  EHT80_80 = 'EHT80+80'
  EHT160 = 'EHT160'
  EHT320 = 'EHT320'

  def __gt__(self, other: 'Mode') -> bool:  # pyrefly: ignore[bad-override]
    if not isinstance(other, Mode):
      return NotImplemented

    # Ensure we are comparing within the same standard.
    if get_standard_from_ht_mode(self) != get_standard_from_ht_mode(other):
      raise errors.ConfigError(
          f'Cannot compare different standards: {self} vs {other}.'
      )

    # Use the definition order (index in the enum) for comparison since they are
    # ordered by increasing channel width.
    members = list(self.__class__)
    return members.index(self) > members.index(other)  # pyrefly: ignore[bad-argument-type]


def get_standard_from_ht_mode(ht_mode: Mode) -> Ieee80211Standards:
  """Gets the standard from the HT mode."""
  match ht_mode:
    case Mode.NOHT:
      return Ieee80211Standards.B
    case Mode.HT20 | Mode.HT40 | Mode.HT40_PLUS | Mode.HT40_MINUS:
      return Ieee80211Standards.N
    case Mode.VHT20 | Mode.VHT40 | Mode.VHT80 | Mode.VHT80_80 | Mode.VHT160:
      return Ieee80211Standards.AC
    case Mode.HE20 | Mode.HE40 | Mode.HE80 | Mode.HE80_80 | Mode.HE160:
      return Ieee80211Standards.AX
    case (
        Mode.EHT20
        | Mode.EHT40
        | Mode.EHT80
        | Mode.EHT80_80
        | Mode.EHT160
        | Mode.EHT320
    ):
      return Ieee80211Standards.BE
    case _:
      raise errors.ConfigError(
          f'Unsupported HT mode {ht_mode} for determining standard.'
      )


@enum.unique
class HostapdHTCapab(enum.StrEnum):
  """HT capabilities that can be set to `ht_capab` field of hostapd config."""

  HT20 = '[HT20]'
  HT40_PLUS = '[HT40+]'
  HT40_MINUS = '[HT40-]'
  SHORT_GI_20 = '[SHORT-GI-20]'
  SHORT_GI_40 = '[SHORT-GI-40]'
  LDPC = '[LDPC]'


@enum.unique
class HostapdHECapab(enum.StrEnum):
  """HE capabilities that can be set to `he_capab` field of hostapd config."""


@enum.unique
class HostapdEHTCapab(enum.StrEnum):
  """EHT capabilities that can be set to `eht_capab` field of hostapd config."""


@enum.unique
class HostapdVHTCapab(enum.StrEnum):
  """VHT capabilities that can be set to `vht_capab` field of hostapd config."""

  SHORT_GI_80 = '[SHORT-GI-80]'
  SHORT_GI_160 = '[SHORT-GI-160]'
  RXLDPC = '[RXLDPC]'
  VHT_CAP_MAX_AMPDULEN_EXP6 = '[MAX-A-MPDU-LEN-EXP6]'
  VHT_CAP_MAX_AMPDULEN_EXP7 = '[MAX-A-MPDU-LEN-EXP7]'


# The dict that returns whether a channel supports HT40+ or HT40-.
CHANNEL_HOSTAPD_HT40_MODE = immutabledict.immutabledict({
    **{ch: HostapdHTCapab.HT40_PLUS for ch in CHANNELS_HT40_PLUS},
    **{ch: HostapdHTCapab.HT40_MINUS for ch in CHANNELS_HT40_MINUS},
})


@enum.unique
class PMF(enum.IntEnum):
  """The enum for the setting of "Protected Management Frames" (IEEE802.11w)."""

  DISABLED = 0
  OPTIONAL = 1
  REQUIRED = 2


@enum.unique
class BssidGenerateMode(enum.StrEnum):
  """The mode of BSSID generation."""

  RANDOM = 'random'
  USE_AP_MAC = 'use_ap_mac'


def generate_wifi_ssid(band_type: BandType) -> str:
  """Generates a wifi SSID with a random substring."""
  random_str = utils.rand_ascii_str(5)
  return f'OpenWRT-{band_type.value}-{random_str}'


def generate_random_bssid() -> str:
  """Generates a random BSSID which is locally administered address and unicast.

  A LAA and unicast MAC address means the second digit must be 2, 6, a or
  e. I.e. X2:XX:XX:XX:XX:XX is valid, while X1:XX:XX:XX:XX:XX is not.

  Reference:
  https://en.wikipedia.org/wiki/MAC_address#Ranges_of_group_and_locally_administered_addresses

  Returns:
    Generated BSSID.
  """
  raw_values = [random.randrange(256) for _ in range(6)]
  raw_values[0] &= ~1
  raw_values[0] |= 2
  mac = ':'.join('%02x' % b for b in raw_values)
  return mac


def channel_width_from_ht_mode(
    ht_mode: Mode,
) -> ChannelWidth:
  """Transforms HT mode to channel width."""
  match ht_mode:
    case Mode.NOHT | Mode.HT20 | Mode.VHT20 | Mode.HE20 | Mode.EHT20:
      return ChannelWidth.WIDTH_20
    case (
        Mode.HT40
        | Mode.HT40_PLUS
        | Mode.HT40_MINUS
        | Mode.VHT40
        | Mode.HE40
        | Mode.EHT40
    ):
      return ChannelWidth.WIDTH_40
    case Mode.VHT80 | Mode.HE80 | Mode.EHT80:
      return ChannelWidth.WIDTH_80
    case Mode.VHT160 | Mode.HE160 | Mode.EHT160:
      return ChannelWidth.WIDTH_160
    case Mode.EHT320:
      return ChannelWidth.WIDTH_320
    case Mode.VHT80_80 | Mode.HE80_80 | Mode.EHT80_80:
      return ChannelWidth.WIDTH_80_80
    case _:
      raise errors.ConfigError(
          f'Unsupported HT mode {ht_mode} for channel width transformation.'
      )


@enum.unique
class PhyType(enum.IntEnum):
  """PHY type values, see dot11PhyType in IEEE 802.11-2020 Annex C."""

  UNSPECIFIED = 0
  FHSS = 1
  DSSS = 2
  IRBASEBAND = 3
  OFDM = 4
  HRDSSS = 5
  ERP = 6
  HT = 7
  DMG = 8
  VHT = 9
  HE = 10
  EHT = 11


def get_phy_type_from_standard(
    standard: Ieee80211Standards | None,
    band_type: BandType | None = None,
) -> PhyType:
  """Derives the dot11PhyType for a given standard and band."""
  if standard is not None:
    match standard:
      case Ieee80211Standards.B:
        return PhyType.HRDSSS
      case Ieee80211Standards.A:
        return PhyType.OFDM
      case Ieee80211Standards.G:
        return PhyType.ERP
      case Ieee80211Standards.N:
        return PhyType.HT
      case Ieee80211Standards.AC:
        return PhyType.VHT
      case Ieee80211Standards.AX:
        return PhyType.HE
      case Ieee80211Standards.BE:
        return PhyType.EHT
  if band_type == BandType.BAND_2G:
    return PhyType.ERP
  elif band_type in (BandType.BAND_5G, BandType.BAND_6G):
    return PhyType.OFDM
  return PhyType.UNSPECIFIED


# 6 GHz is strictly bandwidth-indexed (Global OpClasses)
_OPCLASS_6G: Final[dict[ChannelWidth, int]] = {
    ChannelWidth.WIDTH_20: 131,
    ChannelWidth.WIDTH_40: 132,
    ChannelWidth.WIDTH_80: 133,
    ChannelWidth.WIDTH_160: 134,
    ChannelWidth.WIDTH_80_80: 135,
    ChannelWidth.WIDTH_320: 137,
}

# 5 GHz wide channels
_OPCLASS_5G_WIDE: Final[dict[ChannelWidth, int]] = {
    ChannelWidth.WIDTH_80: 128,
    ChannelWidth.WIDTH_160: 129,
    ChannelWidth.WIDTH_80_80: 130,
}


def _get_5g_20mhz_base_opclass(channel: int) -> int:
  """Returns the 20MHz base OpClass for 5GHz bands (40MHz is base + 1)."""
  if 36 <= channel <= 48:
    return 115  # 40MHz: 116
  if 52 <= channel <= 64:
    return 118  # 40MHz: 119
  if 100 <= channel <= 144:
    return 121  # 40MHz: 122
  if 149 <= channel <= 177:
    return 125  # 40MHz: 126
  raise errors.ConfigError(f'Invalid 5GHz channel {channel}.')


def get_operating_class(
    channel: int,
    band_type: BandType | None = None,
    width: ChannelWidth | None = None,
    ht_mode: Mode | None = None,
) -> int:
  """Derives the IEEE 802.11 Global Operating Class."""
  if band_type is None:
    band_type = band_type_from_channel(channel)

  # 1. Normalize width once
  if width is None and ht_mode is not None:
    width = channel_width_from_ht_mode(ht_mode)
  width = width or ChannelWidth.WIDTH_20

  # 2. Derive OpClass per band
  match band_type:
    case BandType.BAND_6G:
      if channel == 2 and width == ChannelWidth.WIDTH_20:
        return 136
      if width in _OPCLASS_6G:
        return _OPCLASS_6G[width]
      raise errors.ConfigError(f'Unsupported 6GHz width: {width}.')

    case BandType.BAND_5G:
      if width in _OPCLASS_5G_WIDE:
        return _OPCLASS_5G_WIDE[width]

      base_20mhz = _get_5g_20mhz_base_opclass(channel)
      if width == ChannelWidth.WIDTH_20:
        return base_20mhz
      if width == ChannelWidth.WIDTH_40:
        return base_20mhz + 1  # 115->116, 118->119, 121->122, 125->126

      raise errors.ConfigError(
          f'Invalid width {width} for 5GHz channel {channel}.'
      )

    case BandType.BAND_2G:
      if channel == 14:
        return 82
      if width == ChannelWidth.WIDTH_40 or ht_mode in (
          Mode.HT40,
          Mode.HT40_PLUS,
          Mode.HT40_MINUS,
      ):
        is_minus = ht_mode == Mode.HT40_MINUS or (
            channel in CHANNELS_HT40_MINUS
            and channel not in CHANNELS_HT40_PLUS_AND_MINUS
        )
        return 84 if is_minus else 83
      return 81

    case _:
      raise errors.ConfigError(f'Unsupported band type: {band_type}.')


def _get_ht40_mode(channel: int, ht_capab: Sequence[HostapdHTCapab]) -> Mode:
  """Determines HT40+ or HT40- based on channel and capabilities."""
  if channel in CHANNELS_HT40_PLUS_AND_MINUS:
    if HostapdHTCapab.HT40_PLUS in ht_capab:
      return Mode.HT40_PLUS
    else:
      return Mode.HT40_MINUS
  elif channel in CHANNELS_HT40_PLUS:
    return Mode.HT40_PLUS
  else:
    return Mode.HT40_MINUS


def _transform_channel_width_to_ht_mode(
    width: ChannelWidth,
    channel: int,
    standard: Ieee80211Standards,
    ht_capab: Sequence[HostapdHTCapab],
    band_type: BandType | None = None,
) -> Mode:
  """Transforms channel width to HT mode."""
  if band_type is None:
    band_type = band_type_from_channel(channel)

  match standard:
    case Ieee80211Standards.A | Ieee80211Standards.B | Ieee80211Standards.G:
      return Mode.NOHT
    case Ieee80211Standards.N:
      match width:
        case ChannelWidth.WIDTH_20:
          return Mode.HT20
        case ChannelWidth.WIDTH_40:
          return _get_ht40_mode(channel, ht_capab)
        case _:
          raise errors.ConfigError(
              f'Got unsupported channel width {width} with standard {standard}.'
          )
    case Ieee80211Standards.AC:
      match (band_type, width):
        case (BandType.BAND_2G, _):
          raise errors.ConfigError(
              'Standard AC is not supported on 2.4 GHz band.'
          )
        case (BandType.BAND_6G, _):
          raise errors.ConfigError('AC standard does not support 6G band.')
        case (BandType.BAND_5G, ChannelWidth.WIDTH_20):
          return Mode.VHT20
        case (BandType.BAND_5G, ChannelWidth.WIDTH_40):
          return Mode.VHT40
        case (BandType.BAND_5G, ChannelWidth.WIDTH_80):
          return Mode.VHT80
        case (BandType.BAND_5G, ChannelWidth.WIDTH_160):
          return Mode.VHT160
        case (BandType.BAND_5G, ChannelWidth.WIDTH_80_80):
          return Mode.VHT80_80
        case _:
          raise errors.ConfigError(
              f'Unsupported channel width {width} for AC standard.'
          )
    case Ieee80211Standards.AX:
      match (band_type, width):
        case (BandType.BAND_2G, ChannelWidth.WIDTH_20):
          return Mode.HE20
        case (BandType.BAND_2G, ChannelWidth.WIDTH_40):
          return Mode.HE40
        case (BandType.BAND_2G, _):
          raise errors.ConfigError(
              'AX standard on 2G band supports max width 40 and uses HE mode.'
          )
        case (BandType.BAND_6G, ChannelWidth.WIDTH_320):
          raise errors.ConfigError(
              'AX standard on 6G band only supports width up to 160.'
          )
        case (_, ChannelWidth.WIDTH_20):
          return Mode.HE20
        case (_, ChannelWidth.WIDTH_40):
          return Mode.HE40
        case (_, ChannelWidth.WIDTH_80):
          return Mode.HE80
        case (_, ChannelWidth.WIDTH_160):
          return Mode.HE160
        case (BandType.BAND_5G, ChannelWidth.WIDTH_80_80):
          return Mode.HE80_80
        case _:
          raise errors.ConfigError(
              f'Unsupported channel width {width} for AX standard.'
          )
    case Ieee80211Standards.BE:
      match (band_type, width):
        case (BandType.BAND_2G, ChannelWidth.WIDTH_20):
          return Mode.EHT20
        case (BandType.BAND_2G, ChannelWidth.WIDTH_40):
          return Mode.EHT40
        case (BandType.BAND_2G, _):
          raise errors.ConfigError(
              'BE standard on 2G band supports max width 40 and uses EHT mode.'
          )
        case (_, ChannelWidth.WIDTH_20):
          return Mode.EHT20
        case (_, ChannelWidth.WIDTH_40):
          return Mode.EHT40
        case (_, ChannelWidth.WIDTH_80):
          return Mode.EHT80
        case (_, ChannelWidth.WIDTH_160):
          return Mode.EHT160
        case (_, ChannelWidth.WIDTH_320):
          return Mode.EHT320
        case (_, ChannelWidth.WIDTH_80_80):
          return Mode.EHT80_80
        case _:
          raise errors.ConfigError(
              f'Not implemented channel width {width} for EHT standard.'
          )
    case _:
      raise errors.ConfigError(
          f'Unsupported standard: {standard} or channel width: {width}'
      )


def _get_default_width(band_type: BandType) -> ChannelWidth:
  """Gets the default width with a given band type."""
  match band_type:
    case BandType.BAND_2G:
      return ChannelWidth.WIDTH_20
    case BandType.BAND_5G:
      return ChannelWidth.WIDTH_80
    case BandType.BAND_6G:
      return ChannelWidth.WIDTH_160
    case _:
      raise errors.ConfigError(
          f'Unsupported band type {band_type} for default channel width.'
      )


@dataclasses.dataclass
class WiFiConfig:
  """Settings required for the WiFi we need to start.

  Attributes:
    standard: The IEEE 802.11 standard.
    ssid: The SSID of the WiFi network.
    country_code: The country code of the WiFi network.
    encryption_config: The encryption configuration of the WiFi network.
    band_type: The band type of the WiFi network.
    channel: The channel of the WiFi network.
    width: The channel width of the WiFi network.
    ht_mode: The HT mode of the WiFi network.
    ht_capab: The HT capabilities of the WiFi network.
    vht_capab: The VHT capabilities of the WiFi network.
    he_capab: The HE capabilities of the WiFi network.
    eht_capab: The EHT capabilities of the WiFi network.
    pmf: The PMF of the WiFi network.
    hidden: Whether the WiFi network is hidden.
    access_wan_through_nat: Whether to access WAN through NAT.
    host_subnet_on_bridge: Whether to host subnet on bridge.
    maximum_txpower_dbm: The maximum txpower in dBm.
    bssid_or_generate_mode: The mode to generate BSSID. If set to RANDOM, a
      random BSSID will be generated. If set to USE_AP_MAC, the MAC address of
      the AP will be used as the BSSID. If a string is provided, it will be used
      as the BSSID.
    enable_resolve_to_host_ip: Whether to resolve to host IP address.
    custom_hostapd_configs: The custom hostapd configurations.
    custom_dhcp_configs: The custom DHCP configurations.
    ap_type: The AP type of the WiFi network (AP, Monitor, etc.)
    pure_mode: Whether to use pure mode for hostapd config.
    ft: Whether to use 802.11r Fast BSS Transition.
  """

  # Default to WiFi 6 (or 802.11n if WEP). Resolved in _post_init_.
  standard: constants.Ieee80211Standards = dataclasses.field(default=None, init=True)  # pyrefly: ignore[bad-assignment]

  # If None, will be automatically generated in _post_init_.
  ssid: str | None = dataclasses.field(default=None, init=True)

  country_code: str = 'US'

  encryption_config: base_encryption_config.BaseEncryptionConfig = (
      dataclasses.field(default_factory=wpa.gen_config_for_wpa2_ccmp)
  )

  # The band type.
  band_type: BandType = dataclasses.field(default=None, init=True)  # pyrefly: ignore[bad-assignment]

  # See `constant.CHANNEL_TO_FREQUENCY` for all supported channels.
  channel: int = 1

  # The channel width.
  # If None, will be automatically decided in _post_init_.
  width: ChannelWidth | None = dataclasses.field(default=None, init=True)

  # The HT mode of the WiFi network.
  ht_mode: Mode | None = dataclasses.field(default=None, init=True)

  # HT capabilities (supported starting from 802.11N).
  # Corresponds to `ht_capab` field of hostapd config file.
  ht_capab: Sequence[HostapdHTCapab] | None = None

  # VHT capabilities (supported starting from 802.11AC).
  # Corresponds to `vht_capab` field of hostapd config file.
  vht_capab: Sequence[HostapdVHTCapab] | None = None

  # HE capabilities (supported starting from 802.11AX).
  # Corresponds to `he_capab` field of hostapd config file.
  he_capab: Sequence[HostapdHECapab] | None = None

  # EHT capabilities (supported starting from 802.11BE).
  # Corresponds to `eht_capab` field of hostapd config file.
  eht_capab: Sequence[HostapdEHTCapab] | None = None

  # The setting of "Protected Management Frames" (IEEE802.11w).
  pmf: PMF | None = None

  # Whether the WiFi network is hidden.
  hidden: bool = False

  # Whether to use 802.11r Fast BSS Transition.
  ft: bool = False

  # Whether to access wide area network (WAN) through network address
  # translation(NAT). If true, each wireless network will be on its own subnet
  # with its own dhcp server, and traffic will only be routed to specific subnet
  # when needed. Otherwise, all wireless networks will be shared together with
  # the WAN and it assumes there's a DHCP server running in the WAN.
  access_wan_through_nat: bool = True

  # If true, the DHCP server will be hosted on a bridge interface which is
  # bound to the wireless interface. If False, the DHCP server will be hosted
  # on the wireless interface. This field is only used when
  # access_wan_through_nat is True.
  host_subnet_on_bridge: bool = False

  # Specifies the maximum desired transmission power in dBm. The actual txpower
  # used depends on regulatory requirements.
  # This must be a positive integer.
  # Reference value: by default 23 dBm will be used for channel 36 in US.
  maximum_txpower_dbm: int | None = None

  bssid_or_generate_mode: BssidGenerateMode | str = BssidGenerateMode.RANDOM

  # If True, the AP will resolve all DNS requests to the host IP address.
  enable_resolve_to_host_ip: bool = False

  # Custom hostapd configurations.
  # Pass an `Iterable` if the hostapd config key supports multiple values.
  # E.g., Setting `custom_hostapd_configs['venue_name']` to
  # `['eng:Local zoo park', 'fra:Parc zoologique']` results in two
  # entries in the final hostapd config file:
  # `venue_name=eng:Local zoo park` and `venue_name=fra:Parc zoologique`.
  custom_hostapd_configs: Mapping[str, str | Iterable[str]] = dataclasses.field(
      default_factory=dict
  )

  # Custom DHCP configuration for the interface that will be created by the
  # HostapdManager.
  custom_dhcp_configs: Set[str] = dataclasses.field(default_factory=set)

  # The AP type of the WiFi network (AP, Monitor, etc.)
  # Used for UCI setup were interface type is needed.
  # If hostapd is used to create the interface, the type should be AP or error
  # will be raised.
  ap_type: ApType = ApType.AP

  # If True hostapd would add 'require_<mode>=1` to the config file.
  pure_mode: bool = False

  _bssid: str | None = dataclasses.field(default=None, init=False)

  def __post_init__(self):
    if self.bssid_or_generate_mode == BssidGenerateMode.RANDOM:
      self._bssid = generate_random_bssid()
    elif self.bssid_or_generate_mode == BssidGenerateMode.USE_AP_MAC:
      self._bssid = None
    else:
      self._bssid = self.bssid_or_generate_mode

    if self._bssid is not None and not _MAC_ADDRESS_REGEX.fullmatch(
        self._bssid
    ):
      raise errors.ConfigError(f'Invalid BSSID: {self._bssid}')

    if self.band_type is None:
      self.band_type = band_type_from_channel(self.channel)  # pyrefly: ignore[bad-assignment]
    else:
      if not is_valid_channel(self.channel, self.band_type):
        raise errors.ConfigError(
            f'Incompatible channel {self.channel} and band {self.band_type}'
        )

    if self.ssid is None:
      self.ssid = generate_wifi_ssid(self.band_type)

    if self.standard is None:
      if isinstance(self.encryption_config, wep.Wep):
        self.standard = constants.Ieee80211Standards.N  # pyrefly: ignore[bad-assignment]
      else:
        self.standard = constants.Ieee80211Standards.AX  # pyrefly: ignore[bad-assignment]

    self._check_encryption_config_validity()
    self._check_band_and_standard_validity()

    if self.width is None:
      if self.ht_mode is not None:
        self.width = channel_width_from_ht_mode(self.ht_mode)
      else:
        self.width = _get_default_width(self.band_type)
    if self.ht_mode is None:
      self.ht_mode = _transform_channel_width_to_ht_mode(
          self.width,
          self.channel,
          self.standard,
          self.ht_capab or [],
          self.band_type,
      )
    self._check_validity()

  @property
  def bssid(self) -> str | None:
    """The BSSID of the WiFi network."""
    return self._bssid

  def _check_validity(self):
    """Checks whether the configurations are valid."""
    self._check_encryption_config_validity()
    self._check_band_and_standard_validity()
    self._check_width_and_ht_mode_validity()
    self._check_frequency_configs_validity()
    self._check_txpower_config_validity()

  def _check_band_and_standard_validity(self):
    """Checks the validity of the combination of band and standard."""
    match self.band_type:
      case BandType.BAND_2G:
        if self.standard in (
            Ieee80211Standards.A,
            Ieee80211Standards.AC,
        ):
          raise errors.ConfigError(
              f'Standard {self.standard} is not supported on 2.4 GHz band.'
          )
      case BandType.BAND_5G:
        if self.standard in (
            Ieee80211Standards.B,
            Ieee80211Standards.G,
        ):
          raise errors.ConfigError(
              f'Standard {self.standard} is not supported on 5 GHz band.'
          )
      case BandType.BAND_6G:
        if self.standard not in (
            Ieee80211Standards.AX,
            Ieee80211Standards.BE,
        ):
          raise errors.ConfigError(
              f'Standard {self.standard} is not supported on 6 GHz band.'
              ' Only 802.11ax (Wi-Fi 6E) and 802.11be (Wi-Fi 7) are supported.'
          )

  def _check_encryption_config_validity(self):
    """Checks the validity of encryption configuration with band, standard, and width."""
    if isinstance(self.encryption_config, wep.Wep):
      if self.band_type == BandType.BAND_6G:
        raise errors.ConfigError(
            'WEP encryption is not supported on 6 GHz band.'
        )
      if self.standard in (
          Ieee80211Standards.AC,
          Ieee80211Standards.AX,
          Ieee80211Standards.BE,
      ):
        raise errors.ConfigError(
            f'WEP encryption is not supported with {self.standard}. Use'
            ' 802.11n, 802.11g, 802.11b, or 802.11a.'
        )
      if self.width is not None and self.width not in (
          ChannelWidth.WIDTH_20,
          ChannelWidth.WIDTH_40,
      ):
        raise errors.ConfigError(
            f'WEP encryption only supports channel width 20MHz or 40MHz, got'
            f' {self.width}.'
        )

    if self.band_type == BandType.BAND_6G:
      if isinstance(self.encryption_config, open_sec.Open):
        raise errors.ConfigError(
            'Unencrypted open security is not supported on 6 GHz band. Use'
            ' OWE (OWESecurity) instead.'
        )

  def _check_width_and_ht_mode_validity(self):
    """Checks the validity of width and ht_mode configurations."""
    if self.width is None or self.ht_mode is None:
      raise errors.ConfigError('width and ht_mode must be specified.')
    expected_width = channel_width_from_ht_mode(self.ht_mode)
    if self.width != expected_width:
      raise errors.ConfigError(
          f'Incompatible width {self.width} and ht_mode {self.ht_mode}.'
          f' Expected width: {expected_width}.'
      )

  def _check_frequency_configs_validity(self):
    """Checks the frequency related configurations."""
    channel = self.channel
    if not is_valid_channel(channel, self.band_type):
      raise errors.ConfigError(
          f'Unsupported WiFi channel: {channel} for band {self.band_type}. See'
          ' `wifi_configs.CHANNEL_TO_FREQUENCY` for all supported channels.'
      )

    # Check the validity of HT40 mode when width >= 40MHz.
    ht_capab = self.ht_capab or []
    if (
        self.width != ChannelWidth.WIDTH_20
        and self.band_type != BandType.BAND_6G
        and self.standard == Ieee80211Standards.N
    ):
      if channel in CHANNELS_HT40_PLUS_AND_MINUS and not (
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
      ) or (
          channel in CHANNELS_HT40_PLUS
          and HostapdHTCapab.HT40_MINUS in ht_capab
      ):
        raise errors.ConfigError(
            f'Got wrong ht_capab {ht_capab} with'
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
              | Ieee80211Standards.BE
          ),
      ):
        pass
      case (
          ChannelWidth.WIDTH_80,
          (
              Ieee80211Standards.AC
              | Ieee80211Standards.AX
              | Ieee80211Standards.BE
          ),
      ):
        pass
      case (
          ChannelWidth.WIDTH_160,
          (
              Ieee80211Standards.AC
              | Ieee80211Standards.AX
              | Ieee80211Standards.BE
          ),
      ):
        pass
      case (
          ChannelWidth.WIDTH_80_80,
          (
              Ieee80211Standards.AC
              | Ieee80211Standards.AX
              | Ieee80211Standards.BE
          ),
      ):
        pass
      case (
          ChannelWidth.WIDTH_320,
          Ieee80211Standards.BE,
      ):
        pass
      case _:
        raise errors.ConfigError(
            f'Got unsupported channel width {self.width} with standard'
            f' {self.standard}.'
        )

  def _check_txpower_config_validity(self):
    """Checks the txpower configurations."""
    if self.maximum_txpower_dbm is not None and self.maximum_txpower_dbm <= 0:
      raise errors.ConfigError(
          'maximum_txpower_dbm must be positive integers, got'
          f' {self.maximum_txpower_dbm}.'
      )


@dataclasses.dataclass
class MLOConfig:
  """WiFi MLO configurations."""

  name: str
  mld_id: int


@dataclasses.dataclass
class NetworkConfig:
  """WiFi network configurations.

  Attributes:
    wifi_configs: The list of WiFi configurations.
    mlo_config: The MLO configuration.
  """

  wifi_configs: Sequence[WiFiConfig]
  mlo_config: MLOConfig | None = None


@dataclasses.dataclass(frozen=True)
class WifiLinkInfo:
  """The class for the information of a single link of a WiFi network.

  Attributes:
    bssid: The BSSID of this link.
    channel: The channel of the link.
    frequency: The frequency in MHz of the link.
    width: The channel width of the link.
    ht_mode: The HT mode of the link.
    standard: The IEEE 802.11 standard of the link.
    band_type: The band type of the link.
    link_id: The MLO link ID (if applicable).
  """

  bssid: str
  channel: int | None = None
  frequency: int | None = None
  width: ChannelWidth | None = None
  ht_mode: Mode | None = None
  standard: Ieee80211Standards | None = None
  band_type: BandType | None = None
  link_id: int | None = None

  def __post_init__(self):
    if self.band_type is None:
      if self.frequency is not None:
        res = get_channel_and_band(self.frequency)
        if res is not None:
          object.__setattr__(self, 'band_type', res[1])
      elif self.channel is not None and is_valid_channel(self.channel):
        object.__setattr__(
            self, 'band_type', band_type_from_channel(self.channel)
        )

    if (
        self.frequency is None
        and self.channel is not None
        and self.band_type is not None
    ):
      object.__setattr__(
          self, 'frequency', get_frequency(self.channel, self.band_type)
      )

    if self.standard is None and self.ht_mode is not None:
      object.__setattr__(
          self, 'standard', get_standard_from_ht_mode(self.ht_mode)
      )

    if self.width is None and self.ht_mode is not None:
      object.__setattr__(
          self, 'width', channel_width_from_ht_mode(self.ht_mode)
      )

  @property
  def op_class(self) -> int | None:
    """The IEEE 802.11 Global Operating Class of this link."""
    if self.channel is None:
      return None
    return get_operating_class(
        channel=self.channel,
        band_type=self.band_type,
        width=self.width,
        ht_mode=self.ht_mode,
    )

  @property
  def phy_type(self) -> PhyType:
    """The dot11PhyType of this link."""
    return get_phy_type_from_standard(
        standard=self.standard,
        band_type=self.band_type,
    )


@dataclasses.dataclass(frozen=True)
class WifiInfo:
  """The class for the information of a WiFi running on the AP device.

  Attributes:
    id: The unique ID of the WiFi network.
    ssid: The SSID of the WiFi network.
    password: The password of the WiFi network.
    interface: The name of the network interface for this WiFi network.
    phy_name: The name of the PHY device for this WiFi network.
    links: The sequence of links for this WiFi network.
    mld_addr: The MLD MAC address (if MLO).
    bridge: The name of the bridge interface.
    ap_type: The type of the AP (AP, monitor, STA, etc.).
    hidden: Whether the WiFi network is hidden.
    encryption_config: The encryption configuration of the WiFi network.
  """

  id: int
  ssid: str
  password: str | None
  interface: str
  phy_name: str
  links: tuple[WifiLinkInfo, ...] = ()
  mld_addr: str | None = None
  bridge: str | None = None
  ap_type: ApType = ApType.AP
  hidden: bool = False
  encryption_config: base_encryption_config.BaseEncryptionConfig | None = None

  def __post_init__(self):
    if not isinstance(self.links, tuple):
      object.__setattr__(self, 'links', tuple(self.links))

  @property
  def is_mlo(self) -> bool:
    """Whether this network is an MLO (Multi-Link Operation) network."""
    return bool(self.mld_addr) or len(self.links) > 1

  @property
  def _single_link(self) -> WifiLinkInfo:
    """Returns the single link of a non-MLO WiFi network."""
    if not self.links:
      raise errors.ConfigError(f'WiFi network "{self.ssid}" has no links.')
    if self.is_mlo:
      raise errors.ConfigError(
          f'WiFi network "{self.ssid}" is an MLO network with {len(self.links)}'
          f' links (mld_addr: {self.mld_addr}). Accessing single-link'
          ' properties directly is ambiguous. Use `wifi_info.links` or'
          ' `wifi_info.get_link_by_band(...)`.'
      )
    return self.links[0]

  @property
  def bssid(self) -> str:
    """The BSSID of the single-link WiFi network."""
    return self._single_link.bssid

  @property
  def channel(self) -> int | None:
    """The channel of the single-link WiFi network."""
    return self._single_link.channel

  @property
  def frequency(self) -> int | None:
    """The frequency in MHz of the single-link WiFi network."""
    return self._single_link.frequency

  @property
  def width(self) -> ChannelWidth | None:
    """The channel width of the single-link WiFi network."""
    return self._single_link.width

  @property
  def ht_mode(self) -> Mode | None:
    """The HT mode of the single-link WiFi network."""
    return self._single_link.ht_mode

  @property
  def standard(self) -> Ieee80211Standards | None:
    """The IEEE 802.11 standard of the single-link WiFi network."""
    return self._single_link.standard

  @property
  def band_type(self) -> BandType | None:
    """The band type of the single-link WiFi network."""
    return self._single_link.band_type

  @property
  def op_class(self) -> int | None:
    """The IEEE 802.11 Global Operating Class of the single-link WiFi network."""
    return self._single_link.op_class

  @property
  def phy_type(self) -> PhyType:
    """The dot11PhyType of the single-link WiFi network."""
    return self._single_link.phy_type

  def get_link_by_band(self, band: BandType) -> WifiLinkInfo | None:
    """Gets the link for the given frequency band."""
    for link in self.links:
      if link.band_type == band:
        return link
    return None

  def get_link_by_link_id(self, link_id: int) -> WifiLinkInfo | None:
    """Gets the link for the given MLO link ID."""
    for link in self.links:
      if link.link_id == link_id:
        return link
    return None

  @property
  def source_iface(self) -> str:
    """The name of the source interface.

    If the bridge is set, the source interface is the bridge. Otherwise, it is
    the interface. This is used for ping/arping commands from DUT to AP.
    """
    return self.bridge or self.interface


@dataclasses.dataclass
class FreqConfig:
  """The class for representing the frequency band used by a wireless network.

  This class is using the same way to represent the frequency band as hostapd.
  See the docstring of `vht_oper_centr_freq_seg1_idx` for more details.

  When the band width is smaller than 80MHz, the frequency of the center1 should
  be always be zero. When the band width is 80MHz, the frequency of the center1
  will be automatically calculated.

  Attributes:
    channel: The control channel of the frequency band.
    ht_mode: The HT mode of the frequency band. If None, sniffer manager will
      automatically decide the ht_mode for sniffering.
    center1_freq: The frequency of the center1.
    center2_freq: The frequency of the center2. Only used for 80+80MHz width.
    band_type: The band type of the frequency band.
  """

  channel: int
  ht_mode: Mode | None = None
  center1_freq: int = 0
  center2_freq: int = 0
  band_type: BandType = None  # pyrefly: ignore[bad-assignment]

  def __post_init__(self):
    if self.band_type is None:
      self.band_type = band_type_from_channel(self.channel)  # pyrefly: ignore[bad-assignment]
    if self.ht_mode is not None:
      self._check_center_freq()

  def _check_center_freq(self):
    match self.ht_mode:
      case (
          Mode.NOHT
          | Mode.HT20
          | Mode.VHT20
          | Mode.HE20
          | Mode.EHT20
          | Mode.HT40_PLUS
          | Mode.HT40_MINUS
      ):
        if self.center1_freq != 0:
          raise errors.ConfigError(
              'Specifying center1 frequency is not allowed for width'
              f' {self.ht_mode}.'
          )
      case Mode.VHT40 | Mode.HE40 | Mode.EHT40:
        if self.center1_freq == 0:
          self.center1_freq = self._calc_center1_freq_for_width40()
      case Mode.VHT80 | Mode.HE80 | Mode.EHT80:
        if self.center1_freq == 0:
          self.center1_freq = self._calc_center1_freq_for_width80()
      case Mode.VHT160 | Mode.HE160 | Mode.EHT160:
        if self.center1_freq == 0:
          self.center1_freq = self._calc_center1_freq_for_width160()
      case Mode.EHT320:
        if self.center1_freq == 0:
          self.center1_freq = self._calc_center1_freq_for_width320()
      case Mode.VHT80_80 | Mode.HE80_80 | Mode.EHT80_80:
        if self.center1_freq == 0:
          raise errors.ConfigError(
              f'Specifying center1 frequency is required for {self.ht_mode}'
          )
        if self.center2_freq == 0:
          raise errors.ConfigError(
              f'Specifying center2 frequency is required for {self.ht_mode}.'
          )
      case _:
        raise errors.ConfigError(
            f'Unsupported ht_mode in FreqConfig: {self.ht_mode}.'
        )

  def _calc_center1_freq_for_width40(self) -> int:
    """Calculates the center frequency for width 40MHz."""
    control_freq = get_frequency(self.channel, self.band_type)
    if self.band_type in [BandType.BAND_2G, BandType.BAND_5G]:
      is_upper_channel = self.channel in CHANNELS_HT40_PLUS
      is_lower_channel = self.channel in CHANNELS_HT40_MINUS
    else:
      is_upper_channel = (self.channel - 1) % 8 == 0
      is_lower_channel = (self.channel - 5) % 8 == 0

    if is_upper_channel:
      return control_freq + 10  # pyrefly: ignore[unsupported-operation]
    elif is_lower_channel:
      return control_freq - 10  # pyrefly: ignore[unsupported-operation]

    raise errors.ConfigError(
        f'Could not calculate center frequency for channel {self.channel}'
        ' (width 40MHz).'
    )

  def _calc_center1_freq_for_width80(self) -> int:
    """Calculates the center frequency for width 80MHz."""
    control_freq = get_frequency(self.channel, self.band_type)
    for f in START_FREQ_FOR_WIDTH_80_SEGMENTS:
      if f <= control_freq < f + 80:  # pyrefly: ignore[unsupported-operation]
        return f + 30
    raise errors.ConfigError(
        f'Got unsupported control frequency {control_freq} for width 80MHz.'
    )

  def _calc_center1_freq_for_width160(self) -> int:
    """Calculates the center frequency for width 160MHz."""
    control_freq = get_frequency(self.channel, self.band_type)

    # 5GHz 160MHz blocks: [36-64] (Center 5250) and [100-128] (Center 5570)
    if self.band_type == BandType.BAND_5G:
      for f_start in [5170, 5490]:  # Lower boundaries of the 160MHz blocks
        if f_start <= control_freq <= f_start + 140:  # pyrefly: ignore[unsupported-operation]
          return f_start + 70

    # 6GHz 160MHz blocks: Repeating every 160MHz starting from 5950
    elif self.band_type == BandType.BAND_6G:
      # 6GHz blocks start at 5950, 6110, 6270, etc.
      # Calculation: find the multiple of 160 offset from the base 6G freq
      base_6g = 5940
      block_index = (self.channel - 1) // 32
      center_ch = (block_index * 32) + 15
      return base_6g + (5 * center_ch)

    raise errors.ConfigError(
        f'Could not calculate center frequency for channel {self.channel} '
        f'on {self.band_type} (width 160MHz).'
    )

  def _calc_center1_freq_for_width320(self) -> int:
    """Calculates the center frequency for width 320MHz."""
    if self.band_type != BandType.BAND_6G:
      raise errors.ConfigError(
          f'Width 320MHz is not supported on band {self.band_type}.'
      )

    # 320MHz blocks in 6GHz repeat every 64 channel indices (320MHz)
    # Centers are at channels 31, 95, 159, 223
    base_6g = 5940
    block_index = (self.channel - 1) // 64
    center_ch = (block_index * 64) + 31

    return base_6g + (5 * center_ch)

  def _select_ht_mode(self, phy: iw_utils.Phy) -> Mode:
    """Selects the HT mode according to hardware capabilities in phy."""
    band_type = band_type_from_channel(self.channel)

    # First check if the hardware supports 80MHz.
    if band_type is BandType.BAND_5G:
      for band in phy.bands:
        for vht_cap in band.vht_capabilities:
          # This also matches 160MHz so it uses 80MHz even if hardware supports
          # 160MHz. This is because this controller does not support HT160 right
          # now.
          if _VHT_CAP_SUPPORT_WIDTH_80MHZ_RE.search(vht_cap):
            return Mode.VHT80

    # Then check if the hardware supports 40MHz.
    for band in phy.bands:
      if _HARDWARE_SUPPORT_HT20_HT40 not in band.capabilities:
        continue
      if self.channel in CHANNELS_HT40_PLUS_AND_MINUS:
        return Mode.HT40_MINUS
      if self.channel in CHANNELS_HT40_MINUS:
        return Mode.HT40_MINUS
      if self.channel in CHANNELS_HT40_PLUS:
        return Mode.HT40_PLUS
      return Mode.HT20

    # Default to 20MHz.
    return Mode.HT20

  @classmethod
  def from_frequency(cls, frequency_mhz: int, *args, **kwargs) -> 'FreqConfig':
    """Creates a `FreqConfig` from a frequency."""
    res = get_channel_and_band(frequency_mhz)
    if res is None:
      raise errors.ConfigError(f'Got unsupported frequency {frequency_mhz}.')
    channel, band = res
    return cls(channel, band_type=band, *args, **kwargs)

  def complete_from_phy(self, phy: iw_utils.Phy) -> None:
    """Completes the frequency configuration from PHY capabilities.

    If all fields are set, this method is no-op. Otherwise, this method will set
    them according to hardware capabilities described in `phy`.

    Args:
      phy: The wireless hardware device output by `iw phy`.
    """
    if self.ht_mode is not None:
      return

    self.ht_mode = self._select_ht_mode(phy)
    self._check_center_freq()


def band_type_from_channel(channel: int) -> BandType:
  """Gets the band type from the channel."""
  if 1 <= channel <= 14:
    return BandType.BAND_2G
  elif 36 <= channel <= 177:
    return BandType.BAND_5G
  else:
    raise errors.ConfigError(
        f'Unsupported WiFi channel: {channel}. See'
        ' `constant.CHANNEL_TO_FREQUENCY` for all supported channels.'
    )


def get_freq_config(wifi_config: WiFiConfig) -> FreqConfig:
  """Gets the frequency configuration from the given WiFi configuration."""
  return FreqConfig(
      channel=wifi_config.channel,
      ht_mode=wifi_config.ht_mode,
      band_type=wifi_config.band_type,
  )


@dataclasses.dataclass(frozen=True)
class PcapConfig:
  """Configurations for controlling the packet capture process.

  Attributes:
    keep_latest_packets: True to ignore old packets if the capture file exceeds
      a default size limit. False to ignore new packets.
    ignore_qos_data_frames: Whether to ignore QoS data frames. Note that an
      exception is that this will not ignore EAPOL frames which are used for
      WPA2-PSK authentication.
  """

  keep_latest_packets: bool = True
  ignore_qos_data_frames: bool = False
