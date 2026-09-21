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

"""The module for UCI encryption configs."""

import dataclasses
import enum
from typing import Iterable, Mapping

from mobly.controllers.wifi.lib.encryption import constants


@enum.unique
class Encryption(enum.StrEnum):
  """Base encryption modes for OpenWrt UCI.

  In OpenWrt UCI (/etc/config/wireless), cipher suites are specified by
  appending them to the encryption mode with '+' (e.g., 'psk2+ccmp',
  'psk-mixed+tkip+ccmp', 'wpa3-192').
  https://openwrt.org/docs/guide-user/network/wifi/basic#encryption_modes
  """

  NONE = 'none'
  OWE = 'owe'
  # --- WPA Personal (PSK / SAE) ---
  PSK = 'psk'  # WPA1-PSK
  PSK2 = 'psk2'  # WPA2-PSK
  PSK_MIXED = 'psk-mixed'  # WPA1+WPA2 PSK
  SAE = 'sae'  # WPA3-SAE
  SAE_MIXED = 'sae-mixed'  # WPA2+WPA3 SAE
  # TODO: (internal) - Remove SAE_EXT_MIXED and SAE_EXT once sae_ext_key is
  # supported.
  SAE_EXT = 'sae-ext'  # WPA3-SAE-EXT
  SAE_EXT_MIXED = 'sae-ext-mixed'  # WPA2+WPA3 SAE-EXT
  # --- WPA Enterprise (EAP / 802.1X) ---
  WPA = 'wpa'  # WPA1-EAP
  WPA2 = 'wpa2'  # WPA2-EAP
  WPA_MIXED = 'wpa-mixed'  # WPA1+WPA2 EAP
  WPA3 = 'wpa3'  # WPA3-EAP
  WPA3_MIXED = 'wpa3-mixed'  # WPA2+WPA3 EAP
  WPA3_192 = 'wpa3-192'  # WPA3-EAP 192-bit (Suite-B)
  # --- Legacy WEP ---
  WEP_OPEN = 'wep-open'
  WEP_SHARED = 'wep-shared'


@dataclasses.dataclass(frozen=True)
class UciEncryptionConfig:
  """UCI encryption config.

  Attributes:
    encryption: The encryption mode (e.g. 'psk2', 'wpa3-192').
    ciphers: The cipher suites (e.g. {'CCMP', 'TKIP'}).
    key: The password of the network.
    ieee80211w: The setting of "Protected Management Frames" (IEEE802.11w).
    extra_uci_params: The extra parameters that would be added as is to the UCI
      config.
    extra_hostapd_params: The extra parameters that would be added as is to the
      hostapd config.
  """

  encryption: Encryption
  ciphers: set[constants.Cipher] | None = None
  key: str | None = None
  ieee80211w: int | None = None
  extra_uci_params: Mapping[str, str] = dataclasses.field(default_factory=dict)
  extra_hostapd_params: Mapping[str, Iterable[str] | str] = dataclasses.field(
      default_factory=dict
  )

  def format_uci_encryption(self) -> str:
    """Formats the UCI encryption string."""
    if not self.ciphers:
      return str(self.encryption)

    # For WPA3-192 / Suite-B, GCMP-256 is the standard cipher and built into the
    # mode.
    if self.encryption == Encryption.WPA3_192:
      return str(self.encryption)

    if {constants.Cipher.TKIP, constants.Cipher.CCMP} <= self.ciphers:
      return f'{self.encryption}+tkip+ccmp'
    elif constants.Cipher.GCMP256 in self.ciphers:
      return f'{self.encryption}+gcmp256'
    elif constants.Cipher.CCMP256 in self.ciphers:
      return f'{self.encryption}+ccmp256'
    elif constants.Cipher.GCMP in self.ciphers:
      return f'{self.encryption}+gcmp'
    elif constants.Cipher.CCMP in self.ciphers:
      return f'{self.encryption}+ccmp'
    elif constants.Cipher.TKIP in self.ciphers:
      return f'{self.encryption}+tkip'

    raise ValueError(
        f'Unsupported cipher suites: {self.ciphers} for base encryption'
        f' {self.encryption}'
    )
