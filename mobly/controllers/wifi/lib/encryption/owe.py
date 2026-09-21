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

"""Configurations for the encryption mode OWE."""

import enum
import re
from typing import override

from mobly.controllers.wifi.lib import errors
from mobly.controllers.wifi.lib.encryption import uci_encryptions
from mobly.controllers.wifi.lib.encryption import wpa

BSSID_REGEX = re.compile(r'^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$')


@enum.unique
class OweMode(enum.StrEnum):
  """Enum for OWE modes."""

  PURE_OWE = 'ModePureOWE'
  TRANS_OPEN = 'ModeTransOpen'
  TRANS_OWE = 'ModeTransOWE'


class Owe(wpa.WpaCommon):
  """The configuration class for the OWE encryption type."""

  _owe_encrypt_mode: OweMode
  _owe_encrypt_ssid: str
  _owe_encrypt_bssid: str

  # IEEE 802.11w
  IEEE80211W_REQUIRED = '2'

  def __init__(
      self, mode: OweMode = OweMode.PURE_OWE, ssid: str = '', bssid: str = ''
  ):
    """Constructor.

    Args:
      mode: The OWE mode to set.
      ssid: The SSID of the WiFi network.
      bssid: The BSSID of the WiFi network.
    """
    self._owe_encrypt_mode = mode
    self._owe_encrypt_ssid = ssid
    self._owe_encrypt_bssid = bssid

    super().__init__(
        mode=wpa.Mode.PURE_WPA2,
        key_mgmt={wpa.KeyMgmt.OWE},
        ciphers2={wpa.Cipher.CCMP},
    )

  @override
  def validate(self) -> None:
    """Validates the configurations are valid.

    Raises:
      errors.ConfigError: If the configurations are not valid.
    """
    super().validate()

    if self._owe_encrypt_mode != OweMode.PURE_OWE:
      if not self._owe_encrypt_ssid or not self._owe_encrypt_bssid:
        raise errors.ConfigError(
            'SSID and BSSID must be specified for the transition mode.'
        )
      if not BSSID_REGEX.match(self._owe_encrypt_bssid):
        raise errors.ConfigError(
            f'Invalid BSSID: {self._owe_encrypt_bssid}. BSSID must be in the'
            ' format of XX:XX:XX:XX:XX:XX.'
        )

  @override
  def update_hostapd_conf(self, hostapd_conf):
    """Updates the hostapd config for the OWE encryption type.

    Args:
      hostapd_conf: The hostapd config object to update.
    """
    hostapd_conf.set_password(None)
    if self._owe_encrypt_mode in [
        OweMode.PURE_OWE,
        OweMode.TRANS_OWE,
    ]:
      hostapd_conf.update('ieee80211w', self.IEEE80211W_REQUIRED)
      super().update_hostapd_conf(hostapd_conf)

    if self._owe_encrypt_mode == OweMode.TRANS_OWE:
      hostapd_conf.update('ignore_broadcast_ssid', '1')

    if self._owe_encrypt_mode != OweMode.PURE_OWE:
      hostapd_conf.update('owe_transition_ssid', f'"{self._owe_encrypt_ssid}"')
      hostapd_conf.update('owe_transition_bssid', self._owe_encrypt_bssid)

  def get_uci_encryption_config(self) -> uci_encryptions.UciEncryptionConfig:
    """Returns the UCI encryption config."""
    uci_params = {}
    if self._owe_encrypt_mode == OweMode.TRANS_OPEN:
      ieee80211w = 0
      encryption = uci_encryptions.Encryption.NONE
    else:
      ieee80211w = int(self.IEEE80211W_REQUIRED)
      encryption = uci_encryptions.Encryption.OWE

    if self._owe_encrypt_mode == OweMode.TRANS_OWE:
      uci_params['hidden'] = '1'

    if self._owe_encrypt_mode != OweMode.PURE_OWE:
      uci_params['owe_transition_ssid'] = self._owe_encrypt_ssid
      uci_params['owe_transition_bssid'] = self._owe_encrypt_bssid
    uci_params['cipher'] = ' '.join(self._ciphers | self._ciphers2)
    return uci_encryptions.UciEncryptionConfig(
        encryption=encryption,
        ieee80211w=ieee80211w,
        extra_uci_params=uci_params,
    )
