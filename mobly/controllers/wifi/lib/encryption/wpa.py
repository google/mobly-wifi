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

"""Configurations for the encryption mode WPA."""

from collections.abc import Set
import enum

from mobly import utils as mobly_utils

from mobly.controllers.wifi.lib import errors
from mobly.controllers.wifi.lib import utils
from mobly.controllers.wifi.lib.encryption import base_encryption_config

_MIN_ASCII_PASSWORD_LEN = 8
_MAX_ASCII_PASSWORD_LEN = 63
_HEX_PASSWORD_LEN = 64


@enum.unique
class Cipher(enum.StrEnum):
  """Enum for WPA cipher suites for pairwise keys."""

  TKIP = 'TKIP'  # Temporal Key Integrity Protocol
  CCMP = 'CCMP'  # AES in Counter mode with CBC-MAC (CCMP-128)


@enum.unique
class KeyMgmt(enum.StrEnum):
  """Enum for WPA key management algorithms."""

  WPA_PSK = 'WPA-PSK'  # WPA-Personal / WPA2-Personal
  WPA_PSK_SHA256 = 'WPA-PSK-SHA256'  # WPA2-Personal using SHA256
  SAE = 'SAE'  # WPA3-Personal


@enum.unique
class Mode(enum.Enum):
  """Enum for WPA modes."""

  PURE_WPA = 'PureWPA'
  PURE_WPA2 = 'PureWPA2'
  PURE_WPA3 = 'PureWPA3'
  MIXED = 'WPAWPA2'
  MIXED_WPA3 = 'WPA2WPA3'


_MODES_USED_WPA = (Mode.PURE_WPA, Mode.MIXED)
_MODES_USED_WPA2 = (Mode.PURE_WPA2, Mode.PURE_WPA3, Mode.MIXED, Mode.MIXED_WPA3)
_MODES_USED_WPA3 = (Mode.PURE_WPA3, Mode.MIXED_WPA3)


def _generate_wifi_password():
  """Generates a wifi password with a random substring."""
  random_str = mobly_utils.rand_ascii_str(5)
  return f'RandomPSK-{random_str}'


class Wpa(base_encryption_config.BaseEncryptionConfig):
  """The configuration class for the WPA encryption type."""

  _mode: Mode
  _password: str
  _key_mgmt: Set[str]
  _ciphers: Set[str]  # ciphers used for WPA
  _ciphers2: Set[str]  # ciphers used for WPA2

  def __init__(
      self,
      mode: Mode = Mode.PURE_WPA2,
      password: str | None = None,
      ciphers: Set[Cipher] | None = None,
      ciphers2: Set[Cipher] | None = None,
      key_mgmt: Set[KeyMgmt] | None = None,
  ):
    """Constructor.

    Args:
      mode: The WPA mode to set.
      password: The password for the WiFi network. By default, a random password
        will be set.
      ciphers: A set of cipher suites (encryption algorithms) for pairwise keys
        (unicast packets) for WPA.
      ciphers2: A set of cipher suites (encryption algorithms) for pairwise keys
        (unicast packets) for RSN/WPA2.
      key_mgmt: A set of key management algorithms to be used.
    """
    self._mode = mode
    self._password = password or _generate_wifi_password()
    self._ciphers = ciphers or frozenset()
    self._ciphers2 = ciphers2 or frozenset()
    self._key_mgmt = key_mgmt or frozenset()
    self._validate()

  def _validate(self):
    """Validates the configurations are valid."""
    if self._mode not in _MODES_USED_WPA and self._ciphers:
      raise errors.ConfigError(
          f'ciphers cannot be specified for the mode {self._mode} that is not'
          ' using WPA1.'
      )

    if self._mode not in _MODES_USED_WPA2 and self._ciphers2:
      raise errors.ConfigError(
          f'ciphers2 cannot be specified for the mode {self._mode} that is not'
          ' using WPA2/RSN.'
      )

    if len(self._password) == _HEX_PASSWORD_LEN:
      # Password is in the form of hex string.
      if not utils.is_hex_string(self._password):
        raise errors.ConfigError(
            f'The password of length {_HEX_PASSWORD_LEN} must be a valid hex'
            f' string, got {self._password}'
        )
    else:
      # Password is in the form of ascii string.
      if not (
          _MIN_ASCII_PASSWORD_LEN
          <= len(self._password)
          <= _MAX_ASCII_PASSWORD_LEN
      ):
        raise errors.ConfigError(
            'The length of password must be in range'
            f' [{_MIN_ASCII_PASSWORD_LEN}, {_MAX_ASCII_PASSWORD_LEN}], got'
            f' {len(self._password)}'
        )

      if not self._password.isascii():
        raise errors.ConfigError(
            f'The password of length {len(self._password)} must be a valid'
            f' ascii string, got {self._password}'
        )

  def update_hostapd_conf(self, hostapd_conf):
    """See docstring of base class."""
    mode_raw = 0
    if self._mode in _MODES_USED_WPA:
      mode_raw |= 1
    if self._mode in _MODES_USED_WPA2:
      mode_raw |= 2
    hostapd_conf.update('wpa', str(mode_raw))

    key_mgmt = self._key_mgmt
    if not key_mgmt:
      key_mgmt = set()
      # Include the minimum required key management algorithms.
      if self._mode != Mode.PURE_WPA3:
        key_mgmt.add(KeyMgmt.WPA_PSK.value)
      if self._mode in _MODES_USED_WPA3:
        key_mgmt.add(KeyMgmt.SAE.value)
    hostapd_conf.update('wpa_key_mgmt', ' '.join(key_mgmt))

    hostapd_conf.set_password(self._password)
    if len(self._password) == _HEX_PASSWORD_LEN:
      hostapd_conf.update('wpa_psk', self._password)
    else:
      hostapd_conf.update('wpa_passphrase', self._password)

    if self._ciphers:
      hostapd_conf.update('wpa_pairwise', ' '.join(self._ciphers))

    if self._ciphers2:
      hostapd_conf.update('rsn_pairwise', ' '.join(self._ciphers2))


def gen_config_for_wpa2_ccmp() -> Wpa:
  """Generates a WPA2 configuration object with default settings."""
  return Wpa(
      mode=Mode.PURE_WPA2,
      password=None,
      ciphers2={Cipher.CCMP},
      key_mgmt={KeyMgmt.WPA_PSK},
  )
