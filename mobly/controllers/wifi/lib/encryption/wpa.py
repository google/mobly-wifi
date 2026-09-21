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

from typing import override

from mobly import utils as mobly_utils

from mobly.controllers.wifi.lib import errors
from mobly.controllers.wifi.lib import utils
from mobly.controllers.wifi.lib.encryption import base_encryption_config
from mobly.controllers.wifi.lib.encryption import constants
from mobly.controllers.wifi.lib.encryption import uci_encryptions


_MIN_ASCII_PASSWORD_LEN = 8
_MAX_ASCII_PASSWORD_LEN = 63
_HEX_PASSWORD_LEN = 64

Mode = constants.Mode
KeyMgmt = constants.KeyMgmt
Cipher = constants.Cipher
FtMode = constants.FtMode

_FT_KEY_MGMT_MAP = {
    KeyMgmt.WPA_PSK: KeyMgmt.FT_PSK,
    KeyMgmt.SAE: KeyMgmt.FT_SAE,
    KeyMgmt.WPA_EAP: KeyMgmt.FT_EAP,
    KeyMgmt.WPA_EAP_SHA256: KeyMgmt.FT_EAP_SHA384,
}


def _generate_wifi_password():
  """Generates a wifi password with a random substring."""
  random_str = mobly_utils.rand_ascii_str(5)
  return f'RandomPSK-{random_str}'


class WpaCommon(base_encryption_config.BaseEncryptionConfig):
  """Common configurations for WPA encryption modes."""

  _mode: Mode
  _key_mgmt: set[KeyMgmt]
  _ciphers: set[Cipher]  # ciphers used for WPA
  _ciphers2: set[Cipher]  # ciphers used for WPA2
  _ft_mode: FtMode

  def __init__(
      self,
      mode: Mode = Mode.PURE_WPA2,
      ciphers: set[Cipher] | None = None,
      ciphers2: set[Cipher] | None = None,
      key_mgmt: set[KeyMgmt] | None = None,
      ft_mode: FtMode = FtMode.NONE,
      is_enterprise: bool = False,
  ):
    self._mode = mode
    self._ciphers = ciphers or set()
    self._ciphers2 = ciphers2 or set()
    self._key_mgmt = key_mgmt or set()
    self._ft_mode = ft_mode
    self._update_key_mgmt_to_minimum_required(is_enterprise=is_enterprise)
    self.validate()

  @override
  def validate(self) -> None:
    """Validates the configurations are valid."""
    if not (self._mode & Mode.PURE_WPA) and self._ciphers:
      raise errors.ConfigError(
          f'ciphers cannot be specified for the mode {self._mode} that is not'
          ' using WPA1.'
      )

    if (
        not (
            self._mode & (Mode.PURE_WPA2 | Mode.PURE_WPA3 | Mode.PURE_WPA3_EXT)
        )
        and self._ciphers2
    ):
      raise errors.ConfigError(
          f'ciphers2 cannot be specified for the mode {self._mode} that is not'
          ' using WPA2/RSN.'
      )

  def _update_key_mgmt_to_minimum_required(
      self, is_enterprise: bool = False
  ) -> None:
    """Updates the key management set to the minimum required set."""
    if not self._key_mgmt:
      if is_enterprise:
        self._key_mgmt = self._get_enterprise_key_mgmt()
      else:
        self._key_mgmt = self._get_personal_key_mgmt()

  def _get_enterprise_key_mgmt(self) -> set[KeyMgmt]:
    """Returns the minimum required key management algorithms for enterprise."""
    key_mgmt = set()
    if self._ft_mode & FtMode.NONE:
      if self._mode & (Mode.PURE_WPA | Mode.PURE_WPA2):
        key_mgmt.add(KeyMgmt.WPA_EAP)
      if self._mode & Mode.PURE_WPA3:
        key_mgmt.add(KeyMgmt.WPA_EAP_SHA256)
    if self._ft_mode & FtMode.PURE:
      key_mgmt.add(KeyMgmt.FT_EAP)
    return key_mgmt

  def _get_personal_key_mgmt(self) -> set[KeyMgmt]:
    """Returns the minimum required key management algorithms for personal."""
    key_mgmt = set()
    if self._mode != Mode.PURE_WPA3 and self._mode != Mode.PURE_WPA3_EXT:
      key_mgmt.add(KeyMgmt.WPA_PSK)
    if self._mode & (Mode.PURE_WPA3 | Mode.PURE_WPA3_EXT):
      key_mgmt.add(KeyMgmt.SAE)
    if self._mode & Mode.PURE_WPA3_EXT:
      key_mgmt.add(KeyMgmt.SAE_EXT_KEY)
    if self._ft_mode & FtMode.PURE:
      key_mgmt.add(KeyMgmt.FT_PSK)
    return key_mgmt

  def _get_required_pmf(self) -> int:
    """Returns the value of ieee80211w.

    This method must be called after `self._mode` and `self._key_mgmt` are
    initialized.

    Returns:
      The recommended value for the 'ieee80211w' (PMF) setting in hostapd
      configuration, based on the current WPA mode and key management settings.
      - 0: PMF disabled
      - 1: PMF optional
      - 2: PMF required
    """
    # PMF is required to be at least 2 for SAE, WPA_PSK_SHA256,
    # WPA_EAP_SHA256, or OWE.
    if (
        KeyMgmt.SAE in self._key_mgmt
        or KeyMgmt.WPA_PSK_SHA256 in self._key_mgmt
        or KeyMgmt.WPA_EAP_SHA256 in self._key_mgmt
        or KeyMgmt.OWE in self._key_mgmt
        or KeyMgmt.WPA_EAP_SUITE_B_192 in self._key_mgmt
    ):
      if KeyMgmt.WPA_PSK in self._key_mgmt or KeyMgmt.WPA_EAP in self._key_mgmt:
        # WFA recommends PMF to be set to 1 (Optional) for WPA2/WPA3 mixed mode.
        return 1
      return 2
    return 0

  @override
  def get_ft_key_mgmt(self) -> set[KeyMgmt]:
    """Returns the FT key management suites corresponding to configured key_mgmt."""
    ft_key_mgmt = set()
    for km in self._key_mgmt:
      if km in _FT_KEY_MGMT_MAP:
        ft_key_mgmt.add(_FT_KEY_MGMT_MAP[km])
      elif km in _FT_KEY_MGMT_MAP.values():
        ft_key_mgmt.add(km)
    return ft_key_mgmt

  @override
  def update_hostapd_conf(self, hostapd_conf) -> None:
    """See docstring of base class.

    Args:
      hostapd_conf: The hostapd config object to update.

    Raises:
      errors.ConfigError: If given hostapd configuration is not compatible with
        this encryption configuration.
    """
    mode_raw = 0
    if self._mode & Mode.PURE_WPA:
      mode_raw |= 1
    if self._mode & (Mode.PURE_WPA2 | Mode.PURE_WPA3 | Mode.PURE_WPA3_EXT):
      mode_raw |= 2
    hostapd_conf.update('wpa', str(mode_raw))
    hostapd_conf.update('wpa_key_mgmt', ' '.join(sorted(self._key_mgmt)))

    pmf_needed = self._get_required_pmf()
    pmf = int(hostapd_conf.get('ieee80211w') or 0)

    # Check if the PMF is set to the minimum required value.
    if pmf < pmf_needed:
      raise errors.ConfigError(
          f'PMF must be set to at least {pmf_needed}, while it is set to {pmf}'
      )

    if self._ciphers:
      hostapd_conf.update('wpa_pairwise', ' '.join(self._ciphers))

    if self._ciphers2:
      hostapd_conf.update('rsn_pairwise', ' '.join(self._ciphers2))


class Wpa(WpaCommon):
  """Configurations for WPA encryption modes with password."""

  _password: str

  def __init__(
      self,
      mode: Mode = Mode.PURE_WPA2,
      password: str | None = None,
      ciphers: set[Cipher] | None = None,
      ciphers2: set[Cipher] | None = None,
      key_mgmt: set[KeyMgmt] | None = None,
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
    self._password = password or _generate_wifi_password()
    super().__init__(
        mode=mode, ciphers=ciphers, ciphers2=ciphers2, key_mgmt=key_mgmt
    )

  @override
  def validate(self) -> None:
    """Validates the configurations are valid."""

    super().validate()

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

  @override
  @property
  def password(self) -> str | None:
    """Returns the password for the encryption config."""
    return self._password

  @override
  def update_hostapd_conf(self, hostapd_conf) -> None:
    """See docstring of base class.

    Args:
      hostapd_conf: The hostapd config object to update.

    Raises:
      errors.ConfigError: If given hostapd configuration is not compatible with
        this encryption configuration.
    """
    super().update_hostapd_conf(hostapd_conf)

    hostapd_conf.set_password(self._password)
    if len(self._password) == _HEX_PASSWORD_LEN:
      hostapd_conf.update('wpa_psk', self._password)
    else:
      hostapd_conf.update('wpa_passphrase', self._password)

  # TODO: (internal) - Remove SAE_EXT_MIXED and SAE_EXT once sae_ext_key is
  # supported.
  @override
  def get_uci_encryption_config(self) -> uci_encryptions.UciEncryptionConfig:
    """Returns the UCI encryption config."""
    mode = self._mode
    if (mode & Mode.PURE_WPA3_EXT) and (mode & Mode.PURE_WPA2):
      encryption = uci_encryptions.Encryption.SAE_EXT_MIXED
    elif mode & Mode.PURE_WPA3_EXT:
      encryption = uci_encryptions.Encryption.SAE_EXT
    elif (mode & Mode.PURE_WPA3) and (mode & Mode.PURE_WPA2):
      encryption = uci_encryptions.Encryption.SAE_MIXED
    elif mode & Mode.PURE_WPA3:
      encryption = uci_encryptions.Encryption.SAE
    elif (mode & Mode.PURE_WPA2) and (mode & Mode.PURE_WPA):
      encryption = uci_encryptions.Encryption.PSK_MIXED
    elif mode & Mode.PURE_WPA2:
      encryption = uci_encryptions.Encryption.PSK2
    elif mode & Mode.PURE_WPA:
      encryption = uci_encryptions.Encryption.PSK
    else:
      encryption = uci_encryptions.Encryption.PSK

    return uci_encryptions.UciEncryptionConfig(
        encryption=encryption,
        key=self._password,
        ieee80211w=self._get_required_pmf(),
        ciphers=self._ciphers | self._ciphers2,
    )


def gen_config_for_wpa2_ccmp() -> Wpa:
  """Generates a WPA2 configuration object with default settings."""
  return Wpa(
      mode=Mode.PURE_WPA2,
      password=None,
      ciphers2={Cipher.CCMP},
      key_mgmt={KeyMgmt.WPA_PSK},
  )


def gen_config_for_wpa3_ccmp() -> Wpa:
  """Generates a WPA3-Personal configuration object with default settings."""
  return Wpa(
      mode=Mode.PURE_WPA3,
      password=None,
      ciphers2={Cipher.CCMP},
      key_mgmt={KeyMgmt.SAE},
  )
