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

"""WPA-EAP security configuration for Mobly WiFi tests.

This is a Python adaptation of the Go package wpaeap,
designed for configuring Wi-Fi access points with WPA-EAP security
for Mobly tests.
"""

from typing import override

import immutabledict

from mobly.controllers.wifi.lib import errors
from mobly.controllers.wifi.lib import hostapd_manager
from mobly.controllers.wifi.lib.encryption import certificate
from mobly.controllers.wifi.lib.encryption import uci_encryptions
from mobly.controllers.wifi.lib.encryption import wpa

_UCI_ENCRYPTION_BY_WPA_MODE = immutabledict.immutabledict({
    wpa.Mode.PURE_WPA: uci_encryptions.Encryption.WPA,
    wpa.Mode.PURE_WPA2: uci_encryptions.Encryption.WPA2,
    wpa.Mode.PURE_WPA3: uci_encryptions.Encryption.WPA3,
    wpa.Mode.PURE_WPA3_EXT: uci_encryptions.Encryption.WPA3,
    wpa.Mode.MIXED: uci_encryptions.Encryption.WPA_MIXED,
    wpa.Mode.MIXED_WPA3: uci_encryptions.Encryption.WPA3_MIXED,
    wpa.Mode.ALL: uci_encryptions.Encryption.WPA3_MIXED,
    wpa.Mode.MIXED_WPA3_EXT: uci_encryptions.Encryption.WPA3_MIXED,
})


class WpaEap(wpa.WpaCommon):
  """WPA-EAP security configuration.

  Attributes:
    cert_data: The certificates data containing paths on the router.
    wpa_mode: WPA mode (WPA, WPA2, WPA3, or mixed).
    ft_mode: 802.11r Fast Transition mode.
    suite_b_192: Whether to use Suite B 192-bit security.
  """
  cert_data: certificate.CertificatesData
  wpa_mode: wpa.Mode
  ft_mode: wpa.FtMode
  suite_b_192: bool

  def __init__(
      self,
      cert_data: certificate.CertificatesData,
      wpa_mode: wpa.Mode = wpa.Mode.PURE_WPA,
      ft_mode: wpa.FtMode = wpa.FtMode.NONE,
      suite_b_192: bool = False,
  ):
    """Initializes WpaEap.

    Args:
      cert_data: The certificates data containing paths on the router.
      wpa_mode: WPA mode (WPA, WPA2, WPA3, or mixed).
      ft_mode: 802.11r Fast Transition mode.
      suite_b_192: Whether to use Suite B 192-bit security.
    """
    ciphers = set()
    if wpa_mode & wpa.Mode.PURE_WPA:
      ciphers.add(wpa.Cipher.TKIP)
    ciphers2 = set()
    if wpa_mode & (wpa.Mode.PURE_WPA2 | wpa.Mode.PURE_WPA3):
      ciphers2.add(wpa.Cipher.CCMP)
    if suite_b_192:
      if wpa_mode != wpa.Mode.PURE_WPA3:
        raise errors.ConfigError(
            f'Suite B 192-bit security requires wpa_mode to be '
            f'{wpa.Mode.PURE_WPA3}, but got {wpa_mode}'
        )
      ciphers = set()
      ciphers2 = {wpa.Cipher.GCMP256}

    self.cert_data = cert_data
    self.wpa_mode = wpa_mode
    self.ft_mode = ft_mode
    self.suite_b_192 = suite_b_192

    super().__init__(
        mode=wpa_mode,
        ciphers=ciphers,
        ciphers2=ciphers2,
        ft_mode=ft_mode,
        is_enterprise=True,
    )

  @override
  def _get_enterprise_key_mgmt(self) -> set[wpa.KeyMgmt]:
    """Returns the minimum required key management algorithms for enterprise.

    This method overrides the behavior to return WPA_EAP_SUITE_B_192
    if Suite B 192-bit security is enabled. Otherwise, it defers to the
    superclass implementation.
    """
    if self.suite_b_192:
      return {wpa.KeyMgmt.WPA_EAP_SUITE_B_192}
    return super()._get_enterprise_key_mgmt()

  @override
  def validate(self):
    """Validates WPA-EAP specific configuration."""
    super().validate()

    if not self.wpa_mode:
      raise errors.ConfigError(f'Invalid wpa_mode: {self.wpa_mode}')
    if not self.ft_mode:
      raise errors.ConfigError(f'Invalid ft_mode: {self.ft_mode}')

  def update_hostapd_conf(
      self, hostapd_conf: hostapd_manager.HostapdConfig
  ) -> None:
    """Updates and returns hostapd config dictionary for WPA-EAP network.

    Args:
      hostapd_conf: The hostapd config object to be updated in-place.
    """
    hostapd_conf.set_password(None)
    hostapd_conf.update('ieee8021x', '1')
    hostapd_conf.update('eap_server', '1')
    hostapd_conf.update('ca_cert', str(self.cert_data.ca_cert_file))
    hostapd_conf.update('server_cert', str(self.cert_data.cert_file))
    hostapd_conf.update('private_key', str(self.cert_data.key_file))
    if self.cert_data.eap_user_file:
      hostapd_conf.update('eap_user_file', str(self.cert_data.eap_user_file))
    if self.suite_b_192:
      hostapd_conf.update('group_mgmt_cipher', 'BIP-GMAC-256')

    super().update_hostapd_conf(hostapd_conf)

  def get_uci_encryption_config(self) -> uci_encryptions.UciEncryptionConfig:
    """Returns the UCI encryption config."""
    if self.suite_b_192:
      encryption = uci_encryptions.Encryption.WPA3_192
    else:
      encryption = _UCI_ENCRYPTION_BY_WPA_MODE.get(
          self.wpa_mode, uci_encryptions.Encryption.WPA_MIXED
      )

    extra_params = {
        'ieee8021x': '1',
        'eap_server': '1',
        'ca_cert': str(self.cert_data.ca_cert_file),
        'server_cert': str(self.cert_data.cert_file),
        'private_key': str(self.cert_data.key_file),
        'eap_user_file': (
            str(self.cert_data.eap_user_file)
            if self.cert_data.eap_user_file
            else ''
        ),
    }

    return uci_encryptions.UciEncryptionConfig(
        encryption=encryption,
        ieee80211w=self._get_required_pmf(),
        extra_uci_params=extra_params,
        ciphers=self._ciphers | self._ciphers2,
    )
