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

"""Config for TTLS/PEAP protected network."""

from mobly.controllers.wifi.lib.encryption import certificate
from mobly.controllers.wifi.lib.encryption import wpa
from mobly.controllers.wifi.lib.encryption import wpa_eap

# Outer (layer1) and inner (layer2) protocols.
_TTLS_PREFIX = "TTLS-"

LAYER1_TYPE_PEAP = "PEAP"
LAYER1_TYPE_TTLS = "TTLS"

LAYER2_TYPE_GTC = "GTC"
LAYER2_TYPE_MSCHAPV2 = "MSCHAPV2"
LAYER2_TYPE_MD5 = "MD5"
LAYER2_TYPE_TTLS_MSCHAPV2 = _TTLS_PREFIX + "MSCHAPV2"
LAYER2_TYPE_TTLS_MSCHAP = _TTLS_PREFIX + "MSCHAP"
LAYER2_TYPE_TTLS_PAP = _TTLS_PREFIX + "PAP"

# Marker used in server EAP users configuration for Phase 2 authentication.
PHASE2_AUTH_MARKER = 2


class Tunneled1x(wpa_eap.WpaEap):
  """Config for TTLS/PEAP protected network."""

  def __init__(
      self,
      cert_data: certificate.CertificatesData,
      wpa_mode: wpa.Mode = wpa.Mode.PURE_WPA,
      ft_mode: wpa.FtMode = wpa.FtMode.NONE,
  ):
    super().__init__(cert_data=cert_data, wpa_mode=wpa_mode, ft_mode=ft_mode)

  @classmethod
  def generate_eap_users_content(
      cls,
      identity: str,
      password: str,
      outer_protocol: str,
      inner_protocol: str,
  ) -> str:
    """Generates the content for eap_user_file."""
    return (
        f"* {outer_protocol}\n"
        f'"{identity}"'
        f' {inner_protocol} "{password}"'
        f" [{PHASE2_AUTH_MARKER}]"
    )
