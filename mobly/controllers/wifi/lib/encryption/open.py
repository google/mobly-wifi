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

"""Configurations for the encryption mode OPEN."""

from typing import override

from mobly.controllers.wifi.lib.encryption import base_encryption_config
from mobly.controllers.wifi.lib.encryption import uci_encryptions


class Open(base_encryption_config.BaseEncryptionConfig):
  """The configuration class for the encryption type OPEN."""

  @override
  def update_hostapd_conf(self, hostapd_conf):
    del self
    hostapd_conf.set_password(None)

  @override
  def validate(self) -> None:
    del self
    pass

  @override
  def get_uci_encryption_config(self) -> uci_encryptions.UciEncryptionConfig:
    """Returns the UCI encryption config."""
    del self
    return uci_encryptions.UciEncryptionConfig(
        encryption=uci_encryptions.Encryption.NONE,
    )
