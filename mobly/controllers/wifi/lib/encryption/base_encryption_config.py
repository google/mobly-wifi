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

"""The module for encryption configuration base."""

import abc

from mobly.controllers.wifi.lib.encryption import constants
from mobly.controllers.wifi.lib.encryption import uci_encryptions


class BaseEncryptionConfig(abc.ABC):
  """Base class for encryption config objects."""

  @abc.abstractmethod
  def get_uci_encryption_config(self) -> uci_encryptions.UciEncryptionConfig:
    """Returns the UCI encryption config.

    Returns:
      The UCI encryption config.
    """

  @abc.abstractmethod
  def validate(self) -> None:
    """Validates the encryption config."""

  @abc.abstractmethod
  def update_hostapd_conf(self, hostapd_conf):
    """Writes the encryption configs into the hostapd config object."""

  def get_ft_key_mgmt(self) -> set[constants.KeyMgmt]:
    """Returns the FT (Fast Transition) key management suites.

    Returns:
      A set of KeyMgmt values for Fast Transition, empty if not supported.
    """
    return set()

  @property
  def password(self) -> str | None:
    """Returns the password for the encryption config."""
    return None
