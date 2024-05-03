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

"""Configurations for the encryption mode WEP."""

import enum
import random
import string

from mobly.controllers.wifi.lib import errors
from mobly.controllers.wifi.lib import utils
from mobly.controllers.wifi.lib.encryption import base_encryption_config

# Length for valid WEP keys.
# Length for valid WEP keys in the form of ascii strings.
_ASCII_KEY_STRING_LENGTH = (5, 13, 16)

# Length for valid WEP keys in the form of hex strings.
_HEX_KEY_STRING_LENGTH = (10, 26, 32)


@enum.unique
class AuthAlgs(enum.IntEnum):
  """Enum for the authentication algorithms.

  This corresponds the hostapd configuration field `auth_algs`.
  """

  # Open System Authentication.
  OPEN = 1

  # Shared Key Authentication.
  SHARED = 2


def _gen_random_wep104_key() -> str:
  """Generates a random 104-bit WEP key in the form of hex string."""
  # length: 104 bits / 4 bits per hex digit = 26
  return ''.join(random.choice(string.hexdigits) for _ in range(26))


class Wep(base_encryption_config.BaseEncryptionConfig):
  """The configuration class for the WEP encryption type."""

  _auth_algs: AuthAlgs
  _keys: list[str]
  _default_key: int
  _password: str | None = None

  def __init__(
      self,
      auth_algs: AuthAlgs = AuthAlgs.OPEN,
      keys: list[str] | None = None,
      default_key: int = 0,
  ):
    """Constructor.

    If no key is speicified, a random 104-bit key will be used.

    Args:
      auth_algs: The authentication algorithm to use.
      keys: All WEP keys to use, which should be at most 4 keys.
      default_key: The key index to use. The corresponding key must be provided
        in the argument `keys`.
    """
    self._auth_algs = auth_algs
    self._default_key = default_key
    if default_key == 0 and keys is None:
      # Generate a wep104 key as default.
      self._keys = [_gen_random_wep104_key()]
    else:
      self._keys = keys or []
    self._password = None
    self._validate()

  def _validate(self):
    """Validates the configurations are valid."""
    if len(self._keys) > 4:
      raise errors.ConfigError(
          'At most 4 keys can be set for WEP encryption type, got'
          f' {len(self._keys)} keys.'
      )

    if self._default_key >= len(self._keys) or self._default_key < 0:
      raise errors.ConfigError(
          f'Default key index {self._default_key} out of range'
          f' [0, {len(self._keys) - 1}].'
      )

    for key in self._keys:
      self._validate_key(key)

    if self._auth_algs == AuthAlgs.SHARED:
      self._password = self._keys[self._default_key]
    else:
      self._password = None

  def _validate_key(self, key: str):
    if len(key) in _HEX_KEY_STRING_LENGTH:
      if not utils.is_hex_string(key):
        raise errors.ConfigError(
            'WEP encryption key with length 10, 26, or 32 should only contain'
            f' hexadecimal digits: {key}'
        )
      return

    if len(key) in _ASCII_KEY_STRING_LENGTH:
      if not key.isascii():
        raise errors.ConfigError(
            f'WEP encryption key with length {len(key)} should only contain'
            f' ascii chars: {key}'
        )
      return

    raise errors.ConfigError(
        f'Got invalid WEP encryption key length: {len(key)}'
    )

  def update_hostapd_conf(self, hostapd_conf):
    """See docstring of base class."""
    hostapd_conf.set_password(self._password)
    hostapd_conf.update('auth_algs', str(self._auth_algs.value))
    hostapd_conf.update('wep_default_key', str(self._default_key))
    for i, key in enumerate(self._keys):
      hostapd_conf.update(f'wep_key{i}', self._format_key(key))

  def _format_key(self, key: str) -> str:
    """Formats keys according to the hostapd configuration requirements."""
    if len(key) in _ASCII_KEY_STRING_LENGTH:
      # When using the ASCII string format, keys must be surrounded by quotes.
      return f'"{key}"'
    return key
