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

"""Wi-Fi SSID data structures and encoding/decoding utilities."""

from __future__ import annotations

import re

# Mapping of escaped character sequences to byte values
_ESCAPE_MAP = {
    b'\\': b'\\',
    b'"': b'"',
    b'e': b'\x1b',
    b'n': b'\n',
    b'r': b'\r',
    b't': b'\t',
}

# Reverse mapping for common control characters
_ENCODE_MAP = {
    ord('\\'): '\\\\',
    ord('"'): '\\"',
    0x1B: '\\e',
    ord('\n'): '\\n',
    ord('\r'): '\\r',
    ord('\t'): '\\t',
}

_DECODE_PATTERN = re.compile(rb'\\(x[0-9a-fA-F]{2}|[\\"enrt]|.|$)|([^\\]+)')


def is_printf_encoded_ssid(ssid: str | None) -> bool:
  r"""Returns True if the SSID is in printf-escaped format P\"...\"."""
  return (
      ssid is not None
      and len(ssid) >= 3
      and ssid.startswith('P"')
      and ssid.endswith('"')
  )


def encode_printf_ssid(raw_ssid: str | bytes | SSID) -> str:
  r"""Encodes an SSID into hostapd printf format: P\"...\"."""
  if isinstance(raw_ssid, SSID):
    raw_bytes = raw_ssid.raw_bytes
  elif isinstance(raw_ssid, bytes):
    raw_bytes = raw_ssid
  elif isinstance(raw_ssid, str):
    try:
      raw_bytes = raw_ssid.encode('latin-1')
    except UnicodeEncodeError:
      raw_bytes = raw_ssid.encode('utf-8')
  else:
    raw_bytes = bytes(raw_ssid)
  parts = ['P"']

  for b in raw_bytes:
    if b in _ENCODE_MAP:
      parts.append(_ENCODE_MAP[b])
    elif 32 <= b <= 126:
      parts.append(chr(b))
    else:
      parts.append(f'\\x{b:02x}')

  parts.append('"')
  return ''.join(parts)


def _unescape_bytes(content_bytes: bytes) -> bytes:
  """Unescapes a bytes string with printf-style escape sequences."""
  decoded_bytes = bytearray()
  for match in _DECODE_PATTERN.finditer(content_bytes):
    escape_seq, literal = match.groups()
    if literal:
      decoded_bytes.extend(literal)
    elif escape_seq is not None:
      if escape_seq.startswith(b'x') and len(escape_seq) == 3:
        decoded_bytes.append(int(escape_seq[1:], 16))
      elif escape_seq in _ESCAPE_MAP:
        decoded_bytes.extend(_ESCAPE_MAP[escape_seq])
      else:
        # Unrecognized escape or trailing backslash: preserve backslash and char
        decoded_bytes.append(ord('\\'))
        decoded_bytes.extend(escape_seq)
  return bytes(decoded_bytes)


def _decode_bytes_escaped(content_bytes: bytes) -> str:
  raw = _unescape_bytes(content_bytes)
  try:
    return raw.decode('utf-8')
  except UnicodeDecodeError:
    return raw.decode('latin-1')


def decode_printf_ssid(ssid: str | None) -> str | None:
  r"""Decodes a printf-escaped SSID (P\"...\"), quoted SSID, or iw-escaped SSID into a string."""
  if ssid is None:
    return None

  if is_printf_encoded_ssid(ssid):
    return _decode_bytes_escaped(ssid[2:-1].encode('latin-1'))

  if len(ssid) >= 2 and ssid.startswith('"') and ssid.endswith('"'):
    return _decode_bytes_escaped(ssid[1:-1].encode('latin-1'))

  if '\\' in ssid:
    return _decode_bytes_escaped(ssid.encode('latin-1'))

  return ssid


decode_ssid = decode_printf_ssid


def needs_printf_encoding(ssid: str | None) -> bool:
  """Returns True if the SSID contains characters requiring printf encoding."""
  if ssid is None or is_printf_encoded_ssid(ssid):
    return False
  for char in ssid:
    if char == '\\' or char == '"' or not (32 <= ord(char) <= 126):
      return True
  return False


def _normalize_ssid_input(
    value: str | bytes | SSID,
) -> tuple[str, bytes, bool]:
  """Normalizes any SSID-compatible input into (decoded_str, raw_bytes, is_hex)."""
  if isinstance(value, SSID):
    return str(value), value.raw_bytes, value.is_hex

  if isinstance(value, bytes):
    try:
      decoded = value.decode('utf-8')
    except UnicodeDecodeError:
      decoded = value.decode('latin-1')
    is_hex = any(
        c in ('\\', '"', "'") or not (32 <= ord(c) <= 126) for c in decoded
    )
    return decoded, value, is_hex

  if is_printf_encoded_ssid(value):
    raw = _unescape_bytes(value[2:-1].encode('latin-1'))
    try:
      decoded = raw.decode('utf-8')
    except UnicodeDecodeError:
      decoded = raw.decode('latin-1')
    is_hex = True
    return decoded, raw, is_hex

  decoded = value
  try:
    raw = decoded.encode('latin-1')
  except UnicodeEncodeError:
    raw = decoded.encode('utf-8')

  is_hex = any(
      c in ('\\', '"', "'") or not (32 <= ord(c) <= 126) for c in decoded
  )
  return decoded, raw, is_hex


class SSID(str):
  """Represents a Wi-Fi SSID with clean representation and encoding properties."""

  _raw_bytes: bytes
  _is_hex: bool

  def __new__(
      cls,
      value: str | bytes | SSID,
      is_hex: bool | None = None,
  ) -> SSID:
    decoded_str, raw_bytes, detected_is_hex = _normalize_ssid_input(value)
    obj = super().__new__(cls, decoded_str)
    obj._raw_bytes = raw_bytes
    obj._is_hex = is_hex if is_hex is not None else detected_is_hex
    return obj

  @classmethod
  def from_hex(cls, hex_str: str) -> SSID:
    """Constructs an SSID from a hex string."""
    return cls(bytes.fromhex(hex_str), is_hex=True)

  @property
  def raw_bytes(self) -> bytes:
    """Raw byte representation of the SSID."""
    return self._raw_bytes

  @property
  def hex(self) -> str:
    """Hexadecimal string representation."""
    return self._raw_bytes.hex()

  @property
  def is_hex(self) -> bool:
    """True if hex encoding should be used for UCI configuration."""
    return self._is_hex

  def __repr__(self) -> str:
    return f'SSID({str(self)!r})'
