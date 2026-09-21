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

"""Constants for WPA encryption configurations."""

import enum


@enum.unique
class Cipher(enum.StrEnum):
  """Enum for WPA cipher suites for pairwise keys."""

  TKIP = 'TKIP'  # Temporal Key Integrity Protocol
  CCMP = 'CCMP'  # AES in Counter mode with CBC-MAC (CCMP-128)
  CCMP256 = 'CCMP-256'  # AES in Counter mode with CBC-MAC (CCMP-256)
  GCMP = 'GCMP'  # Galois/Counter Mode Protocol (GCMP-128)
  GCMP256 = 'GCMP-256'  # Galois/Counter Mode Protocol (GCMP-256)


@enum.unique
class KeyMgmt(enum.StrEnum):
  """Enum for WPA key management algorithms."""

  WPA_PSK = 'WPA-PSK'  # WPA-Personal / WPA2-Personal
  WPA_PSK_SHA256 = 'WPA-PSK-SHA256'  # WPA2-Personal using SHA256
  SAE = 'SAE'  # WPA3-Personal
  FT_SAE = 'FT-SAE'  # Fast Transition SAE
  SAE_EXT_KEY = 'SAE-EXT-KEY'  # WPA3-SAE-EXT
  FT_PSK = 'FT-PSK'  # Fast Transition PSK
  WPA_EAP = 'WPA-EAP'  # WPA-Enterprise
  WPA_EAP_SHA256 = 'WPA-EAP-SHA256'  # WPA-Enterprise using SHA256
  FT_EAP_SHA384 = 'FT-EAP-SHA384'  # Fast Transition EAP using SHA384
  FT_EAP = 'FT-EAP'  # Fast Transition EAP
  OWE = 'OWE'  # Opportunistic Wireless Encryption
  WPA_EAP_SUITE_B_192 = 'WPA-EAP-SUITE-B-192'  # WPA3-Enterprise 192-bit


@enum.unique
class Mode(enum.IntFlag):
  """Enum for WPA modes."""

  PURE_WPA = 1
  PURE_WPA2 = 2
  PURE_WPA3 = 4
  PURE_WPA3_EXT = 8
  MIXED = PURE_WPA | PURE_WPA2
  MIXED_WPA3 = PURE_WPA2 | PURE_WPA3
  ALL = PURE_WPA | PURE_WPA2 | PURE_WPA3
  MIXED_WPA3_EXT = PURE_WPA2 | PURE_WPA3 | PURE_WPA3_EXT


@enum.unique
class FtMode(enum.IntFlag):
  """802.11r Fast BSS Transition modes."""

  NONE = 1
  PURE = 2
  MIXED = NONE | PURE
