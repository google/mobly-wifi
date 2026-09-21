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

"""Certificate dataclasses for WPA-EAP."""

import dataclasses
import pathlib


@dataclasses.dataclass
class Certificate:
  """Certificates content to be installed on the router."""

  ca_cert: str
  cert: str
  private_key: str
  eap_users: str | None = "* TLS"


@dataclasses.dataclass(frozen=True)
class CertificatesData:
  """Paths to the installed certificates on the router."""

  ca_cert_file: pathlib.PurePosixPath
  cert_file: pathlib.PurePosixPath
  key_file: pathlib.PurePosixPath
  eap_user_file: pathlib.PurePosixPath | None
  suffix: str
