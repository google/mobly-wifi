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

"""Errors for the AP controller module."""


class BaseError(Exception):
  """Base error class for this controller module."""


class ConfigError(BaseError):
  """Configuration error."""


class HostapdStartError(BaseError):
  """Raised if it failed to start hostapd on the AP device."""


class SnifferManagerError(BaseError):
  """Raised if some failure related to sniffer manager happened."""


class SystemLogServiceError(BaseError):
  """Root error type for system log service."""

  def __init__(self, device, msg):
    new_msg = f'{repr(device)}::Service<SystemLog> {msg}'
    super().__init__(new_msg)
