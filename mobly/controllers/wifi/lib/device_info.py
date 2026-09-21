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

"""DeviceInfo class for OpenWrt devices."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
import json
from typing import Any

from mobly.controllers.wifi.lib import constants


def _get_info_from_custom_image_build_process(
    device: Any,
) -> Mapping[str, str]:
  """Gets device info recorded by the custom image build process."""
  custom_info_str = device.ssh.execute_command(
      command=f'cat {constants.CURSTOM_RELEASE_INFO_FILE_PATH}',
      timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
      ignore_error=True,
  )
  if not custom_info_str:
    return {}

  custom_info = json.loads(custom_info_str)
  device_info = {
      'build_profile': (
          custom_info.get('standardBuildConfig', {}).get('buildProfile', '')
      ),
      'device_name': (
          custom_info.get('standardBuildConfig', {}).get('deviceName', '')
      ),
      'image_uuid': custom_info.get('imageUuid', ''),
      'build_time': custom_info.get('buildTime', ''),
      'custom_image_name': custom_info.get('customImageName', ''),
      'router_features': ','.join(custom_info.get('routerFeatures', '')),
  }
  return device_info


class DeviceInfo(Mapping[str, str]):
  """OpenWrt device information.

  It behaves like a read-only dictionary but also provides convenient properties
  to reduce code duplication.
  """

  def __init__(self, data: Mapping[str, str]):
    """Initializes the DeviceInfo object.

    Args:
      data: A mapping containing the device information.
    """
    self._data = dict(data)

  def __getitem__(self, key: str) -> str:
    return self._data[key]

  def __iter__(self) -> Iterator[str]:
    return iter(self._data)

  def __len__(self) -> int:
    return len(self._data)

  def __repr__(self) -> str:
    return f'DeviceInfo({self._data})'

  def to_dict(self) -> Mapping[str, str]:
    """Returns the device info as a read-only dictionary."""
    return dict(self._data)

  @property
  def is_cros_image(self) -> bool:
    """True if the image is builded with cros_openwrt_image_builder."""
    return bool(self._data.get('image_uuid'))

  @property
  def is_snapshot(self) -> bool:
    """Returns True if the image is built against SNAPSHOT."""
    return constants.VERSION_SNAPSHOT in self.release

  @property
  def device_name(self) -> str:
    """Returns the device name."""
    return self._data.get('device_name', '')

  @property
  def release(self) -> str:
    """Returns the release version."""
    return self._data.get('release', '')

  @classmethod
  def from_device(cls, device: Any) -> DeviceInfo:
    """Fetches device info from the device and returns a DeviceInfo instance."""
    device_info = {'serial': device.serial}

    # Get info from the official release info file.
    openwrt_release = device.ssh.execute_command(
        command=f'cat {constants.OPENWRT_RELEASE_INFO_FILE_PATH}',
        timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
        ignore_error=True,
    )
    match = constants.DEVICE_INFO_PATTERN.fullmatch(openwrt_release)
    if match is not None:
      device_info.update(match.groupdict())

    # Get info from the info file created by the custom image build process.
    device_info.update(_get_info_from_custom_image_build_process(device))

    return cls(device_info)
