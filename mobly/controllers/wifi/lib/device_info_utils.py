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

"""Utilities to extract OpenWrt device information."""

from collections.abc import Mapping
import json
from typing import Any

from mobly.controllers.wifi.lib import constants

OpenWrtDevice = Any


def get_device_info(device: 'OpenWrtDevice') -> Mapping[str, str]:
  """Gets OpenWrt device information."""
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
  return device_info


def _get_info_from_custom_image_build_process(
    device: 'OpenWrtDevice',
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
  device_info = {}
  device_info['build_profile'] = custom_info.get('standardBuildConfig', {}).get(
      'buildProfile', ''
  )
  device_info['device_name'] = custom_info.get('standardBuildConfig', {}).get(
      'deviceName', ''
  )
  device_info['image_uuid'] = custom_info.get('imageUuid', '')
  device_info['build_time'] = custom_info.get('buildTime', '')
  device_info['custom_image_name'] = custom_info.get('customImageName', '')
  device_info['router_features'] = ','.join(
      custom_info.get('routerFeatures', '')
  )
  return device_info
