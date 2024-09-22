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

"""Mobly controller module for local sniffer devices connected to lab host."""

from collections.abc import Mapping, Sequence
import logging
import os
from typing import Any

from mobly import logger as mobly_logger
from mobly import runtime_test_info
from mobly import utils

from mobly.controllers.wifi.lib import local_sniffer_manager
from mobly.controllers.wifi.lib import wifi_configs


MOBLY_CONTROLLER_CONFIG_NAME = 'LocalSnifferDevice'
_DEVICE_TAG = MOBLY_CONTROLLER_CONFIG_NAME


class Error(Exception):
  """Error class for the LocalSnifferDevice controller."""


def create(configs: list[dict[str, Any]]) -> list['LocalSnifferDevice']:
  """Creates local sniffer device instances.

  The configs come from Mobly configs that look like:

    ```config.yaml
    TestBeds:
    - Name: SampleTestBed
      Controllers:
        LocalSnifferDevice:
        - phy: 'phy2'
          model: 'ALFA AWUS036AXML'
    ```

  Each config should have the required key-value pair 'phy'. We recommend to
  include model info through key `model`.

  Args:
    configs: a list of dicts, each representing a configuration for a local
      sniffer device.

  Returns:
    A list of LocalSnifferDevice objects.

  Raises:
    Error: Raised if got invalid controller configs.
  """
  if not configs:
    raise Error(f'Missing configuration {configs!r}.')
  devices = [LocalSnifferDevice(config) for config in configs]
  return devices


def destroy(devices: list['LocalSnifferDevice']) -> None:
  """Closes all created local sniffer device instances."""
  for device in devices:
    try:
      device.teardown()
    except Exception:  # pylint: disable=broad-except
      logging.exception('Failed to clean up properly.')


def get_info(
    devices: Sequence['LocalSnifferDevice'],
) -> Sequence[Mapping[str, Any]]:
  """Gets info from the local sniffer device instances used in a test run.

  Args:
    devices: A list of local sniffer device instances.

  Returns:
    A list of dict, each representing info for a device object.
  """
  return [d.device_info for d in devices]


class LocalSnifferDevice:
  """Mobly controller for local sniffer devices connected to lab host.

  Attributes:
    serial: A string that identifies this local sniffer device.
    log_path: A string that is the path where all logs collected on this device
      should be stored.
    log: A logger adapted from root logger with an added prefix specific to a
      remote test machine. The prefix is "[LocalSnifferDevice|<self.serial>] ".
    device_info: A collection of device information.
  """

  def __init__(self, config: dict[str, Any]):
    if 'phy' not in config:
      raise Error(
          f'Missing required field "phy" in device configuration {config!r}.'
      )
    self._phy = config['phy']
    self._model = config.get('model', None)
    self._device_info = None
    self.serial = f'{self._phy}'

    log_path = getattr(logging, 'log_path', '/tmp/logs')
    log_filename = mobly_logger.sanitize_filename(
        f'{_DEVICE_TAG}_{self.serial}'
    )
    self.log_path = os.path.join(log_path, log_filename)
    utils.create_dir(self.log_path)
    self.log = mobly_logger.PrefixLoggerAdapter(
        logging.getLogger(),
        {
            mobly_logger.PrefixLoggerAdapter.EXTRA_KEY_LOG_PREFIX: (
                f'[{_DEVICE_TAG}|{self.serial}]'
            )
        },
    )
    self._sniffer_manager_obj = None

  def __repr__(self) -> str:
    return f'<{_DEVICE_TAG}|{self.serial}>'

  @property
  def device_info(self) -> Mapping[str, str]:
    """Information to be pulled into controller info in the test summary."""
    if self._device_info:
      return self._device_info
    self._device_info = {'phy': self._phy}
    if self._model is not None:
      self._device_info['model'] = self._model
    return self._device_info

  @property
  def _sniffer_manager(self):
    if self._sniffer_manager_obj is None:
      self._sniffer_manager_obj = local_sniffer_manager.LocalSnifferManager(
          self, self._phy
      )
    return self._sniffer_manager_obj

  def start_packet_capture(
      self,
      wifi_config: wifi_configs.WiFiConfig | None = None,
      freq_config: wifi_configs.FreqConfig | None = None,
      capture_config: wifi_configs.PcapConfig | None = None,
  ):
    """Starts pacaket capture on a specific frequency band.

    You need to provide either wifi_config or freq_config. If you provide
    `freq_config`, this will monitor the frequency band specified by it. If you
    provide `wifi_config`, this method will extract channel info from it and
    monitor the same channel that is used by the WiFi network.

    Args:
      wifi_config: The WiFi network to capture the packets.
      freq_config: The frequency to capture the packets.
      capture_config: The configuration to control the packet capture process.

    Raises:
      Error: Raised if the provided configurations are invaliad.
    """
    if (
        sum([
            wifi_config is not None,
            freq_config is not None,
        ])
        != 1
    ):
      raise Error(
          'You must provide either wifi_config or freq_config to start packet'
          f' capture, got wifi_config: "{wifi_config}", freq_config:'
          f' "{freq_config}".'
      )
    if wifi_config is not None:
      freq_config = wifi_configs.get_freq_config(wifi_config)
    self._sniffer_manager.start_capture(
        freq_config=freq_config, capture_config=capture_config
    )

  def stop_packet_capture(
      self, current_test_info: runtime_test_info.RuntimeTestInfo | None = None
  ):
    """Stops pacaket capture."""
    self._sniffer_manager.stop_capture(current_test_info=current_test_info)

  def get_capture_file(self) -> str | None:
    """Gets the full path of the last capture."""
    return self._sniffer_manager.get_capture_file()

  def teardown(self):
    """Tears the device object down."""
    self.log.info('Tearing down this controller object.')
    if self._sniffer_manager_obj is not None:
      self._sniffer_manager_obj.teardown()
      self._sniffer_manager_obj = None
