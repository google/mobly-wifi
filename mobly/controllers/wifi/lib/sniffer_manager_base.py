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

"""The base class for sniffer manager."""

import abc
from typing import Any

from mobly import logger as mobly_logger
from mobly import runtime_test_info

from mobly.controllers.wifi.lib import constants
from mobly.controllers.wifi.lib import errors
from mobly.controllers.wifi.lib import wifi_configs


def gen_iw_set_freq_cmd(
    interface: str,
    freq_config: wifi_configs.FreqConfig,
) -> str:
  """Generates the command to set the frequency of the interface.

  There are 2 formats to call an `iw` command to set frequency:

    set freq <freq> [NOHT|HT20|HT40+|HT40-|5MHz|10MHz|80MHz]
    set freq <control freq> [5|10|20|40|80|80+80|160] [<center1_freq>
      [<center2_freq>]]

  We use the second pattern for channel widht >= 80MHz, and the first one for
  the rest as iw will derive the center frequency for us so we don't have to
  duplicate the logic.

  This function does not validate the given frequencies here and delegate it
  to `iw`. `iw` fails with invalid argument error if the frequencies are not
  matched or invalid.

  Args:
    interface: the wireless interface to set frequency.
    freq_config: the frequency configuration.

  Returns:
    The command to set the frequency.
  """
  freq = constants.CHANNEL_TO_FREQUENCY[freq_config.channel]
  args = [str(freq)]
  match freq_config.ht_mode:
    case (
        wifi_configs.HTMode.NOHT
        | wifi_configs.HTMode.HT20
        | wifi_configs.HTMode.HT40_PLUS
        | wifi_configs.HTMode.HT40_MINUS
    ):
      args.append(str(freq_config.ht_mode))
    case wifi_configs.HTMode.HT80:
      args.append('80')
      args.append(str(freq_config.center1_freq))
  return constants.Commands.IW_DEV_SET_FREQ.format(
      interface=interface, freq_args=' '.join(args)
  )


class SnifferManagerBase(abc.ABC):
  """A base class for managing sniffer process."""

  def __init__(self, device: Any):
    self._device = device
    self._log = mobly_logger.PrefixLoggerAdapter(
        device.log,
        {
            mobly_logger.PrefixLoggerAdapter.EXTRA_KEY_LOG_PREFIX: (
                '[SnifferManager]'
            )
        },
    )

  @property
  def device(self) -> Any:
    """The device controller object."""
    return self._device

  @property
  def log(self) -> mobly_logger.PrefixLoggerAdapter:
    """The logger for this object."""
    return self._log

  @property
  @abc.abstractmethod
  def is_alive(self) -> bool:
    """True if the service is alive; False otherwise."""

  @abc.abstractmethod
  def get_capture_file(self) -> str | None:
    """Gets the full path of the last capture file."""

  def _assert_not_running(self):
    """Asserts this manager is not running.

    Raises:
      errors.SnifferManagerError: if this manager is running.
    """
    if self.is_alive:
      raise errors.SnifferManagerError(
          'Running multiple sniffer instances is not allowed.'
      )

  def start_capture(
      self,
      freq_config: wifi_configs.FreqConfig,
      capture_config: wifi_configs.PcapConfig | None = None,
  ):
    """Starts pacaket capture on the given frequency band."""
    capture_config = capture_config or wifi_configs.PcapConfig()
    self._log.debug(
        'Starting packet capture on frequency conf: %s, capture conf: %s',
        freq_config,
        capture_config,
    )
    self._assert_not_running()
    self.start_sniffer_process(freq_config, capture_config)
    self._log.debug('Started packet capturing.')

  @abc.abstractmethod
  def start_sniffer_process(
      self,
      freq_config: wifi_configs.FreqConfig,
      capture_config: wifi_configs.PcapConfig,
  ) -> None:
    """Starts the sniffer process."""

  def stop_capture(
      self, current_test_info: runtime_test_info.RuntimeTestInfo | None = None
  ):
    """Stops pacaket capture.

    Args:
      current_test_info: If provided, this will move the captured packets to
        `current_test_info.output_path`. Otherwise the captured packets will be
        removed.
    """
    if not self.is_alive:
      return
    self._log.debug('Stopping packet capturing.')
    self.stop_sniffer_process()
    self.post_process_packet_files(current_test_info)
    self._log.debug('Stopped packet capturing.')

  @abc.abstractmethod
  def stop_sniffer_process(self):
    """Stops the sniffer process."""

  @abc.abstractmethod
  def post_process_packet_files(
      self, current_test_info: runtime_test_info.RuntimeTestInfo | None = None
  ):
    """Processes packet files after stopping the sniffer process."""

  def teardown(self):
    """Tears the device object down."""
    self._log.info('Tearing down...')
    self.stop_capture(current_test_info=None)

  def __del__(self):
    self.teardown()
