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

"""The manager managing packet capture instances on AP devices."""

import os
import signal
from typing import Any

from mobly import logger as mobly_logger
from mobly import runtime_test_info

from mobly.controllers.wifi.lib import constants
from mobly.controllers.wifi.lib import errors
from mobly.controllers.wifi.lib import iw_utils
from mobly.controllers.wifi.lib import wifi_configs

# Avoid directly importing cros_device, which causes circular dependencies.
OpenWrtDevice = Any

_FILE_TAG = 'sniffer'
_INTERFACE = 'monitor0'
_REMOTE_FILE_PATH = '/tmp/sniffer.pcap'

# `tcpdump` filter to ignore QoS data frames but keep the EAPOL frames.
# `ether proto 0x888E` is for keeping the EAPOL frames.
_FILTER_IGNORE_QOS_DATA_FRAMES = (
    r'\(ether proto 0x888E\) or not \(type data subtype qos-data\)'
)


class SnifferManager:
  """The class for managing sniffer instances on the AP device."""

  def __init__(self, device: 'OpenWrtDevice') -> None:
    self._device = device
    self._log = mobly_logger.PrefixLoggerAdapter(
        self._device.log,
        {
            mobly_logger.PrefixLoggerAdapter.EXTRA_KEY_LOG_PREFIX: (
                '[SnifferManager]'
            )
        },
    )

    self._remote_process = None
    self._capture_file_local_path = None

  @property
  def is_alive(self) -> bool:
    """True if the service is alive; False otherwise."""
    return self._remote_process is not None

  def start_capture(
      self,
      freq_config: wifi_configs.FreqConfig,
      capture_config: wifi_configs.PcapConfig | None = None,
  ) -> None:
    """Starts pacaket capture on the given channel."""
    capture_config = capture_config or wifi_configs.PcapConfig()
    self._log.debug(
        'Starting packet capture on frequency conf: %s, capture conf: %s',
        freq_config,
        capture_config,
    )
    self._assert_not_running()
    self._start_remote_process(freq_config, capture_config)
    self._print_interface_state()
    self._log.debug('Started packet capturing.')

  def _assert_not_running(self):
    """Asserts this manager is not running.

    Raises:
      errors.SnifferManagerError: if this manager is running.
    """
    if self.is_alive:
      raise errors.SnifferManagerError(
          'Running multiple sniffer instances is not allowed.'
      )

  def _start_remote_process(
      self,
      freq_config: wifi_configs.FreqConfig,
      capture_config: wifi_configs.PcapConfig,
  ) -> None:
    """Starts the remote process to capture packets on the device."""
    interface = _INTERFACE
    channel = freq_config.channel

    phys = iw_utils.get_all_phys(device=self._device)
    phy = iw_utils.get_phy_by_channel(phys, channel).name

    # Kill any existing tcpdump instances.
    self._device.ssh.execute_command(
        command=constants.Commands.KILLALL.format(name='tcpdump'),
        timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
        ignore_error=True,
    )
    self._device.ssh.execute_command(
        command=constants.Commands.IW_DEV_DEL.format(interface=interface),
        timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
        ignore_error=True,
    )
    self._device.ssh.execute_command(
        command=constants.Commands.IW_DEV_ADD_MONITOR.format(
            phy=phy, interface=interface
        ),
        timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
    )
    self._device.ssh.execute_command(
        command=constants.Commands.IP_LINK_UP.format(interface=interface),
        timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
    )
    cmd = self._gen_iw_set_freq_cmd(interface, freq_config)
    self._device.ssh.execute_command(
        command=cmd,
        timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
    )

    if self._device.ssh.is_file(_REMOTE_FILE_PATH):
      self._device.ssh.rm_file(_REMOTE_FILE_PATH)

    capture_filter = ''
    if capture_config.ignore_qos_data_frames:
      capture_filter = _FILTER_IGNORE_QOS_DATA_FRAMES
    self._remote_process = self._device.ssh.start_remote_process(
        command=constants.Commands.START_TCPDUMP.format(
            interface=interface,
            file_path=_REMOTE_FILE_PATH,
            filter=capture_filter,
        ),
        get_pty=True,
    )

  def _gen_iw_set_freq_cmd(
      self,
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

  def _print_interface_state(self):
    """Prints interface state."""
    self._log.debug('Printing sniffer interface state.')
    self._device.ssh.execute_command(
        command=constants.Commands.IW_DEV_INFO.format(interface=_INTERFACE),
        timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
    )
    self._device.ssh.execute_command(
        command=constants.Commands.IP_LINK_SHOW.format(interface=_INTERFACE),
        timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
    )

  def __del__(self):
    self.teardown()

  def stop_capture(
      self, current_test_info: runtime_test_info.RuntimeTestInfo | None = None
  ):
    """Stops pacaket capture."""
    if not self.is_alive:
      return
    self._log.debug('Stopping packet capturing.')
    self._stop_remote_process()
    local_dir = (
        current_test_info.output_path
        if current_test_info is not None
        else self._device.log_path
    )
    self._pull_capture_file(local_dir)
    self._log.debug('Stopped packet capturing.')

  def _stop_remote_process(self):
    """Stops the remote process."""
    if (proc := self._remote_process) is None:
      return

    self._remote_process = None
    proc.send_signal(signal_id=signal.SIGINT, assert_process_exit=True)
    self._log.debug('Sniffer process output: %s', proc.communicate())

  def _pull_capture_file(self, local_dir: str):
    """Pulls the capture file from the device to the host."""
    timestamp = mobly_logger.get_log_file_timestamp()
    filename = f'{_FILE_TAG},{timestamp}.pcap'
    local_path = os.path.join(local_dir, filename)
    if not self._device.ssh.is_file(_REMOTE_FILE_PATH):
      self._log.warning(
          'Packet capture file does not exist on device. This might be because'
          ' no packets were captured if the capturing time was too short.'
      )
      return
    self._device.ssh.pull(_REMOTE_FILE_PATH, local_path)
    self._capture_file_local_path = local_path

  def get_capture_file(self) -> str | None:
    """Gets the full path of the last capture."""
    return self._capture_file_local_path

  def teardown(self):
    """Tears down this manager object."""
    self.stop_capture()
