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
from mobly import utils

from mobly.controllers.wifi.lib import constants
from mobly.controllers.wifi.lib import errors
from mobly.controllers.wifi.lib import iw_utils
from mobly.controllers.wifi.lib import sniffer_manager_base
from mobly.controllers.wifi.lib import wifi_configs

# Avoid directly importing cros_device, which causes circular dependencies.
OpenWrtDevice = Any

_FILE_TAG = 'sniffer'
_INTERFACE = 'monitor0'
_REMOTE_DIR_NAME = 'sniffer'

# Enable rotation with file size 50MB and at most 2 files for packet capturing.
# The packet capture process alternatively saves to 2 files. Once it reaches the
# file size limit it will start overwrite the other file.
# Note that the available RAM on Ubiquiti 6 lite AP is about 120MB, so
# `_PCAP_FILE_SIZE_MB` * `_KEEP_PCAP_FILE_NUM` must be smaller than 120MB.
_PCAP_FILE_SIZE_MB = 50
_KEEP_PCAP_FILE_NUM = 2
_KEEP_LATEST_PCAP_ARG = f'-W {_KEEP_PCAP_FILE_NUM} -C {_PCAP_FILE_SIZE_MB}'

# `tcpdump` filter to ignore QoS data frames.
_FILTER_IGNORE_QOS_DATA_FRAMES = r'not \(type data subtype qos-data\)'


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
    self._local_work_dir = self._device.log_path
    self._timestamp = mobly_logger.get_log_file_timestamp()

  @property
  def is_alive(self) -> bool:
    """True if the service is alive; False otherwise."""
    return self._remote_process is not None

  @property
  def _remote_work_dir(self) -> Any:
    """The remote work directory of this object.

    We cannot initialize this in constructor because
    `self._device.remote_work_dir` can only be used after `device.initialize` is
    used.
    """
    remote_dir = os.path.join(self._device.remote_work_dir, _REMOTE_DIR_NAME)
    self._device.ssh.make_dirs(remote_dir)
    return remote_dir

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
    cmd = sniffer_manager_base.gen_iw_set_freq_cmd(interface, freq_config)
    self._device.ssh.execute_command(
        command=cmd,
        timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
    )

    self._remove_capture_dir()

    self._timestamp = mobly_logger.get_log_file_timestamp()
    capture_file_remote_path = os.path.join(
        self._remote_work_dir, f'sniffer,{self._timestamp}.pcap'
    )

    capture_args = []
    if capture_config.keep_latest_packets:
      capture_args.append(_KEEP_LATEST_PCAP_ARG)
    if capture_config.ignore_qos_data_frames:
      capture_args.append(_FILTER_IGNORE_QOS_DATA_FRAMES)
    self._remote_process = self._device.ssh.start_remote_process(
        command=constants.Commands.START_TCPDUMP.format(
            interface=interface,
            file_path=capture_file_remote_path,
            args=' '.join(capture_args),
        ),
        get_pty=True,
    )

  def _remove_capture_dir(self):
    self._device.ssh.rm_dir(self._remote_work_dir)

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
      self._log.warning(
          'Skip stopping this sniffer manager because it is not running.'
      )
      return
    self._log.debug('Stopping packet capturing.')
    self._stop_remote_process()
    if current_test_info is not None:
      local_dir = current_test_info.output_path
      self._pull_capture_files(local_dir)
    self._remove_capture_dir()
    self._log.debug('Stopped packet capturing.')

  def _stop_remote_process(self):
    """Stops the remote process."""
    if (proc := self._remote_process) is None:
      return

    self._remote_process = None
    proc.send_signal(signal_id=signal.SIGINT, assert_process_exit=True)
    self._log.debug('Sniffer process output: %s', proc.communicate())

  def _pull_capture_files(self, local_dir: str) -> None:
    """Pulls the capture files from the device to the host.

    If multiple capture files are found, this will use `mergecap` on host to
    merge them into one file. If `mergecap` is not installed, this will directly
    upload all capture files.

    Args:
      local_dir: the local directory to pull the capture files to.
    """
    # Print all capture files info for debugging.
    self._device.ssh.execute_command(
        command=f'ls -alh {self._remote_work_dir}',
        timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
        ignore_error=True,
    )
    pcap_files = list(self._device.ssh.list_dir(self._remote_work_dir))
    if not pcap_files:
      self._log.warning(
          'Packet capture file does not exist on device. This might be because'
          ' no packets were captured if the capturing time was too short.'
      )
      return

    self._device.ssh.pull_remote_directory(self._remote_work_dir, local_dir)
    pcap_local_paths = [os.path.join(local_dir, name) for name in pcap_files]

    # Skips merge if `mergecap` is not installed.
    which_mergecap = utils.run_command(['which', 'mergecap'])
    if which_mergecap[0] != 0:
      self._device.log.error(
          'Please install mergecap on your host machine. Otherwise, we will'
          ' directly upload all capture files without merging them into one'
          ' capture file.'
      )
      self._capture_file_local_path = pcap_local_paths[0]
      return

    new_file_path = self._merge_capture_files(pcap_local_paths, local_dir)
    self._capture_file_local_path = new_file_path

  def _merge_capture_files(self, pcap_local_paths: list[str], local_dir: str):
    """Merges multiple captures files into one capture file."""
    new_file_name = f'sniffer,merged,{self._timestamp}.pcap'
    new_file_path = os.path.join(local_dir, new_file_name)
    self._device.log.debug(
        'Merging following capture files into one file %s: %s',
        os.path.basename(new_file_path),
        ','.join(pcap_local_paths),
    )
    result = utils.run_command(
        ['mergecap', '-w', new_file_path] + pcap_local_paths
    )
    if result[0] != 0:
      raise errors.SnifferManagerError(
          f'Failed to merge capture files with result: {result}'
      )
    for pcap_local_path in pcap_local_paths:
      os.remove(pcap_local_path)
    return new_file_path

  def get_capture_file(self) -> str | None:
    """Gets the full path of the last capture."""
    return self._capture_file_local_path

  def teardown(self):
    """Tears down this manager object."""
    if not self.is_alive:
      return
    self.stop_capture()
