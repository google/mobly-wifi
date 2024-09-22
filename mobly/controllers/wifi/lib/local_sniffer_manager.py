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

"""A module for managing sniffer on a local device connected to host."""

import os
import shutil
from typing import Any

from mobly import logger as mobly_logger
from mobly import runtime_test_info
from mobly import utils

from mobly.controllers.wifi.lib import constants
from mobly.controllers.wifi.lib import errors
from mobly.controllers.wifi.lib import sniffer_manager_base
from mobly.controllers.wifi.lib import utils as wifi_utils
from mobly.controllers.wifi.lib import wifi_configs


SnifferDevice = Any

_INTERFACE_PREFIX = 'monitor0'
_FILE_TAG = 'packets'
_FILE_TAG_MERGED = 'packets,merged'

# Capture process adopts rotation with file size limit 50MB and at most 2 files
# for saving captured packets. The packet capture process alternatively saves to
# 2 files. Once it reaches the file size limit it will start overwrite the other
# file.
_PCAP_FILE_SIZE_MB = 300
_KEEP_PCAP_FILE_NUM = 2
_KEEP_LATEST_PCAP_ARG = f'-W {_KEEP_PCAP_FILE_NUM} -C {_PCAP_FILE_SIZE_MB}'

# `tcpdump` filter to ignore QoS data frames.
_FILTER_IGNORE_QOS_DATA_FRAMES = r'not \(type data subtype qos-data\)'


class LocalSnifferManager(sniffer_manager_base.SnifferManagerBase):
  """A class for managing sniffer on a local device connected to host."""

  def __init__(self, device: 'SnifferDevice', phy: str):
    super().__init__(device)
    self._phy = phy
    # We should concact `self._phy` into the interface name because many
    # local sniffer might connect with the same host and used by different
    # tests concurrently.
    self._interface = f'{_INTERFACE_PREFIX}_{self._phy}'
    self._packet_dir = os.path.join(self.device.log_path, _FILE_TAG)
    self._proc = None
    self._timestamp = None
    self._sniffer_stdout = None
    self._sniffer_stderr = None

  @property
  def is_alive(self) -> bool:
    """True if the service is alive; False otherwise."""
    return self._proc is not None

  def get_capture_file(self) -> str | None:
    """Gets the full path of the last capture."""
    return self._capture_file_path

  def start_sniffer_process(
      self,
      freq_config: wifi_configs.FreqConfig,
      capture_config: wifi_configs.PcapConfig,
  ) -> None:
    """Configures network interface and starts the tcpdump process."""
    interface = self._interface
    phy = self._phy

    wifi_utils.run_command(
        cmd=constants.Commands.IW_DEV_DEL.format(interface=interface),
        ignore_error=True,
    )
    wifi_utils.run_command(
        cmd=constants.Commands.IW_DEV_ADD_MONITOR.format(
            phy=phy, interface=interface
        ),
    )
    # TODO: Using sudo permission is a temporary workaround, we
    # should figure out how to allowing running ip link up command. Otherwise
    # we need to modify lab host configuration.
    wifi_utils.run_command(
        cmd=f'sudo {constants.Commands.IP_LINK_UP.format(interface=interface)}',
    )
    wifi_utils.run_command(
        cmd=sniffer_manager_base.gen_iw_set_freq_cmd(interface, freq_config),
    )

    self._remove_capture_dir()
    utils.create_dir(self._packet_dir)
    self._timestamp = mobly_logger.get_log_file_timestamp()
    self._packet_streaming_path = self._get_packet_streaming_path()
    self._sniffer_stdout = open(
        self._get_sniffer_log_path(log_level='stdout'), 'w'
    )
    self._sniffer_stderr = open(
        self._get_sniffer_log_path(log_level='stderr'), 'w'
    )

    capture_args = []
    if capture_config.keep_latest_packets:
      capture_args.append(_KEEP_LATEST_PCAP_ARG)
    if capture_config.ignore_qos_data_frames:
      capture_args.append(_FILTER_IGNORE_QOS_DATA_FRAMES)
    cmd = constants.Commands.START_TCPDUMP.format(
        interface=interface,
        file_path=f'"{self._packet_streaming_path}"',
        args=' '.join(capture_args),
    )
    self._proc = utils.start_standing_subprocess(
        cmd=cmd,
        shell=True,
        stdout=self._sniffer_stdout,
        stderr=self._sniffer_stderr,
    )
    self._print_interface_state()

  def _print_interface_state(self):
    """Prints the state of network interface in DEBUG logs."""
    wifi_utils.run_command(
        cmd=constants.Commands.IW_DEV_INFO.format(interface=self._interface),
    )
    wifi_utils.run_command(
        cmd=constants.Commands.IP_LINK_SHOW.format(interface=self._interface),
    )

  def _remove_capture_dir(self):
    """Removes the directory if it exists."""
    if os.path.exists(self._packet_dir):
      shutil.rmtree(self._packet_dir)

  def stop_sniffer_process(self):
    """Stops the sniffer process and closes log file objects."""
    if (proc := self._proc) is None:
      return

    self._proc = None
    if proc.poll() is not None:
      self._try_close_file_objects()
      raise errors.SnifferManagerError(
          f'Sniffer process (pid={proc.pid}) already stopped.'
      )

    try:
      utils.stop_standing_subprocess(proc)
    finally:
      self._try_close_file_objects()
    self.log.debug(
        'Stopped the sniffer process (pid=%d) with output: %s',
        proc.pid,
        proc.communicate(),
    )

  def _try_close_file_objects(self):
    """Closes log file objects."""
    if self._sniffer_stdout is not None:
      self._sniffer_stdout.close()
      self._sniffer_stdout = None
    if self._sniffer_stderr is not None:
      self._sniffer_stderr.close()
      self._sniffer_stderr = None

  def post_process_packet_files(
      self, current_test_info: runtime_test_info.RuntimeTestInfo | None = None
  ):
    """Processes packet files after stopping the sniffer process."""
    if current_test_info is None:
      self._capture_file_path = None
      self._remove_capture_dir()
      return

    dest_dir = current_test_info.output_path
    self._post_process_packet_files(dest_dir)
    self._remove_capture_dir()

  def _post_process_packet_files(self, dest_dir: str):
    """Merges multiple packet files and move the packet file to the dest dir."""
    # Print the capture files stats in logs.
    wifi_utils.run_command(f'ls -alh {self._packet_dir}')
    pcap_files = os.listdir(self._packet_dir)
    if not pcap_files:
      self.log.warning(
          'Packet capture file does not exist on device. This might be because'
          ' no packets were captured if the capturing time was too short.'
      )
      return

    pcap_local_paths = [
        os.path.join(self._packet_dir, name) for name in pcap_files
    ]

    # Skips merge if `mergecap` is not installed.
    which_mergecap = utils.run_command(['which', 'mergecap'])
    if which_mergecap[0] != 0:
      self.log.error(
          'Please install mergecap on your host machine. Otherwise, we will'
          ' directly upload all capture files without merging them into one'
          ' capture file.'
      )
      for path in pcap_local_paths:
        # If mergecap is not installed, we can set `_capture_file_path` to any
        # of the capture file path.
        self._capture_file_path = shutil.move(path, dest_dir)
      return

    new_file_path = self._merge_capture_files(pcap_local_paths, dest_dir)
    self._capture_file_path = new_file_path

  def _merge_capture_files(self, pcap_local_paths: list[str], dest_dir: str):
    filename = os.path.splitext(os.path.basename(pcap_local_paths[0]))[0]
    new_file_name = filename.replace(_FILE_TAG, _FILE_TAG_MERGED)
    new_file_name = f'{new_file_name}.pcap'
    new_file_path = os.path.join(dest_dir, new_file_name)
    self.log.debug(
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

  def _get_sniffer_log_path(self, log_level: str):
    return os.path.join(
        self.device.log_path, f'{_FILE_TAG},{self._timestamp}.{log_level}'
    )

  def _get_packet_streaming_path(self):
    return os.path.join(self._packet_dir, f'{_FILE_TAG},{self._timestamp}.pcap')
