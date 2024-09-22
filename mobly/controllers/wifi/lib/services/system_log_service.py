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

"""The service for streaming the system logs on AP device to host."""

import datetime
import pathlib
from typing import Any

from mobly import logger as mobly_logger
from mobly import runtime_test_info
from mobly import utils
from mobly.controllers.android_device_lib.services import base_service

from mobly.controllers.wifi.lib import file_clipper
from mobly.controllers.wifi.lib import constants
from mobly.controllers.wifi.lib import errors

# Avoid directly importing cros_device, which causes circular dependencies.
OpenWrtDevice = Any

_FILE_TAG = 'openwrt_syslog'
_REMOTE_PROC_STOP_WAIT_TIME = datetime.timedelta(seconds=30)


class SystemLogService(base_service.BaseService):
  """The service for streaming the system logs on AP device to host."""

  def __init__(self, device: 'OpenWrtDevice', configs: Any = None) -> None:
    del configs  # Unused.
    self._device = device
    self._configs = None
    self._log = mobly_logger.PrefixLoggerAdapter(
        self._device.log,
        {
            mobly_logger.PrefixLoggerAdapter.EXTRA_KEY_LOG_PREFIX: (
                '[SystemLogService]'
            )
        },
    )

    self._remote_process = None
    host_log_dir = pathlib.Path(self._device.log_path)
    self._host_log_path = pathlib.Path(host_log_dir, f'{_FILE_TAG}.log')
    self._excerpt_generator = file_clipper.FileClipper(self._host_log_path)

  @property
  def is_alive(self) -> bool:
    """True if the service is alive; False otherwise."""
    return self._remote_process is not None

  def start(self) -> None:
    """Starts streaming the specified logs to host."""
    self._log.debug('Starting.')
    self._assert_not_running()
    self._start_log_subprocess()
    self._log.debug('Started.')

  def _assert_not_running(self):
    """Asserts the logcat service is not running.

    Raises:
      errors.SystemLogServiceError: if the logcat service is running.
    """
    if self.is_alive:
      raise errors.SystemLogServiceError(
          self._device,
          'System log service is already running, cannot start again.',
      )

  def _start_log_subprocess(self) -> None:
    """Starts the subprocess which streams logs to host."""
    self._remote_process = self._device.ssh.start_remote_process(
        command=constants.Commands.LOGREAD,
        get_pty=True,
        output_file_path=str(self._host_log_path),
    )

  def __del__(self):
    self.stop()

  def stop(self) -> None:
    """Stops streaming device system logs to host.

    Raises:
      errors.SystemLogServiceError: raised if the syslog subprocess has been
        stopped before this service.
    """
    self._log.debug('Stopping.')
    self._excerpt_generator.close()
    self._stop_log_subprocess()
    self._log.debug('Stopped.')

  def _stop_log_subprocess(self):
    if (proc := self._remote_process) is None:
      return

    self._remote_process = None
    proc.terminate(
        timeout=_REMOTE_PROC_STOP_WAIT_TIME.total_seconds(),
        assert_process_exit=True,
    )

  def create_output_excerpts(
      self, test_info: runtime_test_info.RuntimeTestInfo
  ) -> list[Any]:
    """Creates excerpts for system logs and returns the excerpt paths."""
    self._log.debug('Creating output excerpts.')
    dest_path = test_info.output_path
    utils.create_dir(dest_path)
    timestamp = mobly_logger.get_log_file_timestamp()

    filename = f'{_FILE_TAG},{self._device.serial},{timestamp}.log'
    excerpts_path = pathlib.Path(dest_path, filename)
    self._excerpt_generator.clip_new_content(excerpts_path)

    return [excerpts_path]
