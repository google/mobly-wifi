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

"""The module for streaming the output of a ChannelFile object to host."""

from concurrent import futures
import io
import logging
import os
import socket
import threading

from mobly import utils
from paramiko import channel


# The default timeout seconds for each channel read in RemotePopen
CHANNEL_READ_DEFAULT_TIMEOUT_SEC = 5

# The default timeout seconds for ChannelFileStreamer to stop
CHANNEL_FILE_STREAMER_STOP_TIMEOUT_SEC = 10


class ChannelFileStreamer:
  """The class for streaming the output of a ChannelFile object to a host file.

  This class will create a thread to continuously read data from the given
  channel file object and append to a host file.
  """

  def __init__(self, channel_file_obj: channel.ChannelFile,
               output_file_path: str, logger: logging.LoggerAdapter) -> None:
    """Initializes the ChannelFileStreamer instance.

    Args:
      channel_file_obj: The channel file object to read data.
      output_file_path: The host file path for appending the data read from the
        channel file object.
      logger: The logger.
    """
    self._channel_file_obj = channel_file_obj
    self._output_file_path = output_file_path
    utils.create_dir(os.path.dirname(output_file_path))
    self._output_file_obj = io.open(self._output_file_path, 'a')
    self._log = logger

    # When streaming output, the channel timeout is the timeout argument for
    # each channel read. We set it to a small value to avoid being blocked
    # indefinitely.
    self._channel_file_obj.channel.settimeout(CHANNEL_READ_DEFAULT_TIMEOUT_SEC)

    self._lock = threading.Lock()
    self._executor = futures.ThreadPoolExecutor(
        max_workers=1, thread_name_prefix='ChannelFileStreamer')
    self._job = None

  def _stream_channel_file_output(self, channel_file_obj: channel.ChannelFile,
                                  output_file_obj: io.TextIOWrapper,
                                  lock: threading.Lock,
                                  logger: logging.LoggerAdapter) -> None:
    """Streams the channel file output to a host file object."""
    logger.debug('Starting to stream the output to host file %s',
                 output_file_obj.name)

    while True:
      with lock:
        if output_file_obj.closed:
          logger.debug(
              'Stopping log streaming because the target output file object '
              'is already closed.')
          break

      if channel_file_obj.closed:
        logger.debug(
            'Stopping log streaming because the input channel file object '
            'is already closed.')
        break

      try:
        output = channel_file_obj.readline()

        if not output:
          logger.debug(
              'Stopping log streaming because got EOF from the input channel '
              'file object.')
          break

        try:
          output = output.decode('utf-8')
        except UnicodeDecodeError:
          logger.error('Ignoring the channel file output decoding error. The '
                       'output failed to decode is: "%s"', output)
          continue

        with lock:
          if output_file_obj.closed:
            logger.debug(
                'Stopping log streaming because the target output file '
                'object is already closed. Ignoring the unwritten log: %s',
                output)
            break

          output_file_obj.write(output)
          output_file_obj.flush()

      except socket.timeout:
        logger.debug('Ignoring the timeout error when waiting for the output.')

    logger.debug('Finished streaming the output to host file %s',
                 output_file_obj.name)

  def start(self) -> None:
    """Starts streaming the channel file output."""
    self._job = self._executor.submit(self._stream_channel_file_output,
                                      self._channel_file_obj,
                                      self._output_file_obj, self._lock,
                                      self._log)

  def stop(self,
           timeout_sec: int = CHANNEL_FILE_STREAMER_STOP_TIMEOUT_SEC) -> None:
    """Stops streaming the channel file output.

    If the streaming thread exited with an exception, this will raise that
    exception in the main thread.

    Args:
      timeout_sec: The timeout seconds to wait for the streaming thread to exit.
        If the thread does not exit within the given time, we will force stop
        it, potentially causing subsequent outputs to be discarded.
    """
    if timeout_sec < self._channel_file_obj.channel.timeout:
      raise ValueError(
          'The stop timeout should be no smaller than the channel '
          f'read timeout, got stop timeout={timeout_sec}, channel '
          f'read timeout={self._channel_file_obj.channel.timeout}'
      )

    if self._job is None:
      raise ValueError('job not initialized')
    try:
      self._job.result(timeout=timeout_sec)
    except futures.TimeoutError:
      self._log.debug(
          'Ignoring the timeout error occurred when trying to stop,'
          f' which may cause the log file {self._output_file_path}'
          ' incomplete.'
      )
      with self._lock:
        self._output_file_obj.close()

    self._log.debug('Shutting down the threading pool executor.')
    self._executor.shutdown()

    if (exception := self._job.exception()) is not None:
      raise exception
