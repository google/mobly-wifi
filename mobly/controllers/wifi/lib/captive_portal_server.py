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

"""The module for managing the lifecycle of captive portal server.

This module is responsible for starting and stopping the captive portal server.
"""

import datetime
import pathlib
import traceback
from typing import Any

from mobly import logger as mobly_logger

from mobly.controllers.wifi.lib import ssh as ssh_lib
from mobly.controllers.wifi.lib import constants
from mobly.controllers.wifi.lib import errors
from mobly.controllers.wifi.lib import utils as wifi_utils

OpenWrtDevice = Any

_CAPTIVE_PORTAL_SCRIPT_PATH = '/tmp/captive_portal_test'
_CAPTIVE_PORTAL_SCRIPT_FILE_NAME = 'captive_portal_http.py'

_CAPTIVE_PORTAL_SCRIPT_CONTENT = """
import sys
import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer

class RedirectHandler(BaseHTTPRequestHandler):
  def do_GET(self):
    print(f'listening on port {sys.argv[1]}')
    try:
      netstat_output = subprocess.check_output(['netstat', '-tulnp']).decode('utf-8')
      for line in netstat_output.splitlines():
        if f':{sys.argv[1]}' in line or ':80' in line:
          print(f'netstat command output: {line}')
    except subprocess.CalledProcessError as e:
      print(f'Error running netstat: {e}')
    self.protocol_version = "HTTP/1.1"
    self.send_response(int(sys.argv[2]))
    self.send_header("Location", sys.argv[3])
    self.end_headers()
    return

  def do_HEAD(self):
    self.protocol_version = "HTTP/1.1"
    self.send_response(int(sys.argv[2]))
    self.send_header("Location", sys.argv[3])
    self.end_headers()
    return

def run(port=int(sys.argv[1])):
  server_address = ("0.0.0.0", port)
  httpd = HTTPServer(server_address, RedirectHandler)
  print(f"Redirect server running on http://localhost:{port}")
  httpd.serve_forever()

if __name__ == "__main__":
  run()
"""

_PORT = 80
_STATUS_CODE = 302
_REDIRECT_URL = 'http://example.com'
_NETSTAT_CHECK_TIMEOUT = datetime.timedelta(seconds=10)
_NETSTAT_CHECK_INTERVAL = datetime.timedelta(seconds=2)


class CaptivePortalServer:
  """The class for managing the lifecycle of captive portal server.

  This class is responsible for starting and stopping the captive portal server.
  """

  _captive_portal_server_file: pathlib.PurePosixPath

  def __init__(self, device: 'OpenWrtDevice'):
    self._device = device
    self._remote_process = None
    self._netstat_grep_port_error = None

    self._log = mobly_logger.PrefixLoggerAdapter(
        device.log,
        {
            mobly_logger.PrefixLoggerAdapter.EXTRA_KEY_LOG_PREFIX: (
                '[CaptivePortalServer]'
            )
        },
    )

  @property
  def is_alive(self) -> bool:
    """True if the service is alive; False otherwise."""
    return self._remote_process is not None

  def _is_listening_on_port(self) -> bool:
    """Checks if a process is listening on port {_PORT}."""
    self._netstat_grep_port_error = None
    command = f'netstat -tlnp | grep :{_PORT}'
    try:
      netstat_output = self._device.ssh.execute_command(
          command=command,
          timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
      )
      for line in netstat_output.splitlines():
        self._device.ssh.execute_command(
            f'echo "{line}" | logger -t captive_portal_netstat',
            timeout=constants.CMD_SHORT_TIMEOUT.total_seconds()
        )
      self._log.debug('Successfully found process on port %s.', _PORT)
      return True
    except ssh_lib.ExecuteCommandError as e:
      self._netstat_grep_port_error = e
      self._device.ssh.execute_command(
          f'echo "No process listening on port {_PORT}" | logger -t'
          ' captive_portal_netstat',
          timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
      )
      self._log.warning(f':No process listening on port {_PORT}')
      return False

  def _create_captive_portal_server_file(self) -> None:
    """Creates a Python file that runs a simple HTTP redirect server."""
    try:
      self._device.make_dirs(_CAPTIVE_PORTAL_SCRIPT_PATH)
      self._captive_portal_server_file = pathlib.PurePosixPath(
          _CAPTIVE_PORTAL_SCRIPT_PATH,
          _CAPTIVE_PORTAL_SCRIPT_FILE_NAME,
      )
      command = (
          f'cat > "{self._captive_portal_server_file}" << "EOF"\n'
          f'{_CAPTIVE_PORTAL_SCRIPT_CONTENT}\nEOF'
      )
      self._log.debug('Pushing file having script content to openwrt.')
      self._device.ssh.execute_command(
          command=command, timeout=constants.CMD_SHORT_TIMEOUT.total_seconds()
      )
      self._log.debug('Pushed file having script content to openwrt.')
    except (
        ssh_lib.RemoteTimeoutError,
        ssh_lib.SSHRemoteError,
        ssh_lib.ExecuteCommandError,
    ) as e:
      raise errors.CaptivePortalError(
          'Failed to push file containing redirect server script to openwrt.'
      ) from e

  def start_captive_portal_server(self) -> None:
    """Starts the captive portal server if it is not already running.

    This method starts a captive portal server in the background.

    Raises:
      errors.CaptivePortalError: If the captive portal server failed to start.
    """
    if self.is_alive:
      self._log.debug('Captive portal server is already running.')
      return

    self._create_captive_portal_server_file()
    self._log.debug('Starting captive portal server.')
    try:
      command = (
          f'python3 -u {self._captive_portal_server_file} {_PORT} {_STATUS_CODE}'
          f' {_REDIRECT_URL} 2>&1 | logger -t captive_portal'
      )
      self._log.debug(f'Starting captive portal server with command {command}.')
      self._remote_process = self._device.ssh.start_remote_process(
          command,
          get_pty=True,
          timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
      )
      self._log.debug(
          f'Started captive portal server with pid {self._remote_process.pid}.'
      )

      # Verify the server is listening on port {_PORT} with retries.
      self._log.debug(f'Checking what is running on port {_PORT}.')
      if not wifi_utils.wait_for_predicate(
          predicate=self._is_listening_on_port,
          timeout=_NETSTAT_CHECK_TIMEOUT,
          interval=_NETSTAT_CHECK_INTERVAL,
      ):
        message = (
            f'{repr(self)} Captive portal server did not start listening on'
            f' port {_PORT} after'
            f' {_NETSTAT_CHECK_TIMEOUT.total_seconds()} seconds.'
        )
        if self._netstat_grep_port_error is not None:
          error_traceback = '\n'.join(
              traceback.format_exception(self._netstat_grep_port_error)
          )
          message += f' Netstat error:\n{error_traceback}'
          self._netstat_grep_port_error = None
        raise errors.CaptivePortalError(message)

    except (
        ssh_lib.RemoteTimeoutError,
        ssh_lib.SSHRemoteError,
        ssh_lib.ExecuteCommandError,
    ) as e:
      raise errors.CaptivePortalError(
          'Failed to configure captive portal.'
      ) from e

  def stop_captive_portal_server(self):
    """Stops the captive portal server.

    This method stops the captive portal server by terminating the process.
    After stopping the server, the script file is removed from the device.

    Raises:
      errors.CaptivePortalError: If the captive portal server failed to stop.
    """
    try:
      if self._remote_process is None:
        return

      self._log.debug(
          'Stopping captive_portal process %d.',
          self._remote_process.pid,
      )
      self._remote_process.terminate(
          timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
          assert_process_exit=True,
      )
      self._log.debug(
          'Terminated captive portal server with pid'
          f' {self._remote_process.pid}.'
      )
      self._remote_process = None
      self._device.ssh.rm_file(str(self._captive_portal_server_file))
      self._device.ssh.rm_dir(_CAPTIVE_PORTAL_SCRIPT_PATH)
      self._log.debug('Removed captive portal server script file.')
    except (
        ssh_lib.RemoteTimeoutError,
        ssh_lib.SSHRemoteError,
        ssh_lib.ExecuteCommandError,
    ) as e:
      self._remote_process = None
      raise errors.CaptivePortalError(
          'Failed to stop captive portal server.'
      ) from e
