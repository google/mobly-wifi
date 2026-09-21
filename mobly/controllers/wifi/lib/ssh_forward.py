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

"""Robust port forwarding over paramiko.

Modified version of zmq.ssh.forward.py to handle abrupt socket closures (e.g.,
gRPC server restarts) without raising "Bad file descriptor" or "Socket
closed"exceptions.
"""

from __future__ import annotations

import select
import socket
import socketserver
from typing import cast

from mobly import logger as mobly_logger
import paramiko


class ForwardServer(socketserver.ThreadingTCPServer):
  """A TCP server that forwards requests to a remote host.

  This class is a copy of zmq.ssh.forward.ForwardServer with the following
  changes:
  - daemon_threads is set to True to prevent the server from blocking the
    program from exiting.
  - allow_reuse_address is set to True to allow the server to be restarted
    multiple times without getting an "Address already in use" error.
  - handle_error is overridden to catch and log exceptions from the request
    handler.
  """

  daemon_threads = True
  allow_reuse_address = True

  def handle_error(self, request, client_address):
    handler_class = cast(Handler, self.RequestHandlerClass)
    logger = getattr(handler_class, 'logger', None)
    if logger:
      logger.debug(
          'Exception occurred during processing of request from %s for tunnel'
          ' to %s:%s',
          client_address,
          getattr(handler_class, 'chain_host', 'unknown'),
          getattr(handler_class, 'chain_port', 'unknown'),
          exc_info=True,
      )

    else:
      super().handle_error(request, client_address)


class Handler(socketserver.BaseRequestHandler):
  """Handles a single forwarded connection.

  Modified to be defensive against race conditions during server restarts.
  """

  ssh_transport: paramiko.Transport
  chain_host: str
  chain_port: int
  request: socket.socket
  logger: mobly_logger.PrefixLoggerAdapter

  def setup(self) -> None:
    self.logger = mobly_logger.PrefixLoggerAdapter(
        self.logger,
        {
            mobly_logger.PrefixLoggerAdapter.EXTRA_KEY_LOG_PREFIX: (
                f'[SSHForwardServer|{self.chain_port}]'
            )
        },
    )

  def handle(self) -> None:
    try:
      chan = self.ssh_transport.open_channel(
          'direct-tcpip',
          (self.chain_host, self.chain_port),
          self.request.getpeername(),
      )
    except Exception as e:  # pylint: disable=broad-except
      self.logger.debug(
          'Incoming request to %s:%d failed: %r',
          self.chain_host,
          self.chain_port,
          e,
      )
      return

    if chan is None:
      self.logger.debug(
          'Incoming request to %s:%d was rejected by the SSH server.',
          self.chain_host,
          self.chain_port,
      )
      return

    self.logger.debug(
        'Connected! Tunnel open %r -> %r -> %r',
        self.request.getpeername(),
        chan.getpeername(),
        (self.chain_host, self.chain_port),
    )

    try:
      # Set small timeouts to ensure we don't block indefinitely
      # if the transport is severed.
      self.request.settimeout(1.0)
      chan.settimeout(1.0)

      while True:
        try:
          # select() with a timeout allows periodic health checks
          r, _, _ = select.select([self.request, chan], [], [], 1.0)
        except (select.error, socket.error) as e:
          # Catch 'Bad file descriptor' (9) if a socket is closed mid-loop
          self.logger.debug('Select error: %r', e)
          break

        if self.request in r:
          try:
            data = self.request.recv(1024)
            if not data:
              break
            chan.sendall(data)
          except Exception as e:  # pylint: disable=broad-except
            self.logger.debug('Local -> Remote send failed: %r', e)
            break

        if chan in r:
          try:
            data = chan.recv(1024)
            if not data:
              break
            self.request.sendall(data)
          except Exception as e:  # pylint: disable=broad-except
            self.logger.debug('Remote -> Local send failed: %r', e)
            break

        # Verify the main SSH connection is still active
        if not self.ssh_transport.is_active():
          self.logger.debug('SSH Transport is inactive, closing tunnel.')
          break
    except Exception as e:  # pylint: disable=broad-except
      self.logger.debug('General tunnel loop error: %r', e)
    finally:
      # Cleanup resources individually to ensure one failure
      # doesn't prevent the other from closing.
      if chan is not None:
        try:
          chan.close()
        except Exception:  # pylint: disable=broad-except
          pass
      try:
        self.request.close()
      except Exception:  # pylint: disable=broad-except
        pass
      self.logger.debug('Tunnel closed')
