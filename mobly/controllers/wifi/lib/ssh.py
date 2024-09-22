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

"""A wrapper of paramiko.SSHClient to interact with test machine remotely."""

from __future__ import annotations
import contextlib
import dataclasses
import errno
import logging
import os
import pathlib
import signal
import socket
import stat
import threading
import time
from typing import Iterable, Mapping, Optional, Tuple, Dict, cast

from mobly import logger as mobly_logger
import paramiko
from paramiko import channel
from paramiko import sftp_attr
from zmq.ssh import forward

from mobly.controllers.wifi.lib import channel_file_streamer

_SFTP_NOT_CONNECTED_ERROR_MESSAGE = (
    'Cannot use SFTP without opening the SFTP session. Probably because the'
    ' SSH connection is not established or SFTP session is not opened when'
    ' establishing the SSH connection.'
)
_SFTP_CANNOT_BE_OPENED_DUPLICATEDLY = (
    'Unable to open a new SFTP session while another is active.'
)

_SIGNAL_CMD_TIMEOUT_SEC = 4
_WAIT_PROC_EXIT_TIMEOUT_SEC = 30


@dataclasses.dataclass
class CommandResults:
  """A container to collect full command results."""
  exit_code: int = 0
  output: str = ''
  error: str = ''


class Error(Exception):
  """Base error type for ssh module."""

  def __init__(self, ssh: SSHProxy, message: str) -> None:
    super().__init__(f'{repr(ssh)} {message}')


class SSHRemoteError(Error):
  """Raised when a ssh operation encounters an error."""
  pass


class RemotePathDoesNotExistError(Error):
  """Raised when a path doesn't exist on the remote machine."""
  pass


class ExecuteCommandError(Error):
  """Raised when a ssh command encounters an error."""

  _COMMAND_EXCEPTION_TEMPLATE = """
  Call exited with non-zero return code of "{return_code:d}".
  ****************************Call***************************
  {command}
  ****************************Stdout*************************
  {stdout}
  ****************************Stderr*************************
  {stderr}
  **********************End of error message*****************
  """

  def __init__(self, ssh: SSHProxy, command: str,
               command_results: CommandResults) -> None:
    message = self._COMMAND_EXCEPTION_TEMPLATE.format(
        command=command,
        return_code=command_results.exit_code,
        stdout=command_results.output,
        stderr=command_results.error,
    )
    super().__init__(ssh, message)


class SSHNotConnectedError(Error):
  """Raised when the SSH client is not connected."""


class SFTPAlreadyConnectedError(Error):
  """Raised when trying to open a SFTP session while one is already opened."""


class RemoteTimeoutError(Error):
  """Raised when a remote process did not complete in its given time.."""
  pass


class PortForwardingError(Error):
  """Raised when a port forwarding operation encounters an error."""


class SSHProxy:
  """SSH client to interact with test machine.

  Attributes:
    log: A logger adapted from root logger with an added prefix specific to a
      remote test machine. The prefix is "[SSHProxy| hostname:ssh_port] ".
    ssh_client: the underlying Paramiko SSHClient object.
  """

  def __init__(
      self,
      hostname: str,
      ssh_port: int = 22,
      username: str = 'root',
      password: Optional[str] = None,
      keyfile: Optional[str] = None,
      allow_agent: bool = False,
      proxy_command: str | None = None,
  ):
    """Initializes the SSH client instance.

    Args:
      hostname: the IP address of the test machine.
      ssh_port: the ssh port of the test machine.
      username: the user name to log in to test machine.
      password: the password to log in to test machine.
      keyfile: a local path to a private key file.
      allow_agent: allow use of ssh-agent for underlying ssh_client object.
      proxy_command: the ProxyCommand string to use when connecting to the
      remote machine.
    """
    self._hostname = hostname
    self._username = username
    self._password = password
    self._ssh_port = ssh_port
    self._ssh_keyfile = keyfile
    self._allow_agent = allow_agent
    self._port_forward_servers: Dict[int, forward.ForwardServer] = {}
    self._proxy_command = (
        paramiko.ProxyCommand(proxy_command)
        if proxy_command is not None
        else None
    )

    self._sftp = None
    self.log = mobly_logger.PrefixLoggerAdapter(
        logging.getLogger(),
        {
            mobly_logger.PrefixLoggerAdapter.EXTRA_KEY_LOG_PREFIX:
                f'[SSHProxy|{self._hostname}:{self._ssh_port}]'
        }
    )
    self.ssh_client = paramiko.SSHClient()
    self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Suppress Paramiko debug logging. In some circumstances the Paramiko client
    # will continue to log debug messages after it has been closed. This can
    # cause crashes on system shutdown in Python3.
    logging.getLogger('paramiko').setLevel(logging.WARNING)

  def __repr__(self):
    return f'<SSHProxy|{self._hostname}:{self._ssh_port}>'

  def connect(
      self,
      timeout: float | None = None,
      banner_timeout: float | None = None,
      open_sftp: bool = True,
  ) -> None:
    """Connects to the test machine.

    Arguments:
      timeout: Connection timeout in seconds.
      banner_timeout: Timeout for the SSH banner to be presented.
      open_sftp: Whether to open a SFTP session after connection established.
        Without SFTP session, methods that related to remote file operations
        cannot be used.
    """
    self.log.info('Connecting to %s:%d', self._hostname, self._ssh_port)

    self.ssh_client.connect(
        self._hostname,
        port=self._ssh_port,
        username=self._username,
        password=self._password,
        allow_agent=self._allow_agent,
        key_filename=self._ssh_keyfile,
        sock=self._proxy_command,
        timeout=timeout,
        banner_timeout=banner_timeout,
    )
    if open_sftp:
      self.open_sftp()

  def open_sftp(self) -> None:
    """Opens an SFTP session.

    This is required by file operations provided in this class.

    Raises:
      SFTPAlreadyConnectedError: Raised if trying to open a SFTP session while
        one is already opened.
    """
    if self._sftp is not None:
      raise SFTPAlreadyConnectedError(
          ssh=self, message=_SFTP_CANNOT_BE_OPENED_DUPLICATEDLY
      )
    self._sftp = self.ssh_client.open_sftp()

  def disconnect(self):
    """Disconnects from the test machine and cleans up."""
    self.log.info('Disconnecting from %s', self._hostname)

    for forwarded_local_port in list(self._port_forward_servers):
      self.stop_port_forwarding(forwarded_local_port)

    if self._sftp:
      self._sftp.close()
      self._sftp = None

    self.ssh_client.close()

  def forward_port(self, remote_port: int, local_port: int = 0) -> int:
    """Sets up an SSH tunnel to port forward between client and remote host.

    The tunnel will run in a separate thread.

    Args:
      remote_port: The port on the remote host to forward all data to.
      local_port: The port on the local machine from which to forward all data.
        If 0 is passed then an unused port is picked.

    Returns:
      The local port that is used to open the SSH tunnel.

    Raises:
      PortForwardingError: Raised if trying to forward different remote ports
        to the same local port.
    """
    # Modifications were required in order to get a handle to the server object
    # which is used to stop the server during clean up.

    class SubHandler(forward.Handler):
      """Configures the local forward server."""
      chain_host = self._hostname
      chain_port = remote_port
      ssh_transport = self.ssh_client.get_transport()

    if local_port != 0 and local_port in self._port_forward_servers:
      forwarded_server = self._port_forward_servers[local_port]
      forwarded_remote_port = cast(
          SubHandler, forwarded_server.RequestHandlerClass
      ).chain_port

      if remote_port == forwarded_remote_port:
        return local_port

      error_string = (f'Local port {local_port} is in use for forwarding '
                      f'remote port {forwarded_remote_port}. Please choose '
                      'an unused local port, or simply set it to 0.')
      raise PortForwardingError(ssh=self, message=error_string)

    port_forward_server = (
        forward.ForwardServer(('127.0.0.1', local_port), SubHandler))

    # Start the server on a separate thread.
    thread = threading.Thread(
        target=port_forward_server.serve_forever, daemon=True)
    thread.start()

    _, forwarded_local_port = port_forward_server.server_address
    self._port_forward_servers[forwarded_local_port] = port_forward_server

    self.log.debug('Forwarded address %s:%d to local port %d', self._hostname,
                   remote_port, forwarded_local_port)
    return forwarded_local_port

  def stop_port_forwarding(self, local_port: int) -> None:
    """Stops port forwarded in function `forward_port`.

    Args:
      local_port: The forwarded port on the remote device.

    Raises:
      PortForwardingError: Raised if trying to stop forwarding to a local port
        which isn't being forwarding.
    """
    if local_port not in self._port_forward_servers:
      error_message = (f'Trying to stop forwarding to local port {local_port} '
                       "which isn't being forwarding.")
      raise PortForwardingError(ssh=self, message=error_message)

    server = self._port_forward_servers.pop(local_port)
    server.shutdown()
    server.server_close()

  def push_dir(self,
               local_src_dir: str,
               remote_dest_dir: str,
               change_permission: bool = False) -> None:
    """Pushes local directory recursively to the remote machine.

    Args:
      local_src_dir: the local directory to be copied to the remote machine.
      remote_dest_dir: the destination directory in the remote machine.
      change_permission: whether to change the permission to 777 on remote
        destination.
    """
    self.log.debug(
        'Pushing dir %s to test machine dir at %s',
        local_src_dir,
        remote_dest_dir,
    )
    self.make_dirs(remote_dest_dir)
    for (dir_path, _, file_names_list) in os.walk(local_src_dir):
      for file_name in file_names_list:
        local_file = os.path.join(dir_path, file_name)
        self.push(
            local_file,
            local_file.replace(local_src_dir, remote_dest_dir, 1),
            change_permission=change_permission)

  def move_dir(self, remote_current_location: str,
               remote_destination_location: str) -> None:
    """Renames a folder on the remote machine.

    Args:
      remote_current_location: The current name of the folder.
      remote_destination_location: The desired name of the folder. Exception
        will be thrown if remote_destination_location exists.

    Raises:
      IOError: if remote_destination_location is a folder.
      SSHNotConnectedError: If sftp is not connected.
    """
    if self._sftp is None:
      raise SSHNotConnectedError(
          ssh=self,
          message=_SFTP_NOT_CONNECTED_ERROR_MESSAGE,
      )
    self._sftp.rename(remote_current_location, remote_destination_location)

  def push(self,
           local_src_filename: str,
           remote_dest_filename: str,
           change_permission: bool = False) -> None:
    """Pushes local file to the remote machine.

    Args:
      local_src_filename: the local file.
      remote_dest_filename: the destination file location in the remote machine.
      change_permission: whether to change the permission to 777 on remote
        destination.

    Raises:
      FileNotFoundError: If the local file is missing.
      SSHNotConnectedError: If sftp is not connected.
    """
    if self._sftp is None:
      raise SSHNotConnectedError(
          ssh=self,
          message=_SFTP_NOT_CONNECTED_ERROR_MESSAGE,
      )

    self.make_dirs(os.path.dirname(remote_dest_filename))
    self._sftp.put(local_src_filename, remote_dest_filename)
    # Restore file permissions in linux and mac
    if change_permission:
      self._sftp.chmod(remote_dest_filename,
                       (os.stat(local_src_filename).st_mode & 0o777))

  def pull(self, remote_src_filepath: str, local_dest_filepath: str) -> None:
    """Pulls a remote file from the client as a local file.

    Args:
      remote_src_filepath: the remote source file name.
      local_dest_filepath: the local destination file name.

    Raises:
      RemotePathDoesNotExistError: If the remote file is missing.
      SSHNotConnectedError: If sftp is not connected.
    """
    if not self.exists(remote_src_filepath):
      raise RemotePathDoesNotExistError(
          self, f'The file to pull ({remote_src_filepath}) does not exist.')

    local_dir_path = os.path.dirname(local_dest_filepath)
    if not os.path.exists(local_dir_path):
      os.makedirs(local_dir_path)

    if self._sftp is None:
      raise SSHNotConnectedError(
          ssh=self,
          message=_SFTP_NOT_CONNECTED_ERROR_MESSAGE,
      )
    self._sftp.get(remote_src_filepath, local_dest_filepath)

  def pull_to_directory(self, remote_src_filepath: str,
                        local_directory: str) -> None:
    """Pulls a remote file from the client into a local directory.

    Args:
      remote_src_filepath: the remote source file path.
      local_directory: the path to the local destination directory.
    """
    filename = os.path.basename(remote_src_filepath)
    self.pull(remote_src_filepath, os.path.join(local_directory, filename))

  def _get_file_paths_in_remote_directory(
      self,
      remote_dir: pathlib.PurePosixPath) -> Iterable[pathlib.PurePosixPath]:
    """Yields the path to all files within a remote directory recursively.

    Args:
      remote_dir: The remote directory path.

    Yields:
      The path to all files in the directory.

    Raises:
      SSHNotConnectedError: If sftp is not connected.
    """
    if self._sftp is None:
      raise SSHNotConnectedError(
          ssh=self,
          message=_SFTP_NOT_CONNECTED_ERROR_MESSAGE,
      )
    for entry in self._sftp.listdir_attr(str(remote_dir)):
      entry_path = remote_dir.joinpath(entry.filename)
      if stat.S_ISDIR(entry.st_mode):
        yield from self._get_file_paths_in_remote_directory(entry_path)
      else:
        yield entry_path

  def pull_remote_directory(self, remote_src_dir: str,
                            local_dest_dir: str) -> None:
    """Pulls all files within a remote directory to local directory recursively.

    Args:
      remote_src_dir: The path to the remote source directory.
      local_dest_dir: The path to the local destination directory.
    """
    for remote_filepath in self._get_file_paths_in_remote_directory(
        pathlib.PurePosixPath(remote_src_dir)):
      # Use Path.joinpath to avoid messing up the forward/backward slashes.
      local_filepath = pathlib.Path(local_dest_dir).joinpath(
          remote_filepath.relative_to(remote_src_dir))
      self.pull(str(remote_filepath), str(local_filepath))

  def rm_dir_or_error(self, remote_dir: str) -> None:
    """Recursively force remove a remote directory or else raise an error.

    On Windows, busy files cannot be deleted. This function makes it easy to
    notice that problem. Usually the solution is to reboot the machine.
    Note that if the directory doesn't exist then no error will be thrown.

    Args:
      remote_dir: string, the remote directory.

    Raises:
      IOError: If the command failed with an error message showing that the
        device is busy. This matches RmFile's IOError.
      SSHRemoteError: If the command failed (exit code other than 0), but
        reason for the failure wasn't clear.
    """
    command_results = self.rm_dir(remote_dir)
    if command_results.exit_code:
      error_string = (
          f'exit code: {command_results.exit_code}, '
          f'output {command_results.output}, error: {command_results.error}')
      if 'Device or resource busy' in command_results.error:
        raise IOError('Likely a process is still using the file that '
                      f'you are trying to delete: {error_string}')
      else:
        raise SSHRemoteError(self, error_string)

  def rm_dir(self, remote_dir: str) -> CommandResults:
    """Recursively removes a remote directory from the remote machine.

    Args:
      remote_dir: the remote directory.

    Returns:
      A container with full command results.
    """
    if self.exists(remote_dir):
      command_results = CommandResults()
      self.execute_command(
          f'rm -rf "{remote_dir}"',
          ignore_error=True,
          command_results_collector=command_results)
      return command_results

    self.log.debug('Remote folder to remove %s does not exist', remote_dir)
    return CommandResults(exit_code=-1)

  def rm_file(self, remote_file: str) -> None:
    """Removes a remote file from the remote machine.

    Args:
      remote_file: the remote file location.

    Raises:
      SSHNotConnectedError: If sftp is not connected.
    """
    if self.exists(remote_file):
      if self._sftp is None:
        raise SSHNotConnectedError(
            ssh=self,
            message=_SFTP_NOT_CONNECTED_ERROR_MESSAGE,
        )
      self._sftp.remove(remote_file)
    else:
      self.log.debug('Remote file to remove %s does not exist', remote_file)

  def make_dirs(self, remote_dir: str) -> None:
    """Recursively makes directories on the remote machine.

    Args:
      remote_dir: string, the remote directory.

    Raises:
      RuntimeError: a component in remote_dir is not a directory.
      SSHNotConnectedError: If sftp is not connected.
    """
    if remote_dir != '/':
      remote_dir = remote_dir.rstrip('/')
    remote_stat_info = self.stat(remote_dir)
    if remote_stat_info:  # path exists
      if stat.S_ISDIR(remote_stat_info.st_mode):
        return  # already a directory; nothing to do.
      else:
        raise RuntimeError('%s is not a directory.' % remote_dir)

    # The 'or' below ensures that dirname of remote_dir is never empty
    self.make_dirs(os.path.dirname(remote_dir) or '.')
    if self._sftp is None:
      raise SSHNotConnectedError(
          ssh=self,
          message=_SFTP_NOT_CONNECTED_ERROR_MESSAGE,
      )
    self._sftp.mkdir(remote_dir)

  def is_dir(self, dir_path: str) -> bool:
    """Checks whether the dir_path is a directory.

    Args:
      dir_path: string, the path to the directory.

    Returns:
      True if dir_path is a valid path to a directory, False otherwise.
    """
    if dir_path != '/':
      dir_path = dir_path.rstrip('/')
    dir_stat_info = self.stat(dir_path)
    return dir_stat_info and stat.S_ISDIR(dir_stat_info.st_mode)

  def is_file(self, file_path: str) -> bool:
    """Checks whether the file_path is a file.

    Args:
      file_path: string, a path to the file

    Returns:
      True if file_path is a valid path to a file, False otherwise.
    """
    file_path = file_path.rstrip('/')
    file_stat_info = self.stat(file_path)
    return file_stat_info and stat.S_ISREG(file_stat_info.st_mode)

  def exists(self, remote_path: str) -> bool:
    """Checks whether the path exists on the remote machine.

    The path can be either to a file or to a folder.

    Args:
      remote_path: The path to the file on the remote machine.

    Returns:
      True if the file exists else False.
    """
    return self.stat(remote_path) is not None

  def stat(self, remote_path: str) -> Optional[sftp_attr.SFTPAttributes]:
    """Obtains stat info of a remote SFTP path on client.

    Args:
      remote_path: The path to the file on the remote machine.

    Returns:
      the SFTP attributes of the remote path.
    """
    try:
      if self._sftp is None:
        raise SSHNotConnectedError(
            ssh=self,
            message=_SFTP_NOT_CONNECTED_ERROR_MESSAGE,
        )
      return self._sftp.stat(remote_path)
    except IOError as e:
      # ENOENT means "no such file or directory."
      if e.errno == errno.ENOENT:
        return None
      raise

  def list_dir(self, path: str) -> Iterable[str]:
    """Return a list containing the names of the entries in the given path.

    The list is in arbitrary order. It does not include the special entries '.'
    and '..' even if they are present in the folder. This method is meant to
    mirror os.listdir as closely as possible.

    Args:
      path: path to list the contents of.

    Returns:
      List of strings contains the names of the entries.

    Raises:
      SSHNotConnectedError: If sftp is not connected.
    """
    if self._sftp is None:
      raise SSHNotConnectedError(
          ssh=self,
          message=_SFTP_NOT_CONNECTED_ERROR_MESSAGE,
      )
    return self._sftp.listdir(path)

  def chmod(self, remote_path: str, mode: int) -> None:
    """Changes the mode (permissions) of a remote file, similar to os.chmod.

    Args:
      remote_path: The path to the file on the remote machine.
      mode: The permission to set on the remote file.

    Raises:
      RemotePathDoesNotExistError: If the file to chmod is missing.
      SSHNotConnectedError: If sftp is not connected.
    """
    if not self.exists(remote_path):
      raise RemotePathDoesNotExistError(
          self,
          f'The file "{remote_path}" to change the permissions does not exist.')

    self.log.debug('chmod %o %r', mode, remote_path)
    if self._sftp is None:
      raise SSHNotConnectedError(
          ssh=self,
          message=_SFTP_NOT_CONNECTED_ERROR_MESSAGE,
      )
    self._sftp.chmod(remote_path, mode)

  def execute_command(
      self,
      command: str,
      timeout: Optional[float] = None,
      ignore_error: bool = False,
      command_results_collector: Optional[CommandResults] = None) -> str:
    """Executes the command in the remote machine.

    The command waits for the remote process to complete and returns the
    result. If the command you run produces large amount of output (either to
    stdout or to stderr), this method will cause a deadlock. For such commands
    please use execute_command_async() or start_remote_process().

    Args:
      command: The command to be executed in the remote machine.
      timeout: Optional timeout in seconds. If a non-negative float is given,
        subsequent channel read/write operations will raise a timeout exception
        if the timeout period value has elapsed before the operation has
        completed. Setting a timeout of None disables timeouts on socket
        operations.
      ignore_error: Whether to raise an exception if the command fails remotely.
      command_results_collector: the container to collect full command results.

    Returns:
      A string representing stripped stdout of the command.

    Raises:
      ExecuteCommandError: Raised if not ignoring error and exit code of command
      is greater than 0.
    """
    self.log.debug('Command to execute on remote machine: %s', command)

    channel_ = self.ssh_client.get_transport().open_session()
    if timeout is not None:
      channel_.settimeout(timeout)

    channel_.exec_command(command)

    command_result = _block_and_get_channel_status(channel_)
    self.log.debug(
        'cmd: %s, stdout: %s, stderr: %s, ret: %d',
        command,
        command_result.output,
        command_result.error,
        command_result.exit_code,
    )

    if command_results_collector:
      for key, value in dataclasses.asdict(command_result).items():
        setattr(command_results_collector, key, value)
    if not ignore_error and command_result.exit_code:
      raise ExecuteCommandError(self, command, command_result)

    return command_result.output.strip()

  def execute_command_async(
      self,
      command: str,
      timeout: Optional[int] = None,
      get_pty: bool = False
  ) -> Tuple[channel.ChannelStdinFile, channel.ChannelFile,
             channel.ChannelStderrFile]:
    """Executes the command in the remote machine.

    This method returns immediately. It doesn't wait for the remote process to
    complete. Also, the remote process started using this command can outlive
    the connection to it. If you execute a long-running command and then exit
    python, then the command will still be running after you exit.

    Args:
      command: The command to be executed in the remote machine.
      timeout: The time in seconds to wait for the command to finish.
      get_pty: Whether to request a pseudo-terminal from the server. This is
        usually used right after creating a client channel, to ask the server to
        provide some basic terminal semantics for a shell invoked with
        invoke_shell. It is not necessary (or desirable) to enable it if you are
        going to execute a single command. But you need to enable it if you
        would like to get output stream continuously when the command is running
        even for a single command.

    Returns:
      The stdin, stdout, and stderr of the executing command.
    """
    self.log.debug('Running command on remote machine: %s', command)
    return self.ssh_client.exec_command(
        command, timeout=timeout, get_pty=get_pty)

  def execute_commands(self,
                       commands: Iterable[str],
                       sleep_interval: int = 0) -> None:
    """Executes batch of commands.

    Args:
      commands: A list of commands to be executed in the remote machine.
      sleep_interval: Number of seconds to sleep between commands.
    """
    for command in commands:
      self.ssh_client.exec_command(command)
      if sleep_interval:
        time.sleep(sleep_interval)

  def start_remote_process(
      self,
      command: str,
      environment: Optional[Mapping[str, str]] = None,
      timeout: Optional[int] = None,
      get_pty: bool = False,
      output_file_path: Optional[str] = None) -> RemotePopen:
    """Executes a command and returns a RemotePopen object.

    Args:
      command: The command to execute on the remote machine.
      environment: A dictionary of environment variables to enable beforehand.
      timeout: The time in seconds to wait for the command to finish.
      get_pty: Whether to request a pseudo-terminal from the server and execute
        the command using the pseudo-terminal. Turn on this switch to
        automatically exit the remote process when disconnecting the SSH client.
        Because the SSH client disconnection will kill the processes running in
        the pseudo-terminal.
      output_file_path: If set, the stdout and stderr of the remote process will
        be streamed to the file at the given host path.

    Returns:
      A RemotePopen to handle the process.
    """
    session = self.ssh_client.get_transport().open_session()
    if get_pty:
      session.get_pty()
    self.log.debug('Starting remote process: %s, environment=%s', command,
                   environment)
    return RemotePopen(
        self,
        session,
        command,
        environment,
        timeout,
        output_file_path=output_file_path)

  def get_remote_file_contents(self, remote_file: str) -> str:
    """Gets the content of a remote file.

    Args:
      remote_file: The remote file location.

    Returns:
      The content of a remote file.

    Raises:
      RemotePathDoesNotExistError: If the file is missing.
      SSHRemoteError: If the command failed (exit code other than 0).
    """
    if not self.exists(remote_file):
      raise RemotePathDoesNotExistError(
          self,
          f'The file to get the contents of ({remote_file}) does not exist on '
          'the remote machine.')

    try:
      stdout = self.execute_command(f'cat "{remote_file}"')
    except ExecuteCommandError as e:
      raise SSHRemoteError(self,
                           f'Error getting remote file: {remote_file}.') from e

    return stdout


class RemotePopen:
  """Manages a remote process.

  Uses the functionality of SSHProxy to build a Popen-like obj. Popen runs a
  process on the local machine, but in contrast this code runs the
  given command on a remote machine using ssh.SSHProxy.

  Attributes:
    pid: the remote process id on the remote machine.
  """

  def __init__(self,
               client: SSHProxy,
               session: channel.Channel,
               command: str,
               environment: Optional[Mapping[str, str]] = None,
               timeout: Optional[int] = None,
               output_file_path: Optional[str] = None) -> None:
    """Initializes the RemotePopen instance.

    Args:
      client: SSHProxy object with an open connection.
      session: SSH session to use for command execution
      command: The command to execute on the remote machine.
      environment: A dictionary of environment variables to enable beforehand.
      timeout: The time in seconds to wait for the command to finish.
      output_file_path: If set, the stdout and stderr of the remote process will
        be streamed to the file at the given host path.
    """
    if environment:
      mapping = ' '.join([f'{k}={v}' for k, v in environment.items()])
      set_env = f'export {mapping} && '
    else:
      set_env = ''
    if timeout is not None:
      session.settimeout(timeout)

    self._wait_timeout_sec = timeout

    if output_file_path is not None:
      # Combine stderr to stdout so we only need to stream the output of one
      # channel file
      session.set_combine_stderr(combine=True)

    # echo $$ writes the pid to stdout.
    session.exec_command(f'echo $$ && {set_env}exec {command}')

    self._client = client
    self._command = command
    self._session = session
    self._stdin = session.makefile('wb')
    self._stdout = session.makefile('rb')
    self._stderr = session.makefile_stderr('rb')
    self.pid = int(self._stdout.readline())

    self._client.log.debug('The remote process(pid=%d) started.', self.pid)

    self._output_streamer: Optional[
        channel_file_streamer.ChannelFileStreamer] = None
    if output_file_path is not None:
      self._start_streaming_remote_proc_output(output_file_path)

  def _start_streaming_remote_proc_output(self, output_file_path: str) -> None:
    """Starts streaming the remote process output to host."""
    logger = mobly_logger.PrefixLoggerAdapter(
        self._client.log,
        {
            mobly_logger.PrefixLoggerAdapter.EXTRA_KEY_LOG_PREFIX:
                f'[RemoteProcess({self.pid})]'
        },
    )
    self._output_streamer = channel_file_streamer.ChannelFileStreamer(
        self._stdout, output_file_path, logger)
    self._output_streamer.start()

  def communicate(self) -> Tuple[str, str]:
    """Returns the stdout and stderr when the command finishes.

    If this object is streaming the remote process output, this method will
    block until the remote process exits or a timeout occurs, then return a pair
    of empty strings.

    Note that the process does not die when it times out. You need to kill it
    with the kill() method below.

    Returns:
      Tuple of stdout and stderr strings.

    Raises:
      RemoteTimeoutError: if the command did not complete in its given time.
    """
    if self._output_streamer is not None:
      if not self._wait_for_remote_process_exit(timeout=self._wait_timeout_sec):
        raise RemoteTimeoutError(
            self._client,
            f'Command did not complete in {self._wait_timeout_sec} seconds.',
        )
      self._stop_streaming_remote_proc_output()
      # Keep similar behavior to Popen, returning empty value when this class is
      # streaming output
      return ('', '')

    try:
      return (self._stdout.read().decode('utf-8'),
              self._stderr.read().decode('utf-8'))
    except socket.timeout as e:
      # socket.timeout is thrown during a read() operation when the timeout
      # given to the execute_command() function is exceeded.
      raise RemoteTimeoutError(
          self._client,
          f'Command did not complete in {self._session.gettimeout()} seconds.'
      ) from e

  def terminate(
      self,
      timeout: int | None = _SIGNAL_CMD_TIMEOUT_SEC,
      assert_process_exit: bool = False,
  ) -> None:
    """Attempts to terminate the remote process using SIGTERM.

    NOTE: If `assert_process_exit=True` and the process did not exit after
    sending SIGTERM, this will try force kill it with SIGKILL. If force kill
    still fails, this will raise an error.

    Args:
      timeout: The time limit in seconds to send the signal.
      assert_process_exit: If True, this will assert that the remote process
        exits after sending SIGTERM. If False, this will simply send the signal
        and return.

    Raises:
      SSHRemoteError: If `assert_process_exit=True` and the remote process did
        not exit.
    """
    self.send_signal(
        signal_id=signal.SIGTERM,
        timeout=timeout,
        assert_process_exit=assert_process_exit,
    )

  def poll(self) -> Optional[int]:
    """A non-blocking method to check the status of this process.

    Returns:
      The exit code of the process if the process has ended, otherwise None.
    """
    if not self._session.exit_status_ready():
      return None
    return self._session.recv_exit_status()

  def kill(
      self,
      timeout: int | None = _SIGNAL_CMD_TIMEOUT_SEC,
      assert_process_exit: bool = False,
  ) -> None:
    """Attempts to kill the remote process.

    NOTE: If `assert_process_exit=True` and the process did not exit after
    sending SIGKILL, this will raise an error.

    Args:
      timeout: The time limit in seconds to send the signal.
      assert_process_exit: If True, this will assert that the remote process
        exits after sending SIGKILL. If False, this will simply send the signal
        and return.

    Raises:
      SSHRemoteError: If `assert_process_exit=True` and the remote process did
        not exit.
    """
    self.send_signal(
        signal_id=signal.SIGKILL,
        timeout=timeout,
        assert_process_exit=assert_process_exit,
    )

  def send_signal(
      self,
      signal_id: int,
      timeout: int | None = _SIGNAL_CMD_TIMEOUT_SEC,
      assert_process_exit: bool = False,
  ) -> None:
    """Attempts to send a signal to the remote process.

    If the `output_file_path` argument is set in the constructor, then this
    method might need additional time to stop streaming output, which will not
    exceed `channel_file_streamer.CHANNEL_FILE_STREAMER_STOP_TIMEOUT_SEC`.

    This supports asserting the process exit after sending the signal.  If
    `assert_process_exit=True`, this will wait for process exit. If process
    did not exit after sending a non-SIGKILL signal, this will sending SIGKILL
    and assert the process exit.

    Args:
      signal_id: The ID of the signal. You can use constants defined in the
        "signal" module, e.g. signal.SIGTERM
      timeout: A timeout on blocking read/write operations. Default is 4 because
        we don't want to wait forever if this command fails.
      assert_process_exit: Whether to assert process exit after sending the
        signal.

    Raises:
      SSHRemoteError: If `assert_process_exit=True` and the process did not exit
        after sending SIGKILL.
    """
    self._do_send_signal(signal_id=signal_id, timeout=timeout)

    if not assert_process_exit:
      return

    if self._wait_for_remote_process_exit(timeout=_WAIT_PROC_EXIT_TIMEOUT_SEC):
      return

    if signal_id == signal.SIGKILL:
      raise SSHRemoteError(
          self._client, f'Failed to force kill the remote process {self.pid}.'
      )

    self._client.log.info(
        'Remote process pid=%d did not exit, sending escalated signal SIGKILL.',
        self.pid,
    )
    # It's ok that the force kill failed, we only need to check the remote
    # process exit status.
    with contextlib.suppress(
        RemoteTimeoutError, SSHRemoteError, ExecuteCommandError
    ):
      self.send_signal(
          signal_id=signal.SIGKILL, timeout=_SIGNAL_CMD_TIMEOUT_SEC
      )

    if not self._wait_for_remote_process_exit(
        timeout=_WAIT_PROC_EXIT_TIMEOUT_SEC
    ):
      raise SSHRemoteError(
          self._client,
          f'Failed to wait for remote process pid={self.pid} to exit.',
      )

  def _do_send_signal(self, signal_id: int, timeout: int | None = 4) -> None:
    """Sends a signal to the remote process."""
    if self.poll() is not None:
      self._stop_streaming_remote_proc_output()
      return

    command_results = CommandResults()
    try:
      self._client.execute_command(
          f'kill -{signal_id} {self.pid}',
          timeout=timeout,
          command_results_collector=command_results)
    except socket.timeout as e:
      raise RemoteTimeoutError(
          self._client,
          f'The kill command timed out after {self._wait_timeout_sec} seconds.'
      ) from e
    except socket.error as e:
      raise SSHRemoteError(
          self._client, 'Send signal failed due to socket error.'
      ) from e
    finally:
      self._stop_streaming_remote_proc_output()

    self._client.log.info(
        'Killed remote process command stdout: <%s>, stderr <%s>, exit code:'
        ' %s',
        command_results.output,
        command_results.error,
        self.poll(),
    )

  def wait(self,
           ignore_error: bool = False,
           command_results_collector: Optional[CommandResults] = None) -> str:
    """Waits until this process has ended and returns the command results.

    Args:
      ignore_error: Whether to raises an exception if the command fails
        remotely.
      command_results_collector: The container to collect full command results.

    Returns:
      A string representing stripped stdout of the command.

    Raises:
      ExecuteCommandError: Raised if not ignoring error and exit code of command
      was greater than 0.
      RemoteTimeoutError: Raised if the command did not complete in its given
      time.
    """
    command_results = command_results_collector or CommandResults()
    try:
      command_results.output, command_results.error = self.communicate()
    except RemoteTimeoutError:
      self.kill()
      raise
    finally:
      command_results.exit_code = self._session.recv_exit_status()

    self._client.log.debug('The remote process(pid=%d) ended.', self.pid)
    if not ignore_error and command_results.exit_code:
      raise ExecuteCommandError(self._client, self._command, command_results)

    self._client.log.debug('exit code: %s', command_results.exit_code)
    self._client.log.debug('output: %s', command_results.output)
    self._client.log.debug('error: %s', command_results.error)
    return command_results.output.strip()

  def _wait_for_remote_process_exit(self, timeout: int | None):
    """Waits for the remote process to exit."""
    deadline_time = None
    if timeout is not None:
      deadline_time = timeout + time.perf_counter()

    while not self._session.exit_status_ready():
      if (deadline_time is not None and time.perf_counter() > deadline_time):
        return False
      time.sleep(1)

    return True

  def _stop_streaming_remote_proc_output(self):
    """Stops streaming output of the remote process."""
    if self._output_streamer is not None:
      self._output_streamer.stop()


def _block_and_get_channel_status(channel_: channel.Channel) -> CommandResults:
  """Gets the exit code, stdout and stderr from a completed process.

  The channel will be blocked.

  Args:
    channel_: The channel to read status from.

  Returns:
    A container with full command results. Output and error are UTF-8 decoded.
  """
  # Blocking wait until the command completes.
  exit_code = channel_.recv_exit_status()

  stdout_file = channel_.makefile('rb')
  stderr_file = channel_.makefile_stderr('rb')

  with contextlib.closing(channel_):  # pytype: disable=wrong-arg-types
    with contextlib.closing(stdout_file):  # pytype: disable=wrong-arg-types
      stdout_str = stdout_file.read().decode('utf-8')
    with contextlib.closing(stderr_file):  # pytype: disable=wrong-arg-types
      stderr_str = stderr_file.read().decode('utf-8')

  return CommandResults(exit_code, stdout_str, stderr_str)


@contextlib.contextmanager
def create_ssh_connection(
    hostname: str,
    ssh_port: int = 22,
    username: str = 'root',
    password: Optional[str] = None,
    keyfile: Optional[str] = None,
    allow_agent: bool = False,
    connect_timeout: Optional[float] = None,
    connect_banner_timeout: Optional[float] = None,
):
  """The context manager to create a SSH connection."""
  ssh_connection = SSHProxy(
      hostname=hostname,
      ssh_port=ssh_port,
      username=username,
      password=password,
      keyfile=keyfile,
      allow_agent=allow_agent,
  )

  try:
    ssh_connection.connect(connect_timeout, connect_banner_timeout)
    yield ssh_connection
  finally:
    ssh_connection.disconnect()
