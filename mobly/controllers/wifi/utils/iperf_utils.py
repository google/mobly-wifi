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

"""Utilities for using iperf to measure network speed."""

from collections.abc import Sequence
import time

from mobly.controllers import android_device

from mobly.controllers.wifi import openwrt_device
from mobly.controllers.wifi.lib import wifi_configs

_IPERF_CMD = 'iperf3'
_DEFAULT_IPERF_TEST_DURATION_SEC = 10

INVALID_INT = -1
DEFAULT_CLIENT_ARGS = '-t {test_duration_sec} -P1'
DEFAULT_SERVER_ARGS = '-f m'
IPERF_SERVER_START_DELAY_SEC = 1


class IperfServerOnOpenWrt:
  """Class that handles iperf3 server operations on OpenWrt devices."""

  def __init__(
      self, device: openwrt_device.OpenWrtDevice, arg: str = DEFAULT_SERVER_ARGS
  ):
    """Constructor."""
    self._device = device
    self._cmd = f'{_IPERF_CMD} -s {arg}'
    self._iperf_process = None

  def start(self):
    """Starts iperf server on the OpenWrt device."""
    if self._iperf_process is not None:
      return

    self._iperf_process = self._device.ssh.start_remote_process(
        command=self._cmd,
        get_pty=True,
    )

  def stop(self):
    """Stops the iperf server on the OpenWrt device."""
    if not self._iperf_process:
      return
    proc = self._iperf_process
    self._iperf_process = None
    proc.terminate(assert_process_exit=True)
    stdout, stderr = proc.communicate()
    self._device.log.info('Iperf server stdout: %s, stderr: %s', stdout, stderr)


def run_iperf_test(
    network_client: android_device.AndroidDevice,
    network_owner: openwrt_device.OpenWrtDevice,
    wifi_info: wifi_configs.WifiInfo,
    test_duration_sec: int = _DEFAULT_IPERF_TEST_DURATION_SEC,
) -> tuple[bool, Sequence[str]]:
  """Runs iperf test from network_client to network_owner.

  Args:
    network_client: Android device that is the client in the iperf test.
    network_owner: OpenWrt device that is the server in the iperf test.
    wifi_info: The information for the WiFi network to be tested.
    test_duration_sec: The duration of the iperf test.

  Returns:
    A tuple of following values:
      status: True if iperf ran successfully.
      results: The iperf data flow information printed by iperf client.
  """
  owner_addr = get_ap_ip(network_owner, wifi_info.interface)
  if not owner_addr:
    return False, []

  client_arg = DEFAULT_CLIENT_ARGS.format(test_duration_sec=test_duration_sec)
  server_arg = DEFAULT_SERVER_ARGS

  server = IperfServerOnOpenWrt(network_owner, server_arg)
  try:
    network_owner.log.info('Starting iperf server.')
    server.start()
    time.sleep(IPERF_SERVER_START_DELAY_SEC)
    network_client.log.info(f'Starting iperf client {owner_addr}.')
    success, result_list = network_client.run_iperf_client(
        owner_addr, client_arg
    )
    return success, result_list
  except android_device.adb.AdbError:
    network_client.log.info('iperf failed on client.')
    network_owner.ssh.execute_command('ifconfig')
    network_client.adb.shell('ifconfig')
  finally:
    server.stop()
  return False, []


def get_ap_ip(
    ap: openwrt_device.OpenWrtDevice,
    interface: str,
) -> str:
  """Gets the IP address of the OpenWrt device."""
  ifconfig = get_ap_ifconfig(ap, interface)
  return get_substr_between_prefix_postfix(ifconfig, 'inet addr:', 'Bcast')


def get_substr_between_prefix_postfix(
    string: str, prefix: str, postfix: str
) -> str:
  """Gets substring between prefix and postfix."""
  right_index = string.rfind(postfix)
  if right_index == -1:
    return ''
  left_index = string[:right_index].rfind(prefix)
  if left_index > 0:
    try:
      return string[left_index + len(prefix) : right_index].strip()
    except IndexError:
      return ''
  return ''


def get_ap_ifconfig(ap: openwrt_device.OpenWrtDevice, interface: str) -> str:
  """Gets network info on the OpenWrt device."""
  return ap.ssh.execute_command(
      f'ifconfig | grep -A6 {interface}', ignore_error=True
  )


def get_ad_ifconfig(ad: android_device.AndroidDevice) -> str:
  """Gets network info from adb shell ifconfig."""
  return ad.adb.shell('ifconfig').decode('utf-8').strip()
