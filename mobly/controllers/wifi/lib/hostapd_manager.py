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

"""The module for controlling hostpad on AP devices.

The responsibility of this module mainly include:
* Generate hostapd configuration files on AP devices.
* Start/Stop hostpad processes on AP devices.
"""

from collections.abc import Sequence
import contextlib
import dataclasses
import datetime
import logging
import os
import typing
from typing import Any

import immutabledict
from mobly import logger as mobly_logger

from mobly.controllers.wifi.lib import ssh as ssh_lib
from mobly.controllers.wifi.lib import constants
from mobly.controllers.wifi.lib import errors
from mobly.controllers.wifi.lib import iw_utils
from mobly.controllers.wifi.lib import utils
from mobly.controllers.wifi.lib import wifi_configs
from mobly.controllers.wifi.utils import ip_utils


OpenWrtDevice = Any


# The network bridge set up by OpenWrt to bridge wireless networks with the wide
# area network (WAN).
_NETWORK_BRIGE_CONNECTING_WAN = 'br-lan'


_WIFI_START_WAIT_TIME = datetime.timedelta(seconds=30)
# DFS channels require 60s extra start time to check channel availability.
_WIFI_START_WAIT_TIME_DFS = datetime.timedelta(seconds=180)
_WIFI_START_CHECK_INTERVAL = datetime.timedelta(seconds=5)
_WIFI_STOP_WAIT_TIME = datetime.timedelta(seconds=30)


_WIFI_CONFIG_TO_HW_MODE = immutabledict.immutabledict({
    constants.Ieee80211Standards.A: {
        wifi_configs.BandType.BAND_5G: 'a',
    },
    constants.Ieee80211Standards.B: {
        wifi_configs.BandType.BAND_2G: 'b',
    },
    constants.Ieee80211Standards.G: {
        wifi_configs.BandType.BAND_2G: 'g',
    },
    constants.Ieee80211Standards.N: {
        wifi_configs.BandType.BAND_2G: 'g',
        wifi_configs.BandType.BAND_5G: 'a',
    },
    constants.Ieee80211Standards.AC: {
        wifi_configs.BandType.BAND_2G: 'g',
        wifi_configs.BandType.BAND_5G: 'a',
    },
    constants.Ieee80211Standards.AX: {
        wifi_configs.BandType.BAND_2G: 'g',
        wifi_configs.BandType.BAND_5G: 'a',
    },
})

# These default capabilities are enabled to improve the throughput. This is a
# subset of the default settings of UCI.
_DEFAULT_HT_CAPAB = {
    wifi_configs.BandType.BAND_2G: (
        # Enable short guard interval.
        wifi_configs.HostapdHTCapab.SHORT_GI_20,
        wifi_configs.HostapdHTCapab.SHORT_GI_40,
    ),
    wifi_configs.BandType.BAND_5G: (
        # Enable short guard interval.
        wifi_configs.HostapdHTCapab.SHORT_GI_20,
        wifi_configs.HostapdHTCapab.SHORT_GI_40,
        # Enable LDPC codes for error correction. 5GHz only.
        wifi_configs.HostapdHTCapab.LDPC,
    ),
}
_DEFAULT_VHT_CAPAB = {
    wifi_configs.BandType.BAND_2G: (),
    wifi_configs.BandType.BAND_5G: (
        # Enable short guard interval.
        wifi_configs.HostapdVHTCapab.SHORT_GI_80,
        # Enable LDPC codes when receiving and decoding.
        wifi_configs.HostapdVHTCapab.RXLDPC,
    ),
}

# We set fragm_threshold to -1 because the AP might not support setting
# fragmentation threshold when it is not using our custom OpenWrt image. And I
# did not find a way to dynamically check whether setting fragmentation
# threshold is supported or not.
_IS_CUSTOM_OPENWRT_TO_DEFAULT_FRAGM_THRESHOLD = {
    True: 2346,
    False: -1,
}


def _get_default_ht_capab(
    wifi_config: wifi_configs.WiFiConfig,
) -> Sequence[str]:
  """Gets default `ht_capab` configuration."""
  return _DEFAULT_HT_CAPAB[wifi_config.band_type]


def _get_default_vht_capab(
    wifi_config: wifi_configs.WiFiConfig,
) -> Sequence[str]:
  """Gets default `vht_capab` configuration."""
  return _DEFAULT_VHT_CAPAB[wifi_config.band_type]


def _get_center_channel_with_width_80mhz(channel_20mhz: int) -> int:
  """Gets the center channel of a segment of width 80MHz.

  The AP will combines 4 20MHz channels into 1 80MHz. This method takes one
  20MHz channel and returns the 80MHz channel that covers it.

  See Figure "5 GHz Channels, with DFS and TDWR Restrictions" in the following
  link for the correspondence between 20MHz channels and 80MHz channels:

  https://revolutionwifi.blogspot.com/2013/03/80211ac-channel-planning.html

  Args:
    channel_20mhz: A 20MHz channel that is covered by the 80MHz channel.

  Returns:
    The center channel of the 80MHz channel.
  """
  match channel_20mhz:
    case 36 | 40 | 44 | 48:
      return 42
    case 52 | 56 | 60 | 64:
      return 58
    case 100 | 104 | 108 | 112:
      return 106
    case 116 | 120 | 124 | 128:
      return 122
    case 132 | 136 | 140 | 144:
      return 138
    case 149 | 153 | 157 | 161:
      return 155
    case _:
      raise errors.ConfigError(
          'Got unsupported 20MHz channel when using channel width 80MHz:'
          f' {channel_20mhz}'
      )


@dataclasses.dataclass(frozen=True)
class HostapdBssTmReqParams:
  """Parameters for a BSS Transition Management Request.

  Attributes:
    client_mac_address: The MAC address of the client station.
    neighbors: Optional. A sequence of BSSIDs for preferred neighbor APs.
    disassoc_imminent: If True, the AP will indicate imminent disassociation.
    disassoc_timer_100ms: Time in 100ms units before the AP disassociates the
      STA. Only valid if disassoc_imminent is True.
    reassoc_delay_sec: Delay in seconds before STA is permitted to reassociate.
      Assumes MBO is enabled on the AP if this is used, since this is an MBO
      attribute. Only valid if disassoc_imminent is True.
    bss_term_minutes: Duration in minutes for which the current BSS will be
      unavailable. TSF is assumed to be 0 (immediate).
  """

  client_mac_address: str
  neighbors: Sequence[str] = dataclasses.field(default_factory=list)
  disassoc_imminent: bool = False
  disassoc_timer_100ms: int | None = None
  reassoc_delay_sec: int | None = None
  bss_term_minutes: int | None = None


class HostapdConfig:
  """The hostapd configurations.

  When we need to start a WiFi network, we need to transform the user specified
  configurations to a hostapd configuration file. This class representes the
  hostapd configuration file.

  Attributes:
    channel: The WiFi channel.
    ssid: The WiFi SSID.
    password: The WiFi password.
    interface: The name of the network interface that the WiFi network is using.
    bridge: The name of the bridge interface.
    config_content: The content of the hostapd configuration file.
  """

  channel: int
  ssid: str
  password: str | None
  interface: str
  bridge: str | None = None

  _raw: dict[str, str]

  def __init__(
      self,
      interface: str,
      dfs_channels: set[int],
      is_custom_openwrt: bool,
      ctrl_socket_path: str,
      bridge: str | None = None,
  ):
    self._dfs_channels = dfs_channels
    self._raw = {}
    self.update('logger_syslog', '-1')
    self.update('logger_syslog_level', '0')
    self.update('rts_threshold', '-1')
    self.update('driver', 'nl80211')
    self.update(
        'fragm_threshold',
        str(_IS_CUSTOM_OPENWRT_TO_DEFAULT_FRAGM_THRESHOLD[is_custom_openwrt]),
    )
    self.set_interface(interface)
    # Set control interface for hostapd_cli
    self.update('ctrl_interface', ctrl_socket_path)
    # Common group for hostapd_cli, 0 means root/admin.
    self.update('ctrl_interface_group', '0')
    if bridge is not None:
      self.set_bridge(bridge)

  def update(self, key: str, value: str):
    self._raw[key] = value

  def get(self, key: str) -> str | None:
    """Gets the value of the given key.

    Args:
      key: The key to get the value.

    Returns:
      The value of the given key, or None if the key is not found.
    """
    if key not in self._raw:
      return None
    return self._raw[key]

  def update_from_wifi_config(self, wifi_config: wifi_configs.WiFiConfig):
    """Updates this object according to the `WiFiConfig` object."""
    self.set_ssid(wifi_config.ssid)
    if wifi_config.use_random_bssid:
      bssid = wifi_configs.generate_random_bssid()
      self.update('bssid', bssid)

    # TODO: Better API is returning a dict / hostapd_conf and merge
    # it.
    self._update_encryption_configs(wifi_config)
    self.set_channel(wifi_config.channel)
    self._update_dfs_channel_config(wifi_config)

    self.update('ieee80211d', '1')  # Required when country_code is set.
    self.update('country_code', wifi_config.country_code)
    self.update('hw_mode', self._get_hw_mode(wifi_config))
    self._update_according_to_wifi_standard(wifi_config)

    if not wifi_config.access_wan_through_nat:
      self.update('bridge', _NETWORK_BRIGE_CONNECTING_WAN)

    if wifi_config.pmf is not None:
      self.update('ieee80211w', str(wifi_config.pmf.value))

    if wifi_config.hidden:
      self.update('ignore_broadcast_ssid', '1')

    for key, value in wifi_config.custom_hostapd_configs.items():
      self.update(key, value)

  def set_ssid(self, value: str):
    self.ssid = value
    self.update('ssid2', f'"{value}"')

  def set_password(self, value: str | None):
    self.password = value

  def set_interface(self, value: str):
    self.interface = value
    self.update('interface', value)

  def set_channel(self, value: int):
    self.channel = value
    self.update('channel', str(value))

  def set_bridge(self, value: str):
    self.bridge = value
    self.update('bridge', value)

  def is_using_a_dfs_channel(self) -> bool:
    """Returns true if the channel is a DFS channel."""
    return self.channel in self._dfs_channels

  @property
  def config_content(self) -> str:
    return '\n'.join(f'{key}={value}' for key, value in self._raw.items())

  def write_to_file(self, filepath: str, content: str) -> None:
    """Writes the configurations to the given host filepath."""
    with open(filepath, 'w') as f:
      f.write(content)

  def _get_hw_mode(self, wifi_config: wifi_configs.WiFiConfig) -> str:
    """Get the hwmode."""
    band_type_to_hw_mode = _WIFI_CONFIG_TO_HW_MODE.get(wifi_config.standard)
    if band_type_to_hw_mode is None:
      raise errors.ConfigError(
          f'Got unknown WiFi standard: {wifi_config.standard}'
      )

    hw_mode = band_type_to_hw_mode.get(wifi_config.band_type)
    if hw_mode is None:
      raise errors.ConfigError(
          f'Got unsupported band type "{wifi_config.band_type}" under WiFi'
          f' standard "{wifi_config.standard}"'
      )
    return hw_mode

  def _update_dfs_channel_config(self, wifi_config: wifi_configs.WiFiConfig):
    if not self.is_using_a_dfs_channel():
      return
    if wifi_config.country_code is None:
      raise errors.ConfigError(
          'Country code must be set when using a DFS channel.'
      )

    # This is required for ieee80211h
    self.update('ieee80211d', '1')
    # This enables radar detection and DFS support.
    self.update('ieee80211h', '1')

  def _update_according_to_wifi_standard(
      self, wifi_config: wifi_configs.WiFiConfig
  ):
    self._update_11n_configs(wifi_config)
    self._update_11ac_configs(wifi_config)
    self._update_11ax_configs(wifi_config)

  def _update_11n_configs(self, wifi_config: wifi_configs.WiFiConfig):
    """Updates 802.11N related configurations."""
    if wifi_config.standard not in constants.STANDARDS_SUPPORT_HT_CAPAB:
      return
    self.update('ieee80211n', '1')
    self.update('wmm_enabled', '1')  # Required when HT capabilities are used.
    if ht_capab := self._get_ht_capab(wifi_config):
      self.update('ht_capab', ht_capab)

  def _get_ht_capab(self, wifi_config: wifi_configs.WiFiConfig) -> str:
    """Gets the value for `ht_capab` in hostapd config file."""
    ht_capab = wifi_config.ht_capab
    if ht_capab is None:
      ht_capab = list(_get_default_ht_capab(wifi_config))
    if wifi_config.width != wifi_configs.ChannelWidth.WIDTH_20:
      capab = wifi_configs.CHANNEL_HOSTAPD_HT40_MODE.get(wifi_config.channel)
      if capab is not None and capab not in ht_capab:
        ht_capab = ht_capab + [capab]
    return ''.join(ht_capab)

  def _update_11ac_configs(self, wifi_config: wifi_configs.WiFiConfig):
    """Updates 802.11AC related configurations."""
    if wifi_config.standard not in constants.STANDARDS_SUPPORT_VHT_CAPAB:
      return
    self.update('ieee80211ac', '1')

    width = typing.cast(wifi_configs.ChannelWidth, wifi_config.width)
    self.update('vht_oper_chwidth', width.to_hostapd_enum())

    if wifi_config.band_type == wifi_configs.BandType.BAND_2G:
      return

    if wifi_config.width == wifi_configs.ChannelWidth.WIDTH_80:
      self.update(
          'vht_oper_centr_freq_seg0_idx',
          str(_get_center_channel_with_width_80mhz(wifi_config.channel)),
      )

    # vht_capab
    vht_capab = wifi_config.vht_capab
    if vht_capab is None:
      vht_capab = _get_default_vht_capab(wifi_config)
    if vht_capab:
      self.update('vht_capab', ''.join(vht_capab))

  def _update_11ax_configs(self, wifi_config: wifi_configs.WiFiConfig):
    """Updates 802.11AX related configurations."""
    if wifi_config.standard not in constants.STANDARDS_SUPPORT_HE_CAPAB:
      return
    self.update('ieee80211ax', '1')

    width = typing.cast(wifi_configs.ChannelWidth, wifi_config.width)
    self.update('he_oper_chwidth', width.to_hostapd_enum())

    if wifi_config.band_type == wifi_configs.BandType.BAND_2G:
      return

    if wifi_config.width == wifi_configs.ChannelWidth.WIDTH_80:
      self.update(
          'he_oper_centr_freq_seg0_idx',
          str(_get_center_channel_with_width_80mhz(wifi_config.channel)),
      )

  def _update_encryption_configs(
      self, wifi_config: wifi_configs.WiFiConfig
  ):
    """Updates the encryption configuration."""
    # Feed this to the encryption config checking.
    if wifi_config.pmf is not None:
      self.update('ieee80211w', str(wifi_config.pmf.value))
    wifi_config.encryption_config.update_hostapd_conf(hostapd_conf=self)


class HostapdManager:
  """The class for managing one hostapd instance on the AP device."""

  def __init__(
      self,
      device: 'OpenWrtDevice',
      wifi_id: int,
      phy: iw_utils.Phy,
      interface: str,
      wifi_config: wifi_configs.WiFiConfig,
      bridge: str | None = None,
      base_logger: (
          logging.Logger | mobly_logger.PrefixLoggerAdapter | None
      ) = None,
  ):
    """Constructor.

    Args:
      device: The AP device controller object.
      wifi_id: The unique ID of the WiFi network to start.
      phy: The wireless hardware device that the WiFi network is using.
      interface: The name of the network interface that the WiFi network is
        using.
      wifi_config: The WiFi configurations.
      bridge: The name of the bridge interface.
      base_logger: The base logger. Based on that logger, this class will prefix
        each log entry with string "[HostapdManager]".
    """
    self._device = device
    self._wifi_id = wifi_id
    self._wifi_config = wifi_config
    self._phy = phy
    self._interface = interface
    self._bridge = bridge
    self._bssid = None

    self._hostapd_config = None
    self._wifi_info = None
    self._remote_process = None
    self._identifier = f'wifi{self._wifi_id},{self._interface}'

    base_logger = base_logger or device.log
    self._log = mobly_logger.PrefixLoggerAdapter(
        base_logger,
        {
            mobly_logger.PrefixLoggerAdapter.EXTRA_KEY_LOG_PREFIX: (
                f'[HostapdManager|wifi{self._wifi_id}]'
            )
        },
    )
    self._local_work_dir = self._device.log_path
    self._remote_work_dir = self._device.remote_work_dir

  def start(self) -> wifi_configs.WifiInfo:
    """Starts this hostapd manager instance."""
    self._log.debug('Starting a remote hostapd instance.')
    try:
      return self._start()
    except (errors.BaseError, ssh_lib.SSHRemoteError):
      self._log.error('Stopping due to start failure.')
      with contextlib.suppress(errors.BaseError, ssh_lib.SSHRemoteError):
        self.stop()
      raise

  def _start(self) -> wifi_configs.WifiInfo:
    """Starts a hostapd process using given configs on the AP device."""
    dfs_channels = iw_utils.get_all_dfs_channels(self._phy)
    self._log.debug(
        'All DFS channels on phy %s: %s', self._phy.name, sorted(dfs_channels)
    )

    self._hostapd_config = HostapdConfig(
        interface=self._interface,
        dfs_channels=dfs_channels,
        is_custom_openwrt=utils.is_using_custom_image(self._device),
        ctrl_socket_path=self._remote_work_dir,
        bridge=self._bridge,
    )
    self._hostapd_config.update_from_wifi_config(self._wifi_config)

    self._bssid = None
    conf_remote_path = self._generate_remote_config_file()
    self._start_hostpad_process(conf_remote_path)

    self._bssid = typing.cast(str, self._bssid)
    self._wifi_info = wifi_configs.WifiInfo(
        id=self._wifi_id,
        ssid=self._hostapd_config.ssid,
        password=self._hostapd_config.password,
        interface=self._interface,
        phy_name=self._phy.name,
        bssid=self._bssid,
        bridge=self._bridge,
    )

    return self._wifi_info

  def _generate_remote_config_file(self) -> str:
    """Generates the hostapd config file on the AP device."""
    filename = self._get_conf_filename()
    local_path = self._get_local_path(filename)
    remote_path = self._get_remote_path(filename)

    self._hostapd_config = typing.cast(HostapdConfig, self._hostapd_config)
    config_content = self._hostapd_config.config_content
    self._hostapd_config.write_to_file(local_path, config_content)
    self._device.push_file(local_path, remote_path)

    # Rename the local file so it can be directly opened on Sponge.
    os.rename(local_path, f'{local_path}.txt')
    return remote_path

  def _start_hostpad_process(
      self,
      conf_remote_path: str,
  ):
    """Starts the hostapd process and waits until the WiFi is ready."""
    log_file_path = self._get_local_path(self._get_log_filename())
    command = constants.Commands.HOSTAPD_START.format(
        conf_path=conf_remote_path,
    )
    proc = self._device.ssh.start_remote_process(
        command, get_pty=True, output_file_path=log_file_path
    )
    self._remote_process = proc

    self._hostapd_config = typing.cast(HostapdConfig, self._hostapd_config)
    wait_timeout = (
        _WIFI_START_WAIT_TIME_DFS
        if self._hostapd_config.is_using_a_dfs_channel()
        else _WIFI_START_WAIT_TIME
    )
    if not utils.wait_for_predicate(
        predicate=self._is_wifi_ready,
        timeout=wait_timeout,
        interval=_WIFI_START_CHECK_INTERVAL,
    ):
      raise errors.HostapdStartError(
          'Failed to start hostapd. Please check the hostapd log'
          f' {self._get_log_filename()} and config {self._get_conf_filename()}.'
      )

    self._log.debug('Started remote hostapd process.')

  def _is_wifi_ready(self):
    """Returns whether the WiFi is ready.

    If WiFi is ready, `self._bssid` will be set to the BSSID of the WiFi
    network.
    """
    if self._remote_process is None:
      raise errors.HostapdStartError(
          'Hostapd process is not set. Please check whether hostapd object'
          ' has not been started or is already stopped.'
      )
    if self._remote_process.poll() is not None:
      raise errors.HostapdStartError(
          'Hostapd process has exited unexpectedly on the AP device. Please'
          f' check the hostapd log file {self._get_log_filename()} and conf'
          f' file {self._get_conf_filename()}'
      )

    cmd = constants.Commands.IP_LINK_SHOW.format(interface=self._interface)
    stdout = self._device.ssh.execute_command(
        command=cmd,
        timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
        ignore_error=True,
    )
    if 'state UP' not in stdout:
      return False

    intfs_all = ip_utils.parse_all_ip_addr(stdout)
    if len(intfs_all) != 1:
      raise errors.HostapdStartError(
          f'Got unexpected number of interfaces in "{cmd}" output: {intfs_all}.'
      )
    intf = intfs_all[0]
    self._bssid = intf.mac_address
    self._log.debug('WiFi AP is ready. Interface info: %s', intf)
    return True

  def __del__(self):
    self.stop()

  def stop(self):
    """Stops the remote hostapd process."""
    if self._remote_process is None:
      return

    self._log.debug(
        'Stopping hostapd process %d.',
        self._remote_process.pid,
    )
    self._bssid = None
    proc = self._remote_process
    self._remote_process = None
    proc.terminate(
        timeout=_WIFI_STOP_WAIT_TIME.total_seconds(), assert_process_exit=True
    )

  def _get_ctrl_socket_path(self) -> str:
    """Gets the path of the control socket.

    Raises:
      errors.ConfigError: If the control socket path is not set.

    Returns:
      The path of the control socket.
    """
    self._hostapd_config = typing.cast(HostapdConfig, self._hostapd_config)
    ctrl_interface = self._hostapd_config.get('ctrl_interface')
    if ctrl_interface is None:
      raise errors.ConfigError('ctrl_interface is not set.')
    return ctrl_interface

  def _run_hostapd_cli_command(self, command_args: Sequence[str]) -> str:
    """Runs a hostapd_cli command for the managed interface.

    Args:
      command_args: A sequence of arguments to pass to hostapd_cli (e.g.,
        ["list_sta"], ["bss_tm_req", "00:11:22:aa:bb:cc",
        "disassoc_imminent=1"]).

    Returns:
      The stdout from the command.

    Raises:
      errors.BaseError: If the hostapd process is not running.
      ssh_lib.ExecuteCommandError: If the command execution fails.
    """
    if self._remote_process is None or self._remote_process.poll() is not None:
      raise errors.BaseError(
          'Hostapd process is not running. Cannot execute hostapd_cli command.'
      )

    ctrl_path = self._get_ctrl_socket_path()
    full_command_str = constants.Commands.HOSTAPD_CLI.format(
        ctrl_path=ctrl_path,
        interface=self._interface,
        command_args=' '.join(command_args),
    )
    self._log.debug('Executing hostapd_cli command: %s', full_command_str)
    output = self._device.ssh.execute_command(
        command=full_command_str,
        timeout=constants.CMD_SHORT_TIMEOUT.total_seconds(),
    )
    return output.strip()

  def _get_remote_path(self, filename: str) -> str:
    return os.path.join(self._remote_work_dir, filename)

  def _get_local_path(self, filename: str) -> str:
    return os.path.join(self._local_work_dir, filename)

  def _get_conf_filename(self) -> str:
    return f'{self._identifier},hostapd.conf'

  def _get_log_filename(self) -> str:
    return f'{self._identifier},hostapd.log'

  def send_bss_tm_request(self, params: HostapdBssTmReqParams) -> str:
    """Sends a BSS Transition Management Request to a client.

    Args:
      params: The parameters for the BSS TM Request.

    Returns:
      The stdout from the hostapd_cli command.
    """
    command_args = ['BSS_TM_REQ', params.client_mac_address]

    for neighbor_bssid in params.neighbors:
      command_args.append(f'neighbor={neighbor_bssid},0,0,0,0')
    if params.neighbors:
      command_args.append('pref=1')

    if params.disassoc_imminent:
      command_args.append('disassoc_imminent=1')
      if params.disassoc_timer_100ms is not None:
        command_args.append(f'disassoc_timer={params.disassoc_timer_100ms}')
      if params.reassoc_delay_sec is not None:
        # MBO attribute for reassoc delay: mbo=3:<reassoc_delay_sec>:0
        # Assumes MBO is enabled on the AP if this is used.
        command_args.append(f'mbo=3:{params.reassoc_delay_sec}:0')
    elif (
        params.disassoc_timer_100ms is not None
        or params.reassoc_delay_sec is not None
    ):
      self._log.warning(
          'disassoc_timer or reassoc_delay specified without'
          ' disassoc_imminent=True. These parameters might be ignored by'
          ' hostapd.'
      )

    if params.bss_term_minutes is not None and params.bss_term_minutes > 0:
      # hostapd_cli bss_term format is bss_term=<tsf_hex>,<duration_minutes>
      # Using TSF 0, which means the BSS will be terminated immediately.
      command_args.append(f'bss_term=0,{params.bss_term_minutes}')

    return self._run_hostapd_cli_command(command_args)

  def set_hostapd_property(self, property_name: str, value: str) -> None:
    """Sets the property of the hostapd daemon.

    This function executes the `hostapd_cli set` command to modify a specific
    property of the running hostapd instance.

    Args:
      property_name: The name of the property to set. (e.g.,
        'mbo_assoc_disallow')
      value: The value to assign to the property.

    Raises:
      errors.HostapdSetPropertyError: If setting the property fails.
    """
    command_args = ['set', property_name, value]
    try:
      output = self._run_hostapd_cli_command(command_args)
    except (ssh_lib.ExecuteCommandError, errors.BaseError) as e:
      raise errors.HostapdSetPropertyError(
          f'Failed to set hostapd property {property_name} to {value}.'
      ) from e
    if output.strip() != 'OK':
      raise errors.HostapdSetPropertyError(
          f'Failed to set hostapd property {property_name} to {value}.'
          f' Output: {output}'
      )

  def channel_switch(
      self,
      target_channel: int,
      beacon_count: int,
      optional_args: Sequence[str] | None = None,
  ) -> None:
    """Performs a channel switch from the current channel to the target channel.

    Args:
      target_channel: The target channel to switch to.
      beacon_count: The number of beacons to send before switching channels.
      optional_args: Optional arguments to pass to the hostapd_cli command.

    Raises:
      errors.HostapdChannelSwitchError: If the channel switch fails.
    """
    if target_channel not in constants.CHANNEL_TO_FREQUENCY:
      raise errors.HostapdChannelSwitchError(
          f'Target channel {target_channel} is not a valid channel.'
      )
    command_args = [
        'chan_switch',
        str(beacon_count),
        str(constants.CHANNEL_TO_FREQUENCY[target_channel]),
    ]
    if optional_args:
      command_args.extend(optional_args)

    try:
      output = self._run_hostapd_cli_command(command_args)
    except (ssh_lib.ExecuteCommandError, errors.BaseError) as e:
      raise errors.HostapdChannelSwitchError(
          f'Failed to switch channel to {target_channel}.'
      ) from e
    if output.strip() != 'OK':
      raise errors.HostapdChannelSwitchError(
          f'Failed to switch channel to {target_channel}.'
          f' Output: {output}'
      )
