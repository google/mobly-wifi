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

"""Constants for the AP controller module."""

import datetime
import enum
import re

import immutabledict

CMD_SHORT_TIMEOUT = datetime.timedelta(seconds=10)

# A short summary:
# * US: 1 - 11, 36 - 64, 100 - 144, 149 - 173 are valid. 52 - 144 are DFS
#   channels.
# * Japan: 1 - 14, 36 - 64, 100 - 140 are valid. 52 - 140 are DFS channels.
CHANNEL_TO_FREQUENCY = immutabledict.immutabledict({
    # 2G
    1: 2412,
    2: 2417,
    3: 2422,
    4: 2427,
    5: 2432,
    6: 2437,
    7: 2442,
    8: 2447,
    9: 2452,
    10: 2457,
    11: 2462,
    12: 2467,
    13: 2472,
    14: 2484,
    # 5G
    36: 5180,
    38: 5190,
    40: 5200,
    42: 5210,
    44: 5220,
    46: 5230,
    48: 5240,
    52: 5260,
    56: 5280,
    60: 5300,
    64: 5320,
    100: 5500,
    104: 5520,
    108: 5540,
    112: 5560,
    116: 5580,
    120: 5600,
    124: 5620,
    128: 5640,
    132: 5660,
    136: 5680,
    140: 5700,
    144: 5720,
    149: 5745,
    153: 5765,
    157: 5785,
    161: 5805,
    165: 5825,
    169: 5845,
    173: 5865,
})


@enum.unique
class Ieee80211Standards(enum.StrEnum):
  """The enum for IEEE 802.11 standards."""

  A = 'IEEE802.11a'
  B = 'IEEE802.11b'
  G = 'IEEE802.11g'
  N = 'IEEE802.11n'
  AC = 'IEEE802.11ac'
  AX = 'IEEE802.11ax'


STANDARDS_SUPPORT_HT_CAPAB = (
    Ieee80211Standards.N,
    Ieee80211Standards.AC,
    Ieee80211Standards.AX,
)

STANDARDS_SUPPORT_VHT_CAPAB = (
    Ieee80211Standards.AC,
    Ieee80211Standards.AX,
)

STANDARDS_SUPPORT_HE_CAPAB = (Ieee80211Standards.AX,)


@enum.unique
class IptablesAction(enum.StrEnum):

  INSERT = '-I'
  DELETE = '-D'


@enum.unique
class Commands(enum.StrEnum):
  """Commands to be executed on AP devices."""

  IP_FLUSH = 'ip addr flush {iface}'
  IP_ADDR_ADD = (
      'ip addr add {server_ip}/{network_mask_len} dev {iface} broadcast'
      ' {broadcast_ip}'
  )
  IP_LINK_SHOW = 'ip link show {interface}'
  IP_LINK_UP = 'ip link set {interface} up'

  IW_PHY = 'iw phy'
  IW_PHY_INFO = 'iw phy {phy} info'
  IW_REG_SET = 'iw reg set {country_code}'
  IW_REG_GET = 'iw reg get'
  IW_DEV = 'iw dev'
  IW_DEV_DEL = 'iw dev {interface} del'
  IW_DEV_ADD = 'iw phy {phy} interface add {interface} type managed'
  IW_DEV_ADD_MONITOR = 'iw phy {phy} interface add {interface} type monitor'
  IW_DEV_INFO = 'iw dev {interface} info'
  IW_DEV_STATION_DUMP = 'iw dev {interface} station dump'
  IW_DEV_STATION_GET = 'iw dev {interface} station get {station_mac_address}'
  IW_DEV_SET_FREQ = 'iw dev {interface} set freq {freq_args}'
  IW_DEV_SET_MAXIMUM_TXPOWER = (
      'iw dev {interface} set txpower limit {txpower_mbm}'
  )

  # Firewall rules related commands
  FIREWALL_ENABLE_IP_FORWARD = 'echo 1 > /proc/sys/net/ipv4/ip_forward'
  FIREWALL_ENABLE_NAT = (
      'iptables -t nat -I POSTROUTING -o {interface} -j MASQUERADE'
  )
  FIREWALL_FORWARD_TRAFFIC = (
      'iptables {action} FORWARD -i {in_interface} -o {out_interface} -j ACCEPT'
  )
  FIREWALL_FORWARD_KNOWN_TRAFFIC = (
      'iptables {action} FORWARD -i {in_interface} -o {out_interface} -m'
      ' conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT'
  )

  START_TCPDUMP = (
      'tcpdump -vv -i {interface} -U -e -B 1024 -w {file_path} {args}'
  )

  # Opkg commands.
  OPKG_LIST = 'opkg list-installed {package}'
  OPKG_UPDATE = 'opkg update'
  OPKG_INSTALL = 'opkg install {package}'

  HOSTAPD_START = '/usr/sbin/hostapd -dd -t -K {conf_path}'

  KILLALL = 'killall {name}'

  GET_PROCESS_BY_NAME = 'ps | grep {name}'

  REBOOT = 'sudo reboot'

  CHECK_DEVICE_REBOOT_READY = 'test -f /tmp/cros/status/ready'

  # The command to obtain syslog in OpenWrt systems.
  LOGREAD = 'logread -f'


# The network interface to for the AP device to connect with wide area network.
WAN_INTERFACE = 'br-lan'

# Constant fot the name of hostapd.
HOSTAPD = 'hostapd'


# The AP device SSH username.
SSH_USERNAME = 'root'

REMOTE_WORK_DIR = '/tmp/mobly_artifacts'
OPENWRT_RELEASE_INFO_FILE_PATH = '/etc/openwrt_release'
CURSTOM_RELEASE_INFO_FILE_PATH = '/etc/cros/cros_openwrt_image_build_info.json'

OPENWRT_PACKAGE_IPTABLES = 'iptables'
OPENWRT_PACKAGE_SFTP = 'openssh-sftp-server'
OPENWRT_PACKAGE_SUDO = 'sudo'
OPENWRT_PACKAGE_HOSTAPD = 'hostapd'
OPENWRT_PACKAGE_TCPDUMP = 'tcpdump'
OPENWRT_PACKAGE_IPERF3 = 'iperf3'

# Required packages when using an OpenWrt image built against snapshot.
# * Do NOT include `iptables` because snapshot images have limitation on
#   installing kernel version dependent modules. Reference:
#   https://openwrt.org/releases/snapshot
REQUIRED_PACKAGES_SNAPSHOT = (
    OPENWRT_PACKAGE_SUDO,
    OPENWRT_PACKAGE_TCPDUMP,
    OPENWRT_PACKAGE_IPERF3,
)

# Required packages when using an official OpenWrt image.
# * Do NOT include `hostapd` because it might be installed but not through
#   opkg.
REQUIRED_PACKAGES_OFFICIAL = (
    OPENWRT_PACKAGE_SUDO,
    OPENWRT_PACKAGE_TCPDUMP,
    OPENWRT_PACKAGE_IPERF3,
)

DEVICE_INFO_PATTERN = re.compile(
    r"DISTRIB_ID='(?P<image_type>.*)'\n"
    r"DISTRIB_RELEASE='(?P<release>.*)'\n"
    r"DISTRIB_REVISION='(?P<revision>.*)'\n"
    r"DISTRIB_TARGET='(?P<target>.*)'\n"
    r"DISTRIB_ARCH='(?P<arch>.*)'\n"
    r"DISTRIB_DESCRIPTION='(?P<description>.*)'\n"
    r"DISTRIB_TAINTS='(?P<taints>.*)'"
)
