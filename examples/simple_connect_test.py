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

"""A simple connect example test.

It perform following steps on various Wi-Fi configurations:

1. Start Wi-Fi network with a given configuration.
2. Connect an Android device to the started Wi-Fi network. It raises an error if
   failed to connect.

NOTE: This test depends on Mobly bundled snippets. So please follow belowe link
to build and install it on your Android phone before running this test:

https://github.com/google/mobly-bundled-snippets
"""

import dataclasses
import datetime
import enum
import re
import time

from mobly import asserts
from mobly import base_test
from mobly import test_runner
from mobly import utils
from mobly.controllers import android_device
from mobly.controllers.android_device_lib import adb
from mobly.controllers.wifi import openwrt_device
from mobly.controllers.wifi.lib import wifi_configs
from mobly.controllers.wifi.lib.encryption import open as encryption_type_open
from mobly.controllers.wifi.lib.encryption import wpa


_MESSAGE_MOBLY_SNIPPET_BUNDLE_IS_NOT_INSTALLED = """
=======================SNIPPET APK NOT INSTALLED===============================

This test depends on Mobly bundled snippets. So please follow belowe link to
build and install it on your Android phone before running this test:

https://github.com/google/mobly-bundled-snippets

=======================SNIPPET APK NOT INSTALLED===============================
"""


class SimpleConnectTest(base_test.BaseTestClass):

  def setup_class(self):
    # Register an Android device.
    self.ad = self.register_controller(android_device)[0]

    # Load Android snippet.
    try:
      self.ad.load_snippet('mbs', 'com.google.android.mobly.snippet.bundled')
    except Exception:
      logging.error(_MESSAGE_MOBLY_SNIPPET_BUNDLE_IS_NOT_INSTALLED)

    # Register OpenWrt devices.
    self.openwrt = self.register_controller(openwrt_device)[0]

  def test_wifi_with_5g(self):
    wifi_config = wifi_configs.WiFiConfig(channel=36)
    self._start_wifi_and_connect(wifi_config)

  def test_wifi_with_2g(self):
    wifi_config = wifi_configs.WiFiConfig(channel=6)
    self._start_wifi_and_connect(wifi_config)

  def test_wifi_with_a_dfs_channel(self):
    wifi_config = wifi_configs.WiFiConfig(
        channel=52,
        country_code='US',
    )
    self._start_wifi_and_connect(wifi_config)

  def test_wifi_with_5g_11ac_80mhz(self):
    wifi_config = wifi_configs.WiFiConfig(
        standard=wifi_configs.Ieee80211Standards.AC,
        channel=36,
        width=wifi_configs.ChannelWidth.WIDTH_80,
    )
    self._start_wifi_and_connect(wifi_config)

  def test_wifi_with_5g_11ac_80mhz_dfs(self):
    wifi_config = wifi_configs.WiFiConfig(
        standard=wifi_configs.Ieee80211Standards.AC,
        channel=52,
        width=wifi_configs.ChannelWidth.WIDTH_40,
    )
    self._start_wifi_and_connect(wifi_config)

  def test_wifi_with_open_encryption_mode_5g(self):
    wifi_config = wifi_configs.WiFiConfig(
        channel=36,
        encryption_config=encryption_type_open.Open(),
    )
    self._start_wifi_and_connect(wifi_config)

  def test_wifi_with_open_encryption_mode_2g(self):
    wifi_config = wifi_configs.WiFiConfig(
        channel=6,
        encryption_config=encryption_type_open.Open(),
    )
    self._start_wifi_and_connect(wifi_config)

  def test_wifi_with_wpa_tkip(self):
    wifi_config = wifi_configs.WiFiConfig(
        channel=36,
        encryption_config=wpa.Wpa(
            mode=wpa.Mode.PURE_WPA,
            ciphers={wpa.Cipher.TKIP},
        ),
    )
    self._start_wifi_and_connect(wifi_config)

  def test_wifi_with_wpa_ccmp(self):
    wifi_config = wifi_configs.WiFiConfig(
        channel=36,
        encryption_config=wpa.Wpa(
            mode=wpa.Mode.PURE_WPA,
            ciphers={wpa.Cipher.CCMP},
        ),
    )
    self._start_wifi_and_connect(wifi_config)

  def test_wifi_with_wpa_tkip_ccmp(self):
    wifi_config = wifi_configs.WiFiConfig(
        channel=36,
        encryption_config=wpa.Wpa(
            mode=wpa.Mode.PURE_WPA,
            ciphers={wpa.Cipher.TKIP, wpa.Cipher.CCMP},
        ),
    )
    self._start_wifi_and_connect(wifi_config)

  def test_wifi_with_wpa2_tkip(self):
    wifi_config = wifi_configs.WiFiConfig(
        channel=36,
        encryption_config=wpa.Wpa(
            mode=wpa.Mode.PURE_WPA2,
            ciphers2={wpa.Cipher.TKIP},
        ),
    )
    self._start_wifi_and_connect(wifi_config)

  def test_wifi_with_wpa2_ccmp(self):
    wifi_config = wifi_configs.WiFiConfig(
        channel=36,
        encryption_config=wpa.Wpa(
            mode=wpa.Mode.PURE_WPA2,
            ciphers2={wpa.Cipher.CCMP},
        ),
    )
    self._start_wifi_and_connect(wifi_config)

  def test_wifi_with_wpa2_tkip_ccmp(self):
    wifi_config = wifi_configs.WiFiConfig(
        channel=36,
        encryption_config=wpa.Wpa(
            mode=wpa.Mode.PURE_WPA2,
            ciphers2={wpa.Cipher.TKIP, wpa.Cipher.CCMP},
        ),
    )
    self._start_wifi_and_connect(wifi_config)

  def test_wifi_with_wpa3(self):
    wifi_config = wifi_configs.WiFiConfig(
        channel=36,
        encryption_config=wpa.Wpa(
            mode=wpa.Mode.PURE_WPA3,
            ciphers2={wpa.Cipher.CCMP},
        ),
        pmf=wifi_configs.PMF.REQUIRED,
    )
    self._start_wifi_and_connect(wifi_config)

  def test_wifi_with_wpa_mixed(self):
    wifi_config = wifi_configs.WiFiConfig(
        channel=36,
        encryption_config=wpa.Wpa(
            mode=wpa.Mode.MIXED,
            ciphers={wpa.Cipher.TKIP, wpa.Cipher.CCMP},
            ciphers2={wpa.Cipher.CCMP},
        ),
    )
    self._start_wifi_and_connect(wifi_config)

  def test_wifi_with_wpa3_mixed(self):
    wifi_config = wifi_configs.WiFiConfig(
        channel=36,
        encryption_config=wpa.Wpa(
            mode=wpa.Mode.MIXED_WPA3,
            ciphers2={wpa.Cipher.CCMP},
        ),
        pmf=wifi_configs.PMF.OPTIONAL,
    )
    self._start_wifi_and_connect(wifi_config)

  def test_wifi_with_custom_ssid_and_password(self):
    random_str = utils.rand_ascii_str(5)
    ssid = f'Test-WiFi-{random_str}'
    password = utils.rand_ascii_str(8)
    wifi_config = wifi_configs.WiFiConfig(
        ssid=ssid,
        channel=36,
        encryption_config=wpa.Wpa(
            mode=wpa.Mode.PURE_WPA2,
            password=password,
        ),
    )

    wifi_info = self.openwrt.start_wifi(wifi_config)

    asserts.assert_equal(
        wifi_info.ssid, ssid, 'The SSID of the started WiFi is not as expected.'
    )
    asserts.assert_equal(
        wifi_info.password,
        password,
        'The password of the started WiFi is not as expected.',
    )

    self.ad.mbs.wifiEnable()
    self.ad.mbs.wifiConnectSimple(ssid, password)

  def _start_wifi_and_connect(
      self,
      wifi_config: wifi_configs.WiFiConfig,
  ) -> wifi_configs.WifiInfo:
    wifi_info = self.openwrt.start_wifi(wifi_config)
    self.ad.mbs.wifiEnable()
    self.ad.mbs.wifiConnectSimple(wifi_info.ssid, wifi_info.password)
    return wifi_info

  def setup_test(self):
    # Stop all.
    self.ad.mbs.wifiDisable()
    self.openwrt.stop_all_wifi()

  def teardown_test(self):
    # Collcet test artifacts and stop all on Android.
    self.ad.services.create_output_excerpts_all(self.current_test_info)
    self.ad.mbs.wifiDisable()
    # Clear all saved WiFi networks.
    self.ad.mbs.wifiClearConfiguredNetworks()

    # Collect artifacts and stop all on OpenWrt devices.
    self.openwrt.services.create_output_excerpts_all(self.current_test_info)
    self.openwrt.stop_all_wifi()


if __name__ == '__main__':
  test_runner.main()

