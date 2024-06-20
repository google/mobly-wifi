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

It perform following steps:

1. Start packet capture on an OpenWrt AP device.
2. Start a WiFi network on another OpenWrt AP device.
3. Connect an Android phone to the WiFi, verify the internet connection.
4. Teardown test, and get captured packets.
"""

import dataclasses
import datetime
import enum
import re
import time

from mobly import base_test
from mobly import test_runner
from mobly.controllers import android_device
from mobly.controllers.android_device_lib import adb
from mobly.controllers.wifi import openwrt_device
from mobly.controllers.wifi.lib import wifi_configs


class SimpleConnectTest(base_test.BaseTestClass):
 
  def setup_class(self):
    # Register an Android device.
    self.ad = self.register_controller(android_device)[0]

    # Load Android snippet.
    self.ad.load_snippet('mbs', 'com.google.android.mobly.snippet.bundled')

    # Register OpenWrt devices.
    self.openwrt, self.sniffer = self.register_controller(
        openwrt_device, min_number=2
    )

  def test_simple_connect(self):
    config = wifi_configs.WiFiConfig(channel=36)

    # Start Sniffer.
    self.sniffer.start_packet_capture(wifi_config=config)

    # Start WiFi.
    wifi_info = self.openwrt.start_wifi(config=config)
    self.openwrt.log.info('WiFi "%s" started!', wifi_info.ssid)

    # Connect to WiFi.
    self.ad.mbs.wifiEnable()
    self.ad.mbs.wifiConnectSimple(wifi_info.ssid, wifi_info.password)
    self.ad.log.info('Connected to WiFi "%s"!', self.ad.mbs.wifiGetConnectionInfo()['SSID'])

  def setup_test(self):
    # Stop all.
    self.ad.mbs.wifiDisable()
    self.openwrt.stop_all_wifi()
    self.sniffer.stop_packet_capture()
 
  def teardown_test(self):
    # Collcet test artifacts and stop all on Android.
    self.ad.services.create_output_excerpts_all(self.current_test_info)
    self.ad.mbs.wifiDisable()
    self.ad.mbs.wifiClearConfiguredNetworks()

    # Collect artifacts and stop all on OpenWrt devices.
    self.openwrt.services.create_output_excerpts_all(self.current_test_info)
    self.openwrt.stop_all_wifi()
    self.sniffer.stop_packet_capture(self.current_test_info)



if __name__ == '__main__':
  test_runner.main()

