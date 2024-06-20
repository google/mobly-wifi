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

"""A basic Mobly Test with OpenWrt AP device."""

import time

from mobly import base_test
from mobly import test_runner
from mobly.controllers.wifi import openwrt_device
from mobly.controllers.wifi.lib import wifi_configs

 
class HelloWorldTest(base_test.BaseTestClass):
 
  def setup_class(self):
    self.openwrt = self.register_controller(openwrt_device)[0]
 
  def test_start_5g_wifi(self):
    config = wifi_configs.WiFiConfig(channel=36)
    wifi_info = self.openwrt.start_wifi(config=config)
    self.openwrt.log.info(
        'Now you can connect your device to WiFi "%s" with password "%s"!',
        wifi_info.ssid,
        wifi_info.password,
    )
    # Sleep a while, you can manually connect your device to the WiFi.
    for _ in range(10):
      self.openwrt.log.info('Sleeping...')
      time.sleep(60)
 
if __name__ == '__main__':
  test_runner.main()

