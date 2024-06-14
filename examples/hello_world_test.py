import os

print(os.environ)

import sys

print(sys.path)

sys.path.insert(0, os.path.abspath("/Users/minghaoli/github/wifi/mobly-wifi/"))

print(sys.path)

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
        'Now you should be able to see the new started WiFi "%s"',
        wifi_info.ssid,
    )
    # Sleep 5 seconds for you to manual check.
    time.sleep(5)
 
if __name__ == '__main__':
  test_runner.main()

