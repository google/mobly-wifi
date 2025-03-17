# Mobly WiFi Controller

Mobly WiFi controller module for using Python code to operate network devices in Mobly tests.

## Requirements

-   Python 3.11+
-   Mobly 1.12.2+

## Installation

```shell
pip install mobly-wifi
```

## Start to Use

Mobly WiFi controller is an add-on module to control OpenWrt AP devices in [Mobly](https://github.com/google/mobly).
To learn more about Mobly, visit [Getting started with Mobly](https://github.com/google/mobly/blob/master/docs/tutorial.md).

### Ensure the AP device is reachable via SSH

Mobly tests run on a single host computer.

To use an AP device in Mobly tests, connect it to your local network and confirm
SSH access from the host machine.

### Write Mobly Device Configs

Write a testbed config to specify the information of the device under test. For example:

**sample_config.yaml**

```yaml
TestBeds:
- Name: SampleOpenWrtTestbed
  Controllers:
    OpenWrtDevice:
    -  hostname: 'IP_ADDRESS'
```

NOTE: Replace `IP_ADDRESS` with the IP address of the AP device.

### Write a Hello World Mobly Test

This example test starts a 5G Wi-Fi network on the given AP device.

**hello_world_test.py**

```python
"""A basic Mobly Test with OpenWrt AP device."""

import time

from mobly import base_test
from mobly import test_runner
from mobly.controllers.wifi import openwrt_device
from mobly.controllers.wifi.lib import wifi_configs

 
class HelloWorldTest(base_test.BaseTestClass):
 
  def setup_class(self):
    # Register controller for the AP device
    self.openwrt = self.register_controller(openwrt_device)[0]
 
  def test_start_5g_wifi(self):
    # Start Wi-Fi network with channel=36
    config = wifi_configs.WiFiConfig(channel=36)
    wifi_info = self.openwrt.start_wifi(config=config)
    self.openwrt.log.info(
        'Now you can connect your device to WiFi "%s" with password "%s"!',
        wifi_info.ssid,
        wifi_info.password,
    )
    # Sleep a while, you can manually connect your device to the WiFi.
    time.sleep(60)
 
if __name__ == '__main__':
  test_runner.main()
```

### Execute the Test

```bash
python hello_world_test.py -c sample_config.yaml
```

### Configure Android devices in Mobly tests

To use Android devices together with AP devices, you need to configure them in
testbed config.

Following testbed uses one AP device and all Android devices connected with your
host computer:

```yaml
TestBeds:
- Name: SampleOpenWrtTestbed
  Controllers:
    OpenWrtDevice:
    - hostname: 'IP_ADDRESS'
    # Use all Android devices detectable by adb
    AndroidDevice: '*'
```

Following testbed uses one AP device and Android devices with serial number
`abc` and `xyz`.

```yaml
TestBeds:
- Name: SampleOpenWrtTestbed
  Controllers:
    OpenWrtDevice:
    - hostname: 'IP_ADDRESS'
    AndroidDevice: '*'
    - serial: abc
    - serial: xyz
```

### More Examples

See [examples](./examples) folder for more examples.
