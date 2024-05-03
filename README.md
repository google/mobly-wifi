# Mobly WiFi Controller

Mobly WiFi controller module for using Python code to operate OpenWrt AP devices in Mobly tests.

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

### Write Mobly Device Configs

To use a OpenWrt AP device in Mobly tests, first you need to write a config to specify the information of the device under test. For example:

**sample_config.yaml**

```yaml
TestBeds:
- Name: SampleOpenWrtTestbed
  Controllers:
    OpenWrtDevice:
    -  hostname: 'IP_ADDRESS'
```

NOTE: Replace `IP_ADDRESS` with your device information.

### Write a Hello World Mobly Test

**hello_world_test.py**

```python
"""A basic Mobly Test with OpenWrt AP device."""

from mobly import base_test
from mobly import test_runner
from mobly.controllers.wifi import openwrt_device


class HelloWorldTest(base_test.BaseTestClass):
  """A sample test demonstrating using Mobly Windows controller."""

  def setup_class(self):
    super().setup_class()
    # Registers openwrt_device controller module. By default, we expect at
    # least one OpenWrt device.
    self.device = self.register_controller(openwrt_device)[0]

  def test_start_wifi(self):
    wifi_config = wifi_configs.WiFiConfig()
    # Start a WiFi network, you should be able to connect to this WiFi after this method finished.
    self.openwrt.start_wifi(wifi_config)


if __name__ == '__main__':
  test_runner.main()

```

### Execute the Test

```bash
python hello_world_test.py -c sample_config.yaml
```