# Steps for starting a long running using this example

1. Connect an OpenWrt access point (AP) and a Linux machine into the same
   local area network.
2. Determine the IP address of the OpenWrt AP. Ensure the linux machine can
   successfully pint the OpenWrt AP.
3. In the `config.yml` file, replace the `hostname` field with the IP address of
   the AP.
4. Install mobly-wifi module by runing the following command:
   `pip install mobly-wifi`
5. Start a long running WiFi by running the following command:
   `python start_wifi_test.py -c config.yml`
