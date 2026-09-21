# Mobly Wi-Fi Release History

# 1.4.0 (2026-09-21)

### New

#### Wi-Fi Configuration & Data Models
* Add configuration data models, validation, and `iw` parsing foundations for IEEE 802.11be (Wi-Fi 7 / EHT), the 6 GHz band, 160 MHz / 320 MHz channel widths, and Multi-Link Operation (MLO) as preparation for full `hostapd` support.
* Support enforcing pure mode on active Wi-Fi networks to restrict connections to a specific Wi-Fi generation.

#### Encryption, Security, & Roaming
* Support WPA-EAP, Tunneled-1X, and WPA3-Enterprise 192-bit (Suite-B-192) encryption modes, along with certificate installation and removal on AP devices.
* Support Opportunistic Wireless Encryption (OWE), including Pure OWE and OWE Transition modes.
* Support IEEE 802.11r Fast BSS Transition (FT) roaming configurations.
* Support generating OpenWrt UCI encryption configurations across all encryption modes.

#### AP Control & Network Management
* Support sending IEEE 802.11 Deauthentication frames to clients and turning off AP radio transmission on the fly.
* Support building BSS Transition Management (BSS TM) neighbor reports directly from running Wi-Fi network information with automatic operating class and PHY type calculation.
* Support OpenNDS as a captive portal authentication backend alongside HTTP redirect.
* Support `nftables` (`fw4`) firewall management on newer OpenWrt releases in addition to `iptables`.
* Support Alpine (`apk`) package management on OpenWrt devices in addition to `opkg`.
* Support operating OpenWrt devices as Wi-Fi client stations (`wpa_supplicant` and DHCP client management).
* Support new AP hardware models: [Banana Pi BPi-R4](https://docs.banana-pi.org/en/BPI-R4/BananaPi_BPI-R4) and Ubiquiti UniFi 6 Plus.
* Support SSH proxy commands and port forwarding in OpenWrt device configurations.
* Simplify starting packet capture by specifying only a channel or frequency and inferring other parameters from hardware capabilities.

### Fixes
* Stop `hostapd` before removing virtual wireless interfaces during teardown so over-the-air deauthentication frames are delivered to connected clients.
* Wait for `tcpdump` initialization before proceeding with packet capture to prevent missing initial frames.
* Manage system `dnsmasq` automatically across NAT and bridged Wi-Fi network configurations and dynamically detect the active WAN interface.
* Improve SSID encoding/decoding and tighten validation for invalid Wi-Fi standard, frequency band, channel width, and encryption combinations.

# 1.3.0 (2025-09-10)

### New
* Support starting Wi-Fi networks with captive portal authentication.
* Support sending BSS Transition Management (BSS TM) requests from the AP to clients.
* Support on-the-fly channel switch for active Wi-Fi networks.
* Support on-the-fly property modification for active hostapd instances.
* Support starting hidden Wi-Fi networks.
* Support custom DHCP configurations.
* Support more encryption configurations, e.g. the WPA3-EXT encryption mode, GCMP/GCMP-256 ciphers.
* Support dual-band packet capturing.


# 1.2.0: BPi R3 AP model support

### New
* Support new AP hardware model [Banana Pi R3](https://www.banana-pi.org/en/bananapi-router/99.html).

# 1.1: Packet capture support

### New
* Support using a dongle as over the air packet capturer.
* Small edits to support using custom OpenWrt image based on OpenWrt 23.05.

# 1.0: Initial release
