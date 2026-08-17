# Heltec UWB Sniffer Dongle

The Heltec UWB Sniffer Dongle is a USB-A ultra-wideband packet analyzer — an OEM
re-brand of the Eforthink/Forthink "UWB Dongle Sniffer" module. It is built around
an **NXP NCJ29D5** UWB IC (IEEE 802.15.4a/z HRP UWB, CCC/FiRa, up to 6.8 Mbps) with
an integrated **ARM Cortex-M33** host core, connected to the host PC through an
**FTDI FT4222H** USB-to-SPI bridge (VID:PID `0403:601C`) — so it is a libusb/D2XX
device, not a serial COM port, and neither esptool nor nrfutil nor dfu-util apply.
Firmware is an encrypted `.pkg` written to the NCJ29D5 through the FT4222H bridge by
the vendor **SWUP** (Software Update Program) updater, which is fetched (together
with the firmware package) from the vendor repo
<https://github.com/forthink-xyz/forthink_uwb_sniffer_tool>. Two firmware options
are offered: **UWB Sniffer** (the stock passive-capture build that feeds Wireshark)
and **Custom firmware package** (an operator-supplied `.pkg` dropped into the
tool's firmware `user/` directory).
