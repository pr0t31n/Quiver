# nRF52840 Dongle (PCA10059)

The Nordic nRF52840 USB Dongle is a small USB-A form-factor board with a BLE /
IEEE 802.15.4 (Zigbee/Thread) radio and no on-board debugger. Unlike the
nRF52840-DK, it is flashed **over USB DFU** using Nordic's Open Bootloader and
`nrfutil` — press the small RESET button (the red LED pulses, USB re-enumerates
as VID:PID `1915:521F`), then `nrfutil dfu usb-serial -pkg <app.zip> -p
/dev/ttyACM0 -b 115200` writes the firmware. Raw `.hex` images are packaged into
the required DFU `.zip` automatically via `nrfutil pkg generate`. Two firmwares
are offered: **nRF Sniffer for 802.15.4/BLE** (passive BLE/Zigbee capture into
Wireshark — Rx only) and **ButteRFly / WHAD** (active BLE MITM — Rx/Tx, driven by
the WHAD host tools).
