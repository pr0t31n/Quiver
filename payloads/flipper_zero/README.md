# Flipper Zero — Firmware Payloads

The Flipper Zero is a portable multi-tool for pentesters (Sub-GHz, NFC, 125 kHz RFID, IR,
iButton, GPIO, BadUSB). Its main-board firmware (`official.qfw`, `unleashed.qfw`,
`roguemaster.qfw`, `momentum.qfw`) is applied over USB CDC via the SD update-package flow
(`flipper.update.install` over RPC).

This directory also holds firmware for the **Flipper Zero Wi-Fi Dev Board** add-on — an
ESP32-S2 module that clips onto the Flipper's GPIO and is flashed directly over its own
USB-C port with `esptool` (`--chip esp32s2 ... write_flash 0x0 <fw.bin>`, held in BOOT/DFU
download mode). Two dev-board firmwares are provided: `flash-wifi-devboard-marauder.qfw`
(ESP32 Marauder — Wi-Fi + BLE recon/attack, Rx/Tx) and `flash-wifi-devboard-blackmagic.qfw`
(Black Magic Probe — a wireless/USB SWD/JTAG debugger; function-agnostic). Selecting a
dev-board payload auto-runs device info → prepare (download firmware + ensure esptool) →
summary → a single confirm → flash.
