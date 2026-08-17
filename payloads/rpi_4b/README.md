# Raspberry Pi 4B (8GB)

ARM64 single-board computer — provisioned, not flashed like a microcontroller.
Two operations, both wired as no-menu firmware payloads:

1. **OS Image** — writes Raspberry Pi OS 64-bit / Kali ARM64 / a local image to a removable
   SD/USB/NVMe target via `rpi-imager --cli` (dd fallback), SHA-256 verified, with a device-safety
   guard that enumerates removable/external disks and refuses the host system disk.
2. **Bootloader EEPROM** — `rpi-eeprom-update -a` stages the latest SPI-EEPROM bootloader
   (must run ON the Pi 4B).
