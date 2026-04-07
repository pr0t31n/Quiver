#!/usr/bin/env bash
# nRF52840 BLE Sniffer Setup Script
# Sets up Nordic Semiconductor BLE Sniffer firmware with Wireshark
#
# Requirements:
#   - nRF52840 Dongle flashed with nRF Sniffer for Bluetooth LE firmware
#   - Wireshark >= 3.0 installed
#   - nrfutil installed (pip install nrfutil)
#
# Firmware download: https://www.nordicsemi.com/Products/Development-tools/nRF-Sniffer-for-Bluetooth-LE
# Wireshark plugin:  included in the firmware .zip from Nordic

set -euo pipefail

echo "=== nRF52840 BLE Sniffer Setup ==="

# Detect OS
if [[ "$(uname)" == "Darwin" ]]; then
    OS="macos"
    WS_PLUGIN_DIR="$HOME/.config/wireshark/extcap"
    WS_EXTCAP_DIR="$HOME/.config/wireshark/extcap"
else
    OS="linux"
    WS_PLUGIN_DIR="$HOME/.config/wireshark/extcap"
    WS_EXTCAP_DIR="$HOME/.config/wireshark/extcap"
fi

# Check Wireshark
if ! command -v wireshark &>/dev/null; then
    echo "ERROR: Wireshark not found."
    if [[ "$OS" == "linux" ]]; then
        echo "Install: sudo apt-get install wireshark"
        echo "Then:    sudo usermod -aG wireshark \$USER && newgrp wireshark"
    else
        echo "Install: brew install --cask wireshark"
    fi
    exit 1
fi
echo "  [OK] Wireshark found: $(wireshark --version | head -1)"

# Check nrfutil
if ! command -v nrfutil &>/dev/null; then
    echo "nrfutil not found. Installing via pip..."
    pip install nrfutil --break-system-packages 2>/dev/null || pip install nrfutil
fi
echo "  [OK] nrfutil found"

# Linux: add user to dialout for serial access
if [[ "$OS" == "linux" ]]; then
    if ! groups | grep -q dialout; then
        echo "Adding user to dialout group for serial port access..."
        sudo usermod -aG dialout "$USER"
        echo "  NOTE: Log out and back in for group change to take effect"
        echo "        Or run: newgrp dialout"
    else
        echo "  [OK] User is in dialout group"
    fi
fi

echo ""
echo "=== Next Steps ==="
echo "1. Download nRF Sniffer firmware from:"
echo "   https://www.nordicsemi.com/Products/Development-tools/nRF-Sniffer-for-Bluetooth-LE"
echo ""
echo "2. Flash the firmware DFU package to your nRF52840 Dongle:"
echo "   nrfutil dfu usb-serial -pkg sniffer_pca10059_4.1.1.zip -p /dev/ttyACM0"
echo "   (Dongle must be in DFU mode: press side button briefly)"
echo ""
echo "3. Install the Wireshark extcap plugin:"
echo "   mkdir -p $WS_EXTCAP_DIR"
echo "   cp nrf_sniffer_for_bluetooth_le.py $WS_EXTCAP_DIR/"
echo "   chmod +x $WS_EXTCAP_DIR/nrf_sniffer_for_bluetooth_le.py"
echo ""
echo "4. Start Wireshark and select the nRF Sniffer interface"
echo "   (It appears as 'nRF Sniffer for Bluetooth LE <port>')"
echo ""
echo "5. Apply display filters:"
echo "   btle              — all BLE traffic"
echo "   btle.advertising  — advertisements only"
echo "   btle.data         — data packets only"
