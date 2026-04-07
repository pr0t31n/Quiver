#!/usr/bin/env bash
# nRF52840 Zigbee / 802.15.4 Sniffer Setup Script
# Uses Nordic nRF Sniffer for 802.15.4 firmware + Wireshark
#
# Firmware: https://www.nordicsemi.com/Products/Development-tools/nRF-Sniffer-for-802154
# Wireshark plugin: included in firmware zip

set -euo pipefail
echo "=== nRF52840 Zigbee / 802.15.4 Sniffer Setup ==="

if [[ "$(uname)" == "Darwin" ]]; then
    OS="macos"; EXTCAP="$HOME/.config/wireshark/extcap"
else
    OS="linux"; EXTCAP="$HOME/.config/wireshark/extcap"
fi

if ! command -v wireshark &>/dev/null; then
    echo "ERROR: Wireshark not found."
    [[ "$OS" == "linux" ]] && echo "Install: sudo apt-get install wireshark" || echo "Install: brew install --cask wireshark"
    exit 1
fi
echo "  [OK] Wireshark: $(wireshark --version | head -1)"

if ! command -v nrfutil &>/dev/null; then
    echo "Installing nrfutil..."
    pip install nrfutil --break-system-packages 2>/dev/null || pip install nrfutil
fi

if [[ "$OS" == "linux" ]] && ! groups | grep -q dialout; then
    sudo usermod -aG dialout "$USER"
    echo "  NOTE: Log out/in for dialout group to take effect (or: newgrp dialout)"
fi

echo ""
echo "=== Next Steps ==="
echo "1. Download nRF Sniffer for 802.15.4 from:"
echo "   https://www.nordicsemi.com/Products/Development-tools/nRF-Sniffer-for-802154"
echo ""
echo "2. Flash firmware (dongle must be in DFU mode — press side button):"
echo "   nrfutil dfu usb-serial -pkg sniffer_pca10059_802154_1.1.0.zip -p /dev/ttyACM0"
echo ""
echo "3. Install Wireshark extcap plugin:"
echo "   mkdir -p $EXTCAP"
echo "   cp nrf_sniffer_802154.py $EXTCAP/ && chmod +x $EXTCAP/nrf_sniffer_802154.py"
echo ""
echo "4. Launch Wireshark → select 'nRF 802.15.4 Sniffer' interface"
echo ""
echo "5. Useful Wireshark display filters for Zigbee:"
echo "   zbee_nwk          — Zigbee Network Layer"
echo "   zbee_aps          — Zigbee Application Support"
echo "   wpan              — Raw 802.15.4 frames"
echo "   wpan.src64        — Filter by source EUI-64"
echo ""
echo "6. For Zigbee decryption, add network key in:"
echo "   Edit → Preferences → Protocols → ZigBee → Add key"
