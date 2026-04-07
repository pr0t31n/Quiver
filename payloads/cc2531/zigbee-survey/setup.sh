#!/usr/bin/env bash
# CC2531 Zigbee Network Survey — Setup Script
# Requires CC2531 flashed with Zigbee Sniffer firmware + Wireshark

set -euo pipefail
echo "=== CC2531 Zigbee Survey Setup ==="

OS="linux"
[[ "$(uname)" == "Darwin" ]] && OS="macos"

# Check Wireshark
if ! command -v wireshark &>/dev/null; then
    echo "ERROR: Wireshark not found."
    [[ "$OS" == "linux" ]] && echo "Install: sudo apt-get install wireshark" \
        || echo "Install: brew install --cask wireshark"
    exit 1
fi
echo "  [OK] Wireshark: $(wireshark --version | head -1)"

# Check usbmon (Linux)
if [[ "$OS" == "linux" ]]; then
    if ! lsmod | grep -q usbmon; then
        echo "Loading usbmon kernel module..."
        sudo modprobe usbmon
    fi
    echo "  [OK] usbmon loaded"

    # Install Wireshark ZBOSS plugin (ZigBee decode support)
    if ! command -v zboss_sniffer &>/dev/null 2>&1; then
        echo "  NOTE: For full Zigbee decoding, install zboss_sniffer from DSR:"
        echo "  https://www.dsr-wireless.com/en/solutions/technology/zigbee-sniffer"
        echo "  Or use the CC2531 Wireshark plugin from Texas Instruments"
    fi
fi

# Check tshark
if ! command -v tshark &>/dev/null; then
    echo "NOTE: tshark not found (needed for command-line capture)"
    [[ "$OS" == "linux" ]] && echo "Install: sudo apt-get install tshark" \
        || echo "Install: brew install wireshark"
fi

echo ""
echo "=== Zigbee Survey Instructions ==="
echo ""
echo "1. CC2531 must be flashed with Zigbee Sniffer firmware:"
echo "   Download: https://github.com/zigbeer/zigsniff"
echo "   Or:       https://github.com/Koenkk/Z-Stack-firmware/tree/master/sniffer"
echo "   Flash:    cc-tool -e -w CC2531ZNP-with-SBL.hex -v"
echo ""
echo "2. Find the CC2531 serial port:"
echo "   Linux: ls /dev/ttyACM* or ls /dev/ttyUSB*"
echo "   macOS: ls /dev/cu.usbmodem*"
echo ""
echo "3. Capture with Wireshark:"
echo "   wireshark -i <interface> -k"
echo "   Apply filter: wpan || zbee_nwk || zbee_aps"
echo ""
echo "4. Command-line capture (10 minutes, all Zigbee channels 11-26):"
echo "   for ch in \$(seq 11 26); do"
echo "     echo \"Scanning channel \$ch...\""
echo "     tshark -i <interface> -a duration:30 -w scan_ch\${ch}.pcap 2>/dev/null"
echo "   done"
echo ""
echo "5. Extract network info from captures:"
echo "   tshark -r scan_ch11.pcap -T fields -e wpan.src64 -e wpan.dst64 -e zbee_nwk.src -e zbee_nwk.dst 2>/dev/null | sort -u"
echo ""
echo "6. Zigbee channel assignments (2.4 GHz):"
echo "   Ch 11: 2405 MHz | Ch 15: 2425 MHz | Ch 20: 2450 MHz | Ch 25: 2475 MHz"
echo "   Ch 12: 2410 MHz | Ch 16: 2430 MHz | Ch 21: 2455 MHz | Ch 26: 2480 MHz"
