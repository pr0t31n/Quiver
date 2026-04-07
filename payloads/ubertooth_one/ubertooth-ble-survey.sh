#!/usr/bin/env bash
# ==================================================================
#  ubertooth-ble-survey.sh
#  Description : Passive BLE advertisement capture and device survey
#                using Ubertooth One. Captures to PCAP and extracts
#                advertising BLE devices (MAC, name, RSSI, AD data).
#  Requires    : ubertooth-btle, tshark
#  Usage       : ./ubertooth-ble-survey.sh [duration_s]
# ==================================================================

set -euo pipefail
DURATION="${1:-120}"
LOOT_DIR="./loot/ble-survey-$(date +%Y%m%d_%H%M%S)"; mkdir -p "$LOOT_DIR"
PCAP="${LOOT_DIR}/ble_survey.pcap"
DEVICES_FILE="${LOOT_DIR}/ble_devices.csv"

echo " =================================================="
echo "  Ubertooth One — BLE Survey"
echo "  Duration: ${DURATION}s"
echo " =================================================="

echo "[*] Capturing BLE advertisements → $PCAP"
ubertooth-btle -f -c "$PCAP" -t "$DURATION" 2>/dev/null || \
    timeout "$DURATION" ubertooth-btle -f -c "$PCAP" 2>/dev/null || true

echo "[+] Capture complete."

if command -v tshark >/dev/null 2>&1 && [ -f "$PCAP" ]; then
    echo "[*] Extracting BLE devices..."
    tshark -r "$PCAP" \
        -Y 'btle.advertising_header' \
        -T fields \
        -e btle.advertising_address \
        -e btle.le_supported_features \
        -e btcommon.eir_ad.entry.device_name \
        -e btle.rssi \
        -E separator=',' -E quote=d 2>/dev/null | sort -u > "$DEVICES_FILE"

    DEVICE_COUNT=$(wc -l < "$DEVICES_FILE" 2>/dev/null || echo 0)
    echo "[+] BLE devices observed: $DEVICE_COUNT"
    echo "[+] Devices: $DEVICES_FILE"
    echo ""
    cat "$DEVICES_FILE" | head -20
fi
echo "[+] PCAP: $PCAP"
