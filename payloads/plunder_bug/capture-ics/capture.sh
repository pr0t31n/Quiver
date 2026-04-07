#!/usr/bin/env bash
# ================================================================
#  Plunder Bug — capture-ics
#  Description : Industrial Control System (ICS/SCADA) traffic capture.
#                Targets common OT protocols transmitted in cleartext:
#                Modbus/TCP (502), DNP3 (20000), EtherNet/IP (44818),
#                BACnet (47808 UDP), Profinet (DCP/broadcast), ICCP.
#                Extracts function codes, register reads/writes, and
#                device enumeration data for asset inventory and
#                security assessment.
#  Host OS     : Linux/macOS
#  Requires    : tcpdump (sudo), optionally tshark
#  Usage       : sudo ./capture.sh [interface] [duration_seconds]
#  WARNING     : Only use on networks you are authorised to test.
#                ICS traffic capture can impact live plant operations.
# ================================================================

set -euo pipefail

IFACE="${1:-}"
DURATION="${2:-0}"
LOOT_DIR="./loot/$(date +%Y%m%d_%H%M%S)_ics"
mkdir -p "$LOOT_DIR"

detect_iface() {
    for iface in /sys/class/net/*/address; do
        addr=$(cat "$iface" 2>/dev/null || true)
        [[ "${addr,,}" == 00:13:37* ]] && basename "$(dirname "$iface")" && return
    done
}
[ -z "$IFACE" ] && IFACE=$(detect_iface)
[ -z "$IFACE" ] && { echo "[!] Plunder Bug not found."; exit 1; }

# ICS/SCADA protocol filter
# Modbus/TCP: 502, DNP3: 20000, EtherNet/IP: 44818, Profinet: 34962-34964
# BACnet: 47808 UDP, ICCP/TASE.2: 102, IEC 104: 2404
ICS_FILTER='tcp port 502 or tcp port 20000 or tcp port 44818 or
            tcp port 102 or tcp port 2404 or tcp port 4840 or
            udp port 47808 or udp port 34962 or udp port 34963 or udp port 34964'

ICS_PCAP="${LOOT_DIR}/ics_capture.pcap"
HITS_FILE="${LOOT_DIR}/ics_hits.txt"
ASSETS_FILE="${LOOT_DIR}/ics_assets.txt"

echo " =================================================="
echo "  Plunder Bug — ICS/SCADA Capture"
echo " =================================================="
echo "  Interface : $IFACE"
echo "  Protocols : Modbus/EtherNet-IP/DNP3/BACnet/Profinet"
echo "  PCAP      : $ICS_PCAP"
echo " =================================================="
echo ""
echo "  [!] CAUTION: Passive capture only — do NOT send traffic"
echo "      to ICS devices without explicit written authorisation."
echo ""

# PCAP capture in background
sudo tcpdump -i "$IFACE" -w "$ICS_PCAP" "$ICS_FILTER" 2>/dev/null &
PCAP_PID=$!

# Live display via tshark if available
if command -v tshark >/dev/null 2>&1; then
    {
        tshark -i "$IFACE" \
            -Y 'modbus or dnp3 or enip or bacapp or profinet' \
            -T fields \
            -e frame.time_relative \
            -e ip.src -e ip.dst \
            -e _ws.col.Protocol \
            -e _ws.col.Info \
            -E separator='|' 2>/dev/null | \
        while IFS='|' read -r ts src dst proto info; do
            printf "[%s] %-15s -> %-15s  %-14s  %s\n" \
                "$ts" "$src" "$dst" "$proto" "$info"
            printf '%s|%s|%s|%s|%s\n' \
                "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$src" "$dst" "$proto" "$info" \
                >> "$HITS_FILE"
        done
    } &
    LIVE_PID=$!
else
    echo "[*] tshark not found — PCAP-only mode."
    LIVE_PID=""
fi

cleanup() {
    kill "$PCAP_PID" 2>/dev/null || true
    [ -n "${LIVE_PID:-}" ] && kill "$LIVE_PID" 2>/dev/null || true
    echo ""
    echo "[+] Capture complete."

    if command -v tshark >/dev/null 2>&1 && [ -f "$ICS_PCAP" ]; then
        echo "[*] Extracting Modbus function codes..."
        tshark -r "$ICS_PCAP" \
            -Y 'modbus' \
            -T fields \
            -e ip.src -e ip.dst \
            -e modbus.func_code \
            -e modbus.reference_num \
            -e modbus.word_cnt \
            2>/dev/null | sort | uniq -c | sort -rn \
            > "${LOOT_DIR}/modbus_functions.txt"

        echo "[*] Building ICS asset inventory..."
        tshark -r "$ICS_PCAP" \
            -T fields \
            -e ip.src -e ip.dst \
            -e _ws.col.Protocol \
            2>/dev/null | sort -u > "$ASSETS_FILE"
        ASSET_COUNT=$(wc -l < "$ASSETS_FILE" 2>/dev/null || echo 0)
        echo "[+] Unique ICS endpoints observed: $ASSET_COUNT"

        echo "[*] Extracting DNP3 function codes..."
        tshark -r "$ICS_PCAP" \
            -Y 'dnp3' \
            -T fields \
            -e ip.src -e ip.dst \
            -e dnp3.ctl.dir \
            -e dnp3.app.ctl.fir \
            -e dnp3.al.func \
            2>/dev/null > "${LOOT_DIR}/dnp3_functions.txt" 2>/dev/null || true

        echo "[*] Extracting EtherNet/IP device info..."
        tshark -r "$ICS_PCAP" \
            -Y 'enip' \
            -T fields \
            -e ip.src -e ip.dst \
            -e enip.command -e enip.session \
            2>/dev/null > "${LOOT_DIR}/ethernetip_sessions.txt" 2>/dev/null || true

        echo "[*] Extracting BACnet device enumeration..."
        tshark -r "$ICS_PCAP" \
            -Y 'bacapp' \
            -T fields \
            -e ip.src -e bacapp.type \
            -e bacapp.service \
            -e bacapp.objectidentifier \
            2>/dev/null | sort -u > "${LOOT_DIR}/bacnet_devices.txt" 2>/dev/null || true

        echo ""
        echo "    Suggested post-processing:"
        echo "    wireshark $ICS_PCAP"
        echo "    # Apply filter: modbus || dnp3 || enip || bacapp"
    fi
    echo "[+] Full PCAP: $ICS_PCAP"
}
trap cleanup EXIT INT TERM

[ "$DURATION" -gt 0 ] 2>/dev/null && sleep "$DURATION" && exit 0
wait "$PCAP_PID"
