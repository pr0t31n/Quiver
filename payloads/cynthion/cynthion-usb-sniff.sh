#!/usr/bin/env bash
# ==================================================================
#  cynthion-usb-sniff.sh
#  Description : USB traffic capture using Cynthion as a hardware
#                USB analyzer. Starts Packetry or pipes to Wireshark
#                for live USB protocol analysis.
#  Requires    : packetry (Great Scott Gadgets), or cynthion Python pkg
#  Usage       : ./cynthion-usb-sniff.sh [duration_s] [pcap_output]
# ==================================================================

set -euo pipefail
DURATION="${1:-0}"
LOOT_DIR="./loot/usb-sniff-$(date +%Y%m%d_%H%M%S)"; mkdir -p "$LOOT_DIR"
PCAP="${2:-${LOOT_DIR}/usb_capture.pcapng}"

echo " =================================================="
echo "  Cynthion — USB Traffic Capture"
echo "  Output: $PCAP"
echo " =================================================="
echo ""
echo "  Setup:"
echo "  - Connect Cynthion CONTROL USB-C → host machine"
echo "  - Connect target device to Cynthion TARGET-A (or TARGET-C)"
echo "  - Target upstream goes to Cynthion AUX port"
echo ""

if command -v packetry >/dev/null 2>&1; then
    echo "[*] Starting Packetry (GUI mode)..."
    if [ "$DURATION" -gt 0 ] 2>/dev/null; then
        timeout "$DURATION" packetry --output "$PCAP" 2>&1 || true
    else
        packetry --output "$PCAP" 2>&1
    fi
elif python3 -c "import cynthion" 2>/dev/null; then
    echo "[*] Using cynthion Python API for USB capture..."
    python3 - <<-PYEOF
import cynthion, time, sys

analyzer = cynthion.Cynthion()
analyzer.start_usb_analyzer()
print("[*] USB analysis started. Press Ctrl+C to stop.")
out = open("$PCAP", "wb")
try:
    while True:
        data = analyzer.get_usb_packets()
        if data:
            out.write(data)
        time.sleep(0.01)
except KeyboardInterrupt:
    print("\\n[+] Capture stopped.")
finally:
    out.close()
    analyzer.stop_usb_analyzer()
PYEOF
else
    echo "[!] Neither packetry nor cynthion Python package found."
    echo "    Install: pip install cynthion  OR  download Packetry from:"
    echo "    https://github.com/greatscottgadgets/packetry/releases"
    exit 1
fi

if [ -f "$PCAP" ]; then
    echo "[+] Capture: $PCAP ($(du -sh "$PCAP" | cut -f1))"
    echo "    Analyze:  wireshark $PCAP"
fi
