#!/usr/bin/env bash
# ==================================================================
#  killerbee-launch.sh
#  Description : Auto-detect KillerBee-compatible Zigbee hardware
#                (Sonoff ZBDongle-E / CC2531 / RZUSBSTICK / APIMote),
#                select a channel, and launch zbdump to a PCAP file.
#                Optionally decodes Zigbee frames with Wireshark.
#  Requires    : killerbee (pip install killerbee), zbdump in PATH
#  Usage       : ./killerbee-launch.sh [channel] [duration_s] [device]
#  Defaults    : channel=15 duration=300 device=auto
#  Example     : ./killerbee-launch.sh 11 600 /dev/ttyUSB0
# ==================================================================

set -euo pipefail

CHANNEL="${1:-15}"
DURATION="${2:-300}"
DEVICE_OVERRIDE="${3:-}"

LOOT_DIR="./loot/zigbee-$(date +%Y%m%d_%H%M%S)"
mkdir -p "$LOOT_DIR"
PCAP_FILE="${LOOT_DIR}/zigbee-ch${CHANNEL}.pcap"

echo " =================================================="
echo "  KillerBee Zigbee Capture"
echo "  Channel  : $CHANNEL ($(( 2405 + (CHANNEL - 11) * 5 )) MHz)"
echo "  Duration : ${DURATION}s"
echo "  Output   : $PCAP_FILE"
echo " =================================================="

# Verify killerbee tools are present
if ! command -v zbdump >/dev/null 2>&1; then
    echo "[!] zbdump not found. Install: pip install killerbee"
    exit 1
fi

# Auto-detect device
detect_device() {
    # Try zbid first (killerbee device lister)
    if command -v zbid >/dev/null 2>&1; then
        DETECTED=$(zbid 2>/dev/null | grep -E 'dev:|Device' | head -1 | awk '{print $NF}' || true)
        if [[ -n "$DETECTED" ]]; then
            echo "$DETECTED"
            return
        fi
    fi
    # Check common USB serial paths for Sonoff ZBDongle-E / CC2531
    for path in /dev/ttyUSB0 /dev/ttyUSB1 /dev/ttyACM0 /dev/ttyACM1; do
        if [[ -e "$path" ]]; then
            echo "$path"
            return
        fi
    done
    echo ""
}

if [[ -n "$DEVICE_OVERRIDE" ]]; then
    DEVICE="$DEVICE_OVERRIDE"
    echo "[*] Using specified device: $DEVICE"
else
    DEVICE=$(detect_device)
    if [[ -z "$DEVICE" ]]; then
        echo "[!] No KillerBee device detected."
        echo "    Ensure device is plugged in and drivers loaded."
        echo "    Override with: $0 $CHANNEL $DURATION /dev/ttyUSB0"
        exit 1
    fi
    echo "[*] Auto-detected device: $DEVICE"
fi

# Validate channel range (802.15.4: 11-26)
if (( CHANNEL < 11 || CHANNEL > 26 )); then
    echo "[!] Invalid channel $CHANNEL. Zigbee channels are 11-26."
    exit 1
fi

# Run zbdump with timeout
echo "[*] Starting capture on channel $CHANNEL for ${DURATION}s..."
echo "[*] Press Ctrl+C to stop early."
echo ""

if timeout "${DURATION}" zbdump \
    --channel "$CHANNEL" \
    --device "$DEVICE" \
    --pcap-out "$PCAP_FILE" \
    --count 0 2>&1 | tee "${LOOT_DIR}/zbdump.log"; then
    CAPTURE_STATUS="complete"
else
    EXIT_CODE=$?
    if [[ $EXIT_CODE -eq 124 ]]; then
        CAPTURE_STATUS="duration reached"
    else
        CAPTURE_STATUS="interrupted (exit $EXIT_CODE)"
    fi
fi

echo ""
echo "[+] Capture $CAPTURE_STATUS."

# Frame count
if [[ -f "$PCAP_FILE" ]]; then
    if command -v tshark >/dev/null 2>&1; then
        FRAME_COUNT=$(tshark -r "$PCAP_FILE" 2>/dev/null | wc -l | tr -d ' ')
        echo "[+] Frames captured: $FRAME_COUNT"

        # Quick summary: unique PAN IDs and device addresses
        echo ""
        echo "[*] PAN IDs observed:"
        tshark -r "$PCAP_FILE" -T fields -e wpan.dst_pan \
            2>/dev/null | sort -u | grep -v '^$' | head -10 || echo "  (none)"

        echo ""
        echo "[*] Source addresses observed:"
        tshark -r "$PCAP_FILE" -T fields -e wpan.src64 \
            2>/dev/null | sort -u | grep -v '^$' | head -20 || \
        tshark -r "$PCAP_FILE" -T fields -e wpan.src16 \
            2>/dev/null | sort -u | grep -v '^$' | head -20 || echo "  (none)"
    else
        echo "[+] PCAP saved: $PCAP_FILE"
        echo "    Install tshark for frame analysis."
    fi
else
    echo "[!] No PCAP file created. Check device and channel."
fi

echo ""
echo "[+] Loot: $LOOT_DIR"
echo "[*] Analyze: wireshark $PCAP_FILE"
echo "[*] Decrypt: use zbdecrypt if network key is known"
