#!/bin/bash
# ================================================================
#  Packet Squirrel — full-capture-timed
#  Description : Timed full-traffic PCAP capture. Runs for a
#                configurable duration (default 10 minutes) then
#                stops cleanly. Captures all Ethernet traffic on
#                the inline tap interface. Rotates files to prevent
#                oversized PCAPs. Suitable for Switch Position 1.
#  Device      : Packet Squirrel (Mk I / Mk II, OpenWrt)
#  Author      : <operator>
#  Deploy      : Copy to /root/payload/payload.sh via SSH
#                SSH: root@172.16.32.1 (Arming Mode, position 4)
# ================================================================

LED SETUP
sleep 5   # Allow network to settle after plug-in

LOOT_DIR=/root/loot/capture-$(date +%Y%m%d_%H%M%S)
mkdir -p "$LOOT_DIR"

# Configuration
DURATION=600          # Capture duration in seconds (default: 10 min)
ROTATE_SECS=120       # Rotate PCAP file every N seconds
MAX_FILES=10          # Keep at most this many rotation files
IFACE=eth0            # Inline tap interface

LED ATTACK

echo "[*] Full PCAP capture starting — ${DURATION}s on $IFACE"
echo "[*] Rotating every ${ROTATE_SECS}s, max ${MAX_FILES} files"

# tcpdump with file rotation (-G rotate interval, -W max files)
tcpdump -i "$IFACE" \
    -w "${LOOT_DIR}/capture_%Y%m%d_%H%M%S.pcap" \
    -G "$ROTATE_SECS" \
    -W "$MAX_FILES" \
    --buffer-size=4096 \
    2>/dev/null &
TCPDUMP_PID=$!

sleep "$DURATION"
kill "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true

# Summary
PCAP_COUNT=$(find "$LOOT_DIR" -name "*.pcap" | wc -l)
TOTAL_SIZE=$(du -sh "$LOOT_DIR" 2>/dev/null | cut -f1)
echo "[+] Capture complete: $PCAP_COUNT file(s), $TOTAL_SIZE"
echo "[+] Loot: $LOOT_DIR"

LED FINISH
