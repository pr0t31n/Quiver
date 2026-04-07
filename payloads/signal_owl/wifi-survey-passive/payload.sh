#!/bin/bash
# ================================================================
#  Signal Owl — wifi-survey-passive
#  Description : Passive 802.11 WiFi survey. Places wlan0 in monitor
#                mode and captures all visible 802.11 frames. Extracts
#                SSIDs, BSSIDs, signal strengths, clients, probe
#                requests, and handshakes. Channel-hops across 2.4GHz
#                and 5GHz bands. Saves structured JSON + raw PCAP.
#  Device      : Signal Owl (OpenWrt, wlan0)
#  Author      : <operator>
#  Deploy      : Copy to USB drive root as payload.sh, or to
#                /root/payload/payload.sh via SSH (Arming Mode).
#  Note        : USB drive takes priority over internal storage.
# ================================================================

source /usr/share/owl/lib/led.sh 2>/dev/null || true

# LED fallback shims if library not available
command -v LED_ATTACK 2>/dev/null || LED_ATTACK() { echo 255 > /sys/class/leds/owl:red/brightness 2>/dev/null || true; }
command -v LED_FINISH 2>/dev/null || LED_FINISH() { echo 255 > /sys/class/leds/owl:green/brightness 2>/dev/null || true; }
command -v LED_FAIL   2>/dev/null || LED_FAIL()   { echo 0 > /sys/class/leds/owl:green/brightness 2>/dev/null || true; echo 255 > /sys/class/leds/owl:red/brightness 2>/dev/null || true; }

LOOT_DIR=/root/loot/wifi-survey-$(date +%Y%m%d_%H%M%S)
IFACE=wlan0
CHANNEL_HOP_INTERVAL=2   # seconds per channel
SURVEY_DURATION=${1:-300} # total survey time in seconds (default 5 min)

mkdir -p "$LOOT_DIR"

echo "[*] Signal Owl — Passive WiFi Survey"
echo "[*] Duration: ${SURVEY_DURATION}s | Loot: $LOOT_DIR"

# ── Enter monitor mode ────────────────────────────────────────────
ip link set "$IFACE" down 2>/dev/null || true
iw dev "$IFACE" set type monitor 2>/dev/null || true
ip link set "$IFACE" up 2>/dev/null || true

if ! iw dev "$IFACE" info | grep -q 'type monitor'; then
    echo "[!] Failed to enter monitor mode on $IFACE"
    LED_FAIL
    exit 1
fi
echo "[+] Monitor mode active on $IFACE"
LED_ATTACK

# ── PCAP capture (all 802.11 frames) ─────────────────────────────
PCAP="${LOOT_DIR}/wifi_survey.pcap"
tcpdump -i "$IFACE" -w "$PCAP" type mgt 2>/dev/null &
TCPDUMP_PID=$!

# ── Channel hopper ────────────────────────────────────────────────
# 2.4 GHz: 1,6,11 (non-overlapping primary) + 2,3,4,5,7,8,9,10,12,13
# 5 GHz: 36,40,44,48,52,56,60,64,100,104,108,112,116,132,136,140,149,153,157,161,165
CHANNELS_24="1 6 11 2 3 4 5 7 8 9 10 12 13"
CHANNELS_5="36 40 44 48 52 56 60 64 100 104 108 112 116 132 136 140 149 153 157 161 165"
ALL_CHANNELS="$CHANNELS_24 $CHANNELS_5"

channel_hop() {
    while true; do
        for ch in $ALL_CHANNELS; do
            iw dev "$IFACE" set channel "$ch" 2>/dev/null || true
            sleep "$CHANNEL_HOP_INTERVAL"
        done
    done
}
channel_hop &
HOP_PID=$!

# ── Live network list via iw scan (supplemental structured data) ──
{
    while true; do
        iw dev "$IFACE" scan passive 2>/dev/null | \
        awk '
            /^BSS / { bssid=$2 }
            /SSID:/ { ssid=$0; gsub(/.*SSID: /,"",ssid) }
            /signal:/ { sig=$2" "$3 }
            /freq:/ && bssid { printf "%s\t%s\t%s\n", bssid, ssid, sig; bssid=""; ssid=""; sig="" }
        ' >> "${LOOT_DIR}/networks_raw.tsv" 2>/dev/null || true
        sleep 30
    done
} &
SCAN_PID=$!

# ── Run for survey duration ────────────────────────────────────────
sleep "$SURVEY_DURATION"

# ── Cleanup & post-process ────────────────────────────────────────
kill "$TCPDUMP_PID" "$HOP_PID" "$SCAN_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true

echo "[*] Processing results..."

# Restore managed mode
ip link set "$IFACE" down 2>/dev/null || true
iw dev "$IFACE" set type managed 2>/dev/null || true
ip link set "$IFACE" up 2>/dev/null || true

# Post-process PCAP with tshark if available
if command -v tshark >/dev/null 2>&1 && [ -f "$PCAP" ]; then
    # Unique SSIDs from beacon frames
    tshark -r "$PCAP" \
        -Y 'wlan.fc.type_subtype == 8' \
        -T fields \
        -e wlan.sa -e wlan_mgt.ssid -e wlan_mgt.ds.current_channel \
        -E separator=',' 2>/dev/null | sort -u \
        > "${LOOT_DIR}/networks.csv"
    NET_COUNT=$(wc -l < "${LOOT_DIR}/networks.csv" 2>/dev/null || echo 0)
    echo "[+] Networks discovered: $NET_COUNT"

    # Probe requests — device tracking
    tshark -r "$PCAP" \
        -Y 'wlan.fc.type_subtype == 4' \
        -T fields \
        -e wlan.sa -e wlan_mgt.ssid \
        -E separator=',' 2>/dev/null | sort -u \
        > "${LOOT_DIR}/probe_requests.csv"
    PROBE_COUNT=$(wc -l < "${LOOT_DIR}/probe_requests.csv" 2>/dev/null || echo 0)
    echo "[+] Client probes captured: $PROBE_COUNT"

    # WPA handshakes (EAPOL)
    tshark -r "$PCAP" \
        -Y 'eapol' \
        -T fields \
        -e wlan.sa -e wlan.da \
        -E separator=',' 2>/dev/null | sort -u \
        > "${LOOT_DIR}/eapol_frames.csv"
    EAPOL_COUNT=$(wc -l < "${LOOT_DIR}/eapol_frames.csv" 2>/dev/null || echo 0)
    [ "$EAPOL_COUNT" -gt 0 ] && \
        echo "[!] EAPOL frames (potential handshakes): $EAPOL_COUNT"

    # Deauth/disassoc frames (detect jammers or other attacks)
    tshark -r "$PCAP" \
        -Y 'wlan.fc.type_subtype == 12 or wlan.fc.type_subtype == 10' \
        -T fields \
        -e wlan.sa -e wlan.da \
        2>/dev/null | wc -l \
        | xargs -I{} echo "[*] Deauth/Disassoc frames observed: {}"
fi

# Unique networks from scan data
if [ -f "${LOOT_DIR}/networks_raw.tsv" ]; then
    sort -u "${LOOT_DIR}/networks_raw.tsv" > "${LOOT_DIR}/networks_unique.tsv"
    echo "[+] Networks (iw scan): $(wc -l < "${LOOT_DIR}/networks_unique.tsv")"
fi

echo "[+] PCAP: $PCAP"
echo "[+] Loot: $LOOT_DIR"
LED_FINISH
