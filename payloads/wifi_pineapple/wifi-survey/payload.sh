#!/bin/bash
# ================================================================
#  WiFi Pineapple MK7 — wifi-survey
#  Description : Passive WiFi survey and recon module. Performs a
#                multi-channel passive scan across 2.4 and 5 GHz,
#                captures beacon frames and probe requests, logs
#                SSIDs/BSSIDs/signal/clients to structured output.
#                Optionally captures WPA handshakes opportunistically.
#                Saves CSV + raw PCAP to /root/loot/.
#  Device      : WiFi Pineapple MK7 (OpenWrt)
#  Author      : <operator>
#  Deploy      : SSH to root@172.16.42.1, copy to /root/wifi-survey.sh
#                or install as a module via Web UI.
#  Run         : bash /root/wifi-survey.sh [duration_seconds]
# ================================================================

SURVEY_DURATION="${1:-300}"  # Default: 5 minutes
LOOT_DIR=/root/loot/wifi-survey-$(date +%Y%m%d_%H%M%S)
IFACE_MON=wlan0             # Primary 2.4 GHz radio for monitor
IFACE_5G=wlan1              # 5 GHz radio (if available)
CHANNEL_DWELL=3             # Seconds per channel during hop

mkdir -p "$LOOT_DIR"
LOG="${LOOT_DIR}/survey.log"

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }

log "WiFi Pineapple MK7 — WiFi Survey"
log "Duration  : ${SURVEY_DURATION}s"
log "Loot      : $LOOT_DIR"

# ── Graceful cleanup on exit ──────────────────────────────────────
cleanup() {
    log "Stopping survey..."
    kill "$HOP_PID" "$TCPDUMP_PID" 2>/dev/null || true
    # Restore interfaces to managed mode
    ip link set "$IFACE_MON" down 2>/dev/null || true
    iw dev "$IFACE_MON" set type managed 2>/dev/null || true
    ip link set "$IFACE_MON" up 2>/dev/null || true

    # Post-process with tshark if available
    PCAP="${LOOT_DIR}/survey.pcap"
    if command -v tshark >/dev/null 2>&1 && [ -f "$PCAP" ]; then
        log "Extracting APs from beacon frames..."
        tshark -r "$PCAP" \
            -Y 'wlan.fc.type_subtype == 8' \
            -T fields \
            -e wlan.sa -e wlan_mgt.ssid \
            -e wlan_mgt.ds.current_channel \
            -e radiotap.dbm_antsignal \
            -E separator=',' -E quote=d 2>/dev/null | sort -u \
            > "${LOOT_DIR}/access_points.csv"
        AP_COUNT=$(wc -l < "${LOOT_DIR}/access_points.csv")
        log "Access points found: $AP_COUNT"

        log "Extracting client probe requests..."
        tshark -r "$PCAP" \
            -Y 'wlan.fc.type_subtype == 4' \
            -T fields \
            -e wlan.sa -e wlan_mgt.ssid \
            -E separator=',' -E quote=d 2>/dev/null | sort -u \
            > "${LOOT_DIR}/probe_requests.csv"
        PROBE_COUNT=$(wc -l < "${LOOT_DIR}/probe_requests.csv")
        log "Client probes captured: $PROBE_COUNT"

        log "Checking for EAPOL handshakes..."
        tshark -r "$PCAP" \
            -Y 'eapol' \
            -T fields \
            -e wlan.sa -e wlan.da -e eapol.keydes.nonce \
            2>/dev/null | sort -u \
            > "${LOOT_DIR}/eapol_frames.csv"
        EAPOL_COUNT=$(wc -l < "${LOOT_DIR}/eapol_frames.csv")
        [ "$EAPOL_COUNT" -gt 0 ] && \
            log "EAPOL frames (potential handshakes): $EAPOL_COUNT"

        log "Extracting hidden SSID candidates..."
        tshark -r "$PCAP" \
            -Y 'wlan.fc.type_subtype == 8 and wlan_mgt.ssid == ""' \
            -T fields -e wlan.sa \
            2>/dev/null | sort -u \
            > "${LOOT_DIR}/hidden_ssids.txt"
        HIDDEN=$(wc -l < "${LOOT_DIR}/hidden_ssids.txt")
        [ "$HIDDEN" -gt 0 ] && log "Hidden SSIDs (BSSID only): $HIDDEN"
    fi

    log "Survey complete. Loot: $LOOT_DIR"
}
trap cleanup EXIT INT TERM

# ── Enter monitor mode on primary interface ───────────────────────
ip link set "$IFACE_MON" down
iw dev "$IFACE_MON" set type monitor
ip link set "$IFACE_MON" up

if ! iw dev "$IFACE_MON" info | grep -q 'type monitor'; then
    log "[!] Failed to enter monitor mode on $IFACE_MON"
    exit 1
fi
log "Monitor mode active on $IFACE_MON"

# ── PCAP capture (management frames only for efficiency) ──────────
PCAP="${LOOT_DIR}/survey.pcap"
tcpdump -i "$IFACE_MON" type mgt -w "$PCAP" \
    --buffer-size=4096 2>/dev/null &
TCPDUMP_PID=$!
log "PCAP capture started → $PCAP"

# ── Channel hopper ────────────────────────────────────────────────
CHANNELS_24="1 2 3 4 5 6 7 8 9 10 11 12 13"
CHANNELS_5="36 40 44 48 52 56 60 64 100 104 108 112 116 132 136 140 149 153 157 161 165"

channel_hop() {
    while true; do
        for ch in $CHANNELS_24 $CHANNELS_5; do
            iw dev "$IFACE_MON" set channel "$ch" 2>/dev/null || true
            sleep "$CHANNEL_DWELL"
        done
    done
}
channel_hop &
HOP_PID=$!
log "Channel hopper active (${CHANNEL_DWELL}s dwell per channel)"

# ── Live AP list via iw scan (supplemental) ───────────────────────
{
    SCANNED=0
    while [ "$SCANNED" -lt "$SURVEY_DURATION" ]; do
        iw dev "$IFACE_MON" scan passive 2>/dev/null | \
        awk '
            /^BSS /       { bssid=$2; gsub(/\(.*/,"",bssid) }
            /SSID:/       { ssid=$0; gsub(/.*SSID: ?/,"",ssid) }
            /signal:/     { sig=$2 }
            /freq:/       { freq=$2 }
            /DS Parameter/ { ch=$4 }
            /WPA:|RSN:/   { enc="WPA" }
            /Privacy/     { enc=(enc ? enc : "WEP") }
            bssid && ssid { printf "%s|%s|%s|%s|%s|%s\n",
                            bssid, ssid, freq, ch, sig, enc;
                            bssid=ssid=freq=ch=sig=enc="" }
        ' >> "${LOOT_DIR}/iw_scan.tsv" 2>/dev/null || true
        sleep 20
        SCANNED=$((SCANNED + 20))
    done
} &
SCAN_PID=$!

# ── Run for survey duration ────────────────────────────────────────
sleep "$SURVEY_DURATION"
kill "$SCAN_PID" 2>/dev/null || true
# cleanup fires via trap
