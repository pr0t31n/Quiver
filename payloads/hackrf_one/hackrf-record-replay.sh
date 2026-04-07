#!/usr/bin/env bash
# ==================================================================
#  hackrf-record-replay.sh
#  Description : Record and replay RF signals with HackRF One.
#                Record: captures IQ samples to file.
#                Replay: transmits previously captured file.
#                Common use: static-code sub-GHz devices (garage openers,
#                TPMS, ISM band sensors, etc.)
#  Requires    : hackrf_transfer
#  Usage       : ./hackrf-record-replay.sh record <freq_hz> [duration_s] [outfile]
#                ./hackrf-record-replay.sh replay <freq_hz> <iqfile> [repeat]
# ==================================================================

set -euo pipefail
MODE="${1:-record}"; FREQ="${2:-433920000}"
LOOT_DIR="./loot/hackrf-rr-$(date +%Y%m%d_%H%M%S)"; mkdir -p "$LOOT_DIR"
SAMPLE_RATE=2000000   # 2 Msps
LNA_GAIN=16; VGA_GAIN=16; AMP=0

case "$MODE" in
    record)
        DURATION="${3:-5}"
        OUTFILE="${4:-${LOOT_DIR}/capture_${FREQ}Hz.iq}"
        echo "[*] Recording ${FREQ} Hz for ${DURATION}s → $OUTFILE"
        echo "    Sample rate: ${SAMPLE_RATE} sps | LNA: ${LNA_GAIN} | VGA: ${VGA_GAIN}"
        hackrf_transfer -r "$OUTFILE" -f "$FREQ" -s "$SAMPLE_RATE" \
            -l "$LNA_GAIN" -g "$VGA_GAIN" -n $((SAMPLE_RATE * DURATION)) 2>&1
        echo "[+] Captured: $OUTFILE ($(du -sh "$OUTFILE" | cut -f1))"
        echo ""
        echo "    Replay with:"
        echo "    $0 replay $FREQ $OUTFILE"
        ;;
    replay)
        IQFILE="${3:?Usage: $0 replay <freq_hz> <iqfile> [repeat_count]}"
        REPEAT="${4:-1}"
        echo "[*] Replaying $IQFILE at ${FREQ} Hz (${REPEAT}x)"
        echo "    [!] Ensure you are authorized to transmit on ${FREQ} Hz"
        for i in $(seq 1 "$REPEAT"); do
            echo "[*] Transmission $i/$REPEAT..."
            hackrf_transfer -t "$IQFILE" -f "$FREQ" -s "$SAMPLE_RATE" \
                -x 20 -a "$AMP" 2>&1
            [ "$REPEAT" -gt 1 ] && sleep 1
        done
        echo "[+] Replay complete."
        ;;
    *)
        echo "Usage: $0 [record|replay] <freq_hz> [args...]"
        exit 1
        ;;
esac
