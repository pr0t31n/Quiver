#!/usr/bin/env bash
# ==================================================================
#  chameleon-mifare-emulate.sh
#  Description : Load a full Mifare Classic sector dump (from pm3
#                hf mf dump) into Chameleon Ultra for complete card
#                emulation including sector keys and data.
#  Requires    : chameleon-ultra Python library or chameleon CLI
#  Usage       : ./chameleon-mifare-emulate.sh <dump_file.bin> [slot]
#  Example     : ./chameleon-mifare-emulate.sh hf-mf-DEADBEEF-dump.bin 0
# ==================================================================

set -euo pipefail
DUMP_FILE="${1:?Usage: $0 <dump_file.bin> [slot]}"
SLOT="${2:-0}"

[ -f "$DUMP_FILE" ] || { echo "[!] Dump file not found: $DUMP_FILE"; exit 1; }
DUMP_SIZE=$(wc -c < "$DUMP_FILE")
LOOT_DIR="./loot/chameleon-emulate-$(date +%Y%m%d_%H%M%S)"; mkdir -p "$LOOT_DIR"

echo " =================================================="
echo "  Chameleon Ultra — Mifare Classic Full Emulation"
echo "  Dump    : $DUMP_FILE (${DUMP_SIZE} bytes)"
echo "  Slot    : $SLOT"
echo " =================================================="

# Determine card type from dump size
case "$DUMP_SIZE" in
    1024) CARD_TYPE="MIFARE_1K" ;;
    4096) CARD_TYPE="MIFARE_4K" ;;
    *) echo "[!] Unexpected dump size: ${DUMP_SIZE} bytes (expected 1024 or 4096)"; exit 1 ;;
esac
echo "[*] Card type: $CARD_TYPE"

if python3 -c "from chameleon_ultra import ChameleonUltra" 2>/dev/null; then
    python3 - <<EOF
from chameleon_ultra import ChameleonUltra, SlotNumber, CardType

ultra = ChameleonUltra()
ultra.connect()

slot = SlotNumber($SLOT)
card_type = CardType['$CARD_TYPE']

with open('$DUMP_FILE', 'rb') as f:
    dump_data = f.read()

print(f"[*] Loading {len(dump_data)} bytes into slot {slot}...")
ultra.slot_change_tag_type(slot, card_type)
ultra.slot_tag_write(slot, dump_data)
ultra.slot_enable(slot, True)
ultra.save_settings()

# Read back UID for confirmation
uid = ultra.slot_tag_uid_read(slot)
print(f"[+] Loaded. UID: {uid.hex().upper()}")
ultra.disconnect()
EOF
elif command -v chameleon >/dev/null 2>&1; then
    chameleon slot set --slot "$SLOT" --type "$CARD_TYPE"
    chameleon dump load --slot "$SLOT" --file "$DUMP_FILE"
    chameleon slot activate --slot "$SLOT"
    echo "[+] Dump loaded into slot $SLOT"
else
    echo "[!] chameleon_ultra not found. Install: pip install chameleon-ultra"
    exit 1
fi

echo "[+] Present Chameleon Ultra to reader. Full $CARD_TYPE emulation active."
