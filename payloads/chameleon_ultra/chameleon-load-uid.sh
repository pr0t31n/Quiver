#!/usr/bin/env bash
# ==================================================================
#  chameleon-load-uid.sh
#  Description : Load a cloned UID into Chameleon Ultra for card
#                emulation. Supports ISO 14443-A (Mifare/NTAG) and
#                ISO 15693 card types.
#  Requires    : ChameleonTool or chameleon-cli (pip install chameleon-ultra)
#  Usage       : ./chameleon-load-uid.sh <uid_hex> [card_type] [slot]
#  Card types  : MIFARE_1K (default), MIFARE_4K, NTAG213, NTAG215, NTAG216
#  Example     : ./chameleon-load-uid.sh DEADBEEF1234 MIFARE_1K 0
# ==================================================================

set -euo pipefail
UID="${1:?Usage: $0 <uid_hex> [card_type] [slot]}"
CARD_TYPE="${2:-MIFARE_1K}"; SLOT="${3:-0}"
LOOT_DIR="./loot/chameleon-$(date +%Y%m%d_%H%M%S)"; mkdir -p "$LOOT_DIR"

echo " =================================================="
echo "  Chameleon Ultra — Load UID for Emulation"
echo "  UID       : $UID"
echo "  Card Type : $CARD_TYPE"
echo "  Slot      : $SLOT"
echo " =================================================="

if command -v chameleon >/dev/null 2>&1; then
    echo "[*] Using chameleon-cli..."
    chameleon slot set --slot "$SLOT" --type "$CARD_TYPE" 2>&1 | tee "${LOOT_DIR}/slot_config.txt"
    chameleon uid set --uid "$UID" 2>&1 | tee -a "${LOOT_DIR}/slot_config.txt"
    chameleon slot activate --slot "$SLOT" 2>&1 | tee -a "${LOOT_DIR}/slot_config.txt"
    echo "[+] UID $UID loaded into slot $SLOT as $CARD_TYPE"

elif python3 -c "from chameleon_ultra import ChameleonUltra" 2>/dev/null; then
    echo "[*] Using Python chameleon_ultra..."
    python3 - <<EOF
from chameleon_ultra import ChameleonUltra, SlotNumber, CardType
import binascii

ultra = ChameleonUltra()
ultra.connect()
slot = SlotNumber($SLOT)
card_type = CardType['$CARD_TYPE']
uid_bytes = binascii.unhexlify('$UID')

ultra.slot_change_tag_type(slot, card_type)
ultra.slot_tag_uid_write(slot, uid_bytes)
ultra.slot_enable(slot, True)
ultra.save_settings()
print("[+] UID loaded and slot activated")
ultra.disconnect()
EOF

else
    echo "[!] chameleon CLI or Python library not found."
    echo "    Install: pip install chameleon-ultra"
    echo "    OR: https://github.com/RfidResearchGroup/ChameleonUltra/releases"
    exit 1
fi

echo "[+] Present Chameleon Ultra to reader to emulate UID: $UID"
