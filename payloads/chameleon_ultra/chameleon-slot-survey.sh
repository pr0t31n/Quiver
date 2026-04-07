#!/usr/bin/env bash
# ==================================================================
#  chameleon-slot-survey.sh
#  Description : List all 8 Chameleon Ultra slots, showing card type,
#                UID, enabled/disabled status, and assigned name.
#  Requires    : chameleon-ultra Python library or chameleon CLI
#  Usage       : ./chameleon-slot-survey.sh
# ==================================================================

set -euo pipefail

echo " =================================================="
echo "  Chameleon Ultra — Slot Survey"
echo " =================================================="

if python3 -c "from chameleon_ultra import ChameleonUltra" 2>/dev/null; then
    python3 - <<'EOF'
from chameleon_ultra import ChameleonUltra, SlotNumber

ultra = ChameleonUltra()
ultra.connect()

print(f"\n  {'Slot':<6} {'Type':<20} {'UID':<20} {'Active'}")
print(f"  {'-'*60}")

for i in range(8):
    slot = SlotNumber(i)
    try:
        tag_type = ultra.slot_get_tag_type(slot)
        uid = ultra.slot_tag_uid_read(slot)
        enabled = ultra.slot_is_enabled(slot)
        uid_hex = uid.hex().upper() if uid else 'N/A'
        status = 'YES' if enabled else 'no'
        print(f"  {i:<6} {str(tag_type):<20} {uid_hex:<20} {status}")
    except Exception as e:
        print(f"  {i:<6} {'(empty/error)':<20} {'N/A':<20} no")

ultra.disconnect()
print("")
EOF
elif command -v chameleon >/dev/null 2>&1; then
    chameleon slot list
else
    echo "[!] chameleon_ultra not found. Install: pip install chameleon-ultra"
    exit 1
fi
