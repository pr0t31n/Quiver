#!/usr/bin/env bash
# ==================================================================
#  greatfet-swd-dump.sh
#  Description : ARM SWD flash dump via GreatFET One acting as a
#                debug probe. Attaches to ARM Cortex-M targets,
#                reads flash contents using pyocd over GreatFET.
#  Requires    : pyocd (pip install pyocd), greatfet
#  Usage       : ./greatfet-swd-dump.sh [target] [outfile]
#  Targets     : cortex_m (auto), stm32f4, nrf52, lpc1768, etc.
#  Wiring      : SWDCLK→SWDCLK, SWDIO→SWDIO, GND→GND
# ==================================================================

set -euo pipefail
TARGET="${1:-cortex_m}"; LOOT_DIR="./loot/swd-dump-$(date +%Y%m%d_%H%M%S)"; mkdir -p "$LOOT_DIR"
OUTFILE="${2:-${LOOT_DIR}/flash_dump.bin}"

echo " =================================================="
echo "  GreatFET One — SWD Flash Dump"
echo "  Target : $TARGET"
echo "  Output : $OUTFILE"
echo " =================================================="
echo ""
echo "  Wiring: GF J1_24→SWDCLK, J1_26→SWDIO, GND→GND"
echo "  Ensure target is powered"
echo ""

if ! command -v pyocd >/dev/null 2>&1; then
    echo "[!] pyocd not found. Install with: pip install pyocd"
    exit 1
fi

echo "[*] Detecting target..."
pyocd list 2>&1 | tee "${LOOT_DIR}/probe_list.txt"

echo ""
echo "[*] Reading flash memory..."
# Read standard Cortex-M flash at 0x08000000 (STM32) or 0x00000000 (nRF/LPC)
pyocd commander -t "$TARGET" -c "savemem 0x08000000 0x80000 ${OUTFILE}" 2>&1 | \
    tee "${LOOT_DIR}/dump_log.txt" || \
pyocd commander -t "$TARGET" -c "savemem 0x00000000 0x80000 ${OUTFILE}" 2>&1 | \
    tee "${LOOT_DIR}/dump_log.txt" || true

if [ -f "$OUTFILE" ] && [ -s "$OUTFILE" ]; then
    SIZE=$(wc -c < "$OUTFILE")
    echo "[+] Flash dump: $OUTFILE (${SIZE} bytes)"
    echo ""
    echo "    Analyze:"
    echo "    binwalk $OUTFILE"
    echo "    strings $OUTFILE | grep -i 'pass\|key\|secret\|wifi\|ssid'"
    echo "    arm-none-eabi-objdump -D -b binary -m arm $OUTFILE | head -100"
else
    echo "[!] Dump may have failed. Check ${LOOT_DIR}/dump_log.txt"
    echo "    RDP Level 2 (permanent protection) cannot be bypassed."
fi
