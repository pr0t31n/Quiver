#!/usr/bin/env bash
# ==================================================================
#  stm32-flash-dump.sh
#  Description : STM32 flash memory dump via ST-Link V2 using pyocd.
#                Reads full flash from standard STM32 address space.
#                Also dumps option bytes to determine RDP level.
#  Requires    : pyocd or openocd + st-flash
#  Usage       : ./stm32-flash-dump.sh [target_id] [flash_size_kb] [outfile]
#  Targets     : stm32f4 (default), stm32f1, stm32l4, stm32h7, etc.
# ==================================================================

set -euo pipefail
TARGET="${1:-stm32f4}"; FLASH_KB="${2:-512}"
LOOT_DIR="./loot/stm32-dump-$(date +%Y%m%d_%H%M%S)"; mkdir -p "$LOOT_DIR"
OUTFILE="${3:-${LOOT_DIR}/stm32_flash.bin}"
FLASH_BYTES=$((FLASH_KB * 1024))

echo " =================================================="
echo "  ST-Link V2 — STM32 Flash Dump"
echo "  Target  : $TARGET"
echo "  Flash   : ${FLASH_KB} KB"
echo "  Output  : $OUTFILE"
echo " =================================================="
echo ""

if command -v pyocd >/dev/null 2>&1; then
    echo "[*] Using pyocd..."
    echo "[*] Detected probes:"
    pyocd list 2>&1

    echo ""
    echo "[*] Reading option bytes (RDP level check)..."
    pyocd commander -t "$TARGET" \
        -c "read32 0x40022020" \
        2>&1 | tee "${LOOT_DIR}/option_bytes.txt" || true

    echo "[*] Dumping flash (${FLASH_KB} KB)..."
    pyocd commander -t "$TARGET" \
        -c "savemem 0x08000000 $FLASH_BYTES $OUTFILE" \
        2>&1 | tee "${LOOT_DIR}/dump_log.txt"

elif command -v st-flash >/dev/null 2>&1; then
    echo "[*] Using st-flash..."
    st-flash read "$OUTFILE" 0x08000000 $FLASH_BYTES 2>&1 | tee "${LOOT_DIR}/dump_log.txt"
else
    echo "[!] Neither pyocd nor st-flash found."
    echo "    Install: pip install pyocd  OR  apt install stlink-tools"
    exit 1
fi

if [ -f "$OUTFILE" ] && [ -s "$OUTFILE" ]; then
    MD5=$(md5sum "$OUTFILE" 2>/dev/null | cut -d' ' -f1 || md5 "$OUTFILE" 2>/dev/null | awk '{print $NF}')
    echo "[+] Flash: $OUTFILE (${FLASH_KB} KB) MD5=$MD5"
    echo ""
    echo "    Useful analysis:"
    echo "    strings $OUTFILE | grep -iE 'ssid|wifi|pass|key|secret|version'"
    echo "    binwalk -e $OUTFILE"
else
    echo "[!] Dump failed. Check RDP status and wiring."
fi
