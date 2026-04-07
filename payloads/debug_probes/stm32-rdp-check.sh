#!/usr/bin/env bash
# ==================================================================
#  stm32-rdp-check.sh
#  Description : Check STM32 Read Protection (RDP) level via ST-Link.
#                Level 0 = no protection (flash readable)
#                Level 1 = read protection (flash NOT readable via debug)
#                Level 2 = permanent protection (debug port disabled forever)
#  Requires    : pyocd or openocd
#  Usage       : ./stm32-rdp-check.sh [target_id]
# ==================================================================

set -euo pipefail
TARGET="${1:-stm32f4}"
LOOT_DIR="./loot/stm32-rdp-$(date +%Y%m%d_%H%M%S)"; mkdir -p "$LOOT_DIR"

echo " =================================================="
echo "  ST-Link V2 — STM32 RDP Level Check"
echo "  Target: $TARGET"
echo " =================================================="

# STM32F4 Option Bytes base address = 0x1FFFC000
# RDP byte is at offset 1 (0x1FFFC001)
# For STM32F1: 0x1FFFF800

declare -A RDP_ADDRS=(
    ["stm32f4"]="0x1FFFC000"
    ["stm32f1"]="0x1FFFF800"
    ["stm32f7"]="0x1FFF0000"
    ["stm32l4"]="0x1FFF7800"
    ["stm32h7"]="0x1FF00000"
)

OB_ADDR="${RDP_ADDRS[$TARGET]:-0x1FFFC000}"

if command -v pyocd >/dev/null 2>&1; then
    echo "[*] Reading option bytes at $OB_ADDR..."
    OB_OUT=$(pyocd commander -t "$TARGET" \
        -c "read32 $OB_ADDR" 2>&1 | tee "${LOOT_DIR}/option_bytes.txt")
    RDP_RAW=$(echo "$OB_OUT" | grep -oiE '0x[0-9a-f]+' | head -1 || true)
    RDP_BYTE=$(echo "$RDP_RAW" | awk '{print and(strtonum($0),0xFF)}' 2>/dev/null || true)

    echo ""
    echo "  Option bytes: $RDP_RAW"
    echo "  RDP byte    : 0x${RDP_BYTE:-??}"
    echo ""

    case "${RDP_BYTE:-}" in
        *"AA"|*"aa") echo "  [!] RDP Level 0 — NO PROTECTION — flash is readable via debug" ;;
        *"CC"|*"cc") echo "  [!] RDP Level 2 — PERMANENT — debug port disabled, flash locked forever" ;;
        *)           echo "  [*] RDP Level 1 — Protected — flash not readable via debug (but erasable)" ;;
    esac
else
    echo "[!] pyocd not found. Install with: pip install pyocd"
    exit 1
fi

echo ""
echo "[+] Full output: ${LOOT_DIR}/option_bytes.txt"
