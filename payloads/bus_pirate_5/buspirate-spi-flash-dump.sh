#!/usr/bin/env bash
# ==================================================================
#  buspirate-spi-flash-dump.sh
#  Description : Dump SPI flash chip via Bus Pirate 5.
#                Supports common SPI NOR flash ICs:
#                Winbond W25Q, Macronix MX25L, ISSI IS25LP, GigaDevice GD25.
#                Uses flashrom for reliable read-back.
#  Requires    : flashrom with buspirate_spi programmer
#  Usage       : ./buspirate-spi-flash-dump.sh <device> [outfile] [chip]
#  Example     : ./buspirate-spi-flash-dump.sh /dev/ttyUSB0 firmware.bin W25Q64
# ==================================================================

set -euo pipefail
DEVICE="${1:?Usage: $0 <device> [outfile] [chip_model]}"
LOOT_DIR="./loot/spi-dump-$(date +%Y%m%d_%H%M%S)"; mkdir -p "$LOOT_DIR"
OUTFILE="${2:-${LOOT_DIR}/flash_dump.bin}"
CHIP="${3:-}"  # Leave empty for auto-detect

echo " =================================================="
echo "  Bus Pirate 5 — SPI Flash Dump"
echo "  Device : $DEVICE"
echo "  Output : $OUTFILE"
echo "  Chip   : ${CHIP:-auto-detect}"
echo " =================================================="
echo ""
echo "  Wiring: BP CS→CS, BP CLK→CLK, BP MOSI→DI, BP MISO→DO"
echo "          BP 3.3V→VCC (if chip not powered), GND→GND"
echo "  IMPORTANT: Power off target board before connecting"
echo ""

if ! command -v flashrom >/dev/null 2>&1; then
    echo "[!] flashrom not found. Install with: apt install flashrom | brew install flashrom"
    exit 1
fi

CHIP_ARG=""
[ -n "$CHIP" ] && CHIP_ARG="-c $CHIP"

echo "[*] Auto-detecting flash chip..."
flashrom -p buspirate_spi:dev="$DEVICE",spispeed=1M $CHIP_ARG 2>&1 | tee "${LOOT_DIR}/chip_detect.txt"

echo ""
echo "[*] Reading flash (this may take 1-10 minutes for large chips)..."
flashrom -p buspirate_spi:dev="$DEVICE",spispeed=1M $CHIP_ARG \
    -r "$OUTFILE" 2>&1 | tee "${LOOT_DIR}/dump_log.txt"

if [ -f "$OUTFILE" ]; then
    SIZE=$(wc -c < "$OUTFILE")
    MD5=$(md5sum "$OUTFILE" 2>/dev/null || md5 "$OUTFILE" 2>/dev/null || echo "N/A")
    echo ""
    echo "[+] Flash dump complete:"
    echo "    File   : $OUTFILE"
    echo "    Size   : ${SIZE} bytes ($(echo "scale=1; $SIZE/1048576" | bc) MB)"
    echo "    MD5    : $MD5"
    echo ""
    echo "    Analysis:"
    echo "    file $OUTFILE"
    echo "    strings $OUTFILE | grep -i 'password\|user\|admin\|version'"
    echo "    binwalk $OUTFILE"
else
    echo "[!] Dump failed — check wiring and chip identification."
fi
