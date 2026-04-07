#!/usr/bin/env bash
# ==================================================================
#  buspirate-jtag-idcode.sh
#  Description : JTAG chain enumeration via Bus Pirate 5.
#                Reads IDCODE from each device in the JTAG chain
#                to identify processor/FPGA/MCU type.
#  Requires    : openocd with buspirate interface OR urjtag
#  Usage       : ./buspirate-jtag-idcode.sh <device>
#  Wiring      : BP CLK→TCK, BP MOSI→TDI, BP MISO→TDO, BP CS→TMS
#               GND→GND, BP 3.3V→VTREF (if target unpowered)
# ==================================================================

set -euo pipefail
DEVICE="${1:?Usage: $0 <device>}"
LOOT_DIR="./loot/jtag-$(date +%Y%m%d_%H%M%S)"; mkdir -p "$LOOT_DIR"
IDCODE_FILE="${LOOT_DIR}/jtag_idcodes.txt"

echo " =================================================="
echo "  Bus Pirate 5 — JTAG IDCODE Read"
echo "  Device : $DEVICE"
echo " =================================================="
echo ""
echo "  Wiring: BP CLK→TCK, MOSI→TDI, MISO→TDO, CS→TMS, GND→GND"
echo ""

if command -v openocd >/dev/null 2>&1; then
    echo "[*] Using OpenOCD + buspirate interface..."
    cat > /tmp/buspirate_jtag.cfg <<-OCFG
        adapter driver buspirate
        buspirate_port $DEVICE
        buspirate_vreg 1
        buspirate_mode normal
        buspirate_speed 1000
        reset_config none
        jtag scan_chain
OCFG
    openocd -f /tmp/buspirate_jtag.cfg -c "scan_chain; jtag_reset 0 0; targets; exit" \
        2>&1 | tee "$IDCODE_FILE" || true

elif command -v jtag >/dev/null 2>&1; then
    echo "[*] Using UrJTAG..."
    {
        echo "cable BusPirate $DEVICE speed=1000"
        echo "detect"
        echo "quit"
    } | jtag 2>&1 | tee "$IDCODE_FILE" || true

else
    echo "[!] Neither openocd nor jtag (urjtag) found."
    echo "    Install: apt install openocd urjtag"
    exit 1
fi

echo ""
echo "[+] JTAG scan complete. Results: $IDCODE_FILE"
grep -iE "IDCODE|device|tap\b|chain" "$IDCODE_FILE" | head -20 || true
