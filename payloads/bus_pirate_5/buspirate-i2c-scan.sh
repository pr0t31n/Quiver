#!/usr/bin/env bash
# ==================================================================
#  buspirate-i2c-scan.sh
#  Description : I2C address scan (0x00-0x7F) via Bus Pirate 5.
#                Identifies all responsive devices on the I2C bus.
#                Common targets: IoT sensors, EEPROMs, MCU peripherals,
#                HDMI EDID chips, camera modules.
#  Requires    : Bus Pirate 5 in I2C mode, python3 + pyserial
#  Usage       : ./buspirate-i2c-scan.sh <device> [speed]
#  Speed       : 100 (default) | 400 | 1000 (kHz)
# ==================================================================

set -euo pipefail
DEVICE="${1:?Usage: $0 <device> [speed_khz]}"
SPEED="${2:-100}"
LOOT_DIR="./loot/i2c-scan-$(date +%Y%m%d_%H%M%S)"; mkdir -p "$LOOT_DIR"
OUTFILE="${LOOT_DIR}/i2c_devices.txt"

echo " =================================================="
echo "  Bus Pirate 5 — I2C Address Scan"
echo "  Device : $DEVICE | Speed: ${SPEED} kHz"
echo " =================================================="
echo ""
echo "  Wiring: SDA→SDA, SCL→SCL, GND→GND, 3.3V→VCC (if bus unpowered)"
echo ""

python3 - <<EOF | tee "$OUTFILE"
import serial, time, sys

device = "$DEVICE"
speed  = $SPEED

try:
    bp = serial.Serial(device, 115200, timeout=1)
except Exception as e:
    print(f"[!] Cannot open {device}: {e}")
    sys.exit(1)

def bp_send(cmd):
    bp.write(cmd)
    time.sleep(0.05)
    return bp.read(bp.in_waiting)

# Enter binary mode
bp.write(b'\x00' * 20)
time.sleep(0.1)
bp.write(b'\x00')
resp = bp.read_until(b'BBIO1', timeout=2)
if b'BBIO1' not in resp:
    print("[!] Bus Pirate binary mode not responding. Power cycle and try again.")
    bp.close(); sys.exit(1)

# Enter I2C mode
bp.write(b'\x02')
resp = bp.read_until(b'I2C1', timeout=2)
if b'I2C1' not in resp:
    print("[!] I2C mode failed.")
    bp.close(); sys.exit(1)

# Set speed (0x60=~5k, 0x61=~50k, 0x62=~100k, 0x63=~400k)
speed_map = {5: b'\x60', 50: b'\x61', 100: b'\x62', 400: b'\x63', 1000: b'\x63'}
spd_byte = speed_map.get(speed, b'\x62')
bp.write(spd_byte); bp.read(1)

# Enable power + pullups
bp.write(b'\x4C'); bp.read(1)

print(f"[*] Scanning I2C bus {device} at {speed} kHz...")
print("")
print("  Addr  | Hex  | Status")
print("--------|------|--------")

found = []
for addr in range(0x00, 0x78):
    # Start + addr(write) + Stop
    bp.write(b'\x02')  # Start
    bp.write(b'\x10\x01')  # Send 1 byte
    bp.write(bytes([addr << 1]))  # Address + write bit
    bp.write(b'\x03')  # Stop
    resp = bp.read(4)
    if resp and len(resp) >= 3 and resp[2] == 0x00:  # ACK
        found.append(addr)
        print(f"  {addr:5d} | 0x{addr:02X} | FOUND")

print("")
if found:
    print(f"[+] {len(found)} device(s) found: {[f'0x{a:02X}' for a in found]}")
else:
    print("[*] No I2C devices found. Check wiring and bus power.")

# Disable power, back to user mode
bp.write(b'\x44'); bp.read(1)
bp.write(b'\x0F'); bp.read(10)
bp.close()
EOF

echo "[+] Results: $OUTFILE"
