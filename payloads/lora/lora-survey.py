#!/usr/bin/env python3
"""
lora-survey.py
Description : Passive LoRa network survey via LilyGo LoRa32 or
              Heltec WiFi LoRa32 (MicroPython). Listens across common
              LoRa spreading factors and bandwidths to detect active
              networks, logs RSSI/SNR and packet metadata.
Requires    : mpremote (pip install mpremote) for MicroPython deployment
              OR runs directly on device REPL via serial
Usage       : python3 lora-survey.py <serial_port> [freq_mhz] [duration_s]
Defaults    : 915.0 MHz (US), 300 seconds
"""

import sys
import time
import os
import serial
from datetime import datetime

SERIAL_PORT = sys.argv[1] if len(sys.argv) > 1 else "/dev/ttyUSB0"
FREQ_MHZ    = float(sys.argv[2]) if len(sys.argv) > 2 else 915.0
DURATION    = int(sys.argv[3])   if len(sys.argv) > 3 else 300

LOOT_DIR = f"./loot/lora-survey-{datetime.now().strftime('%Y%m%d_%H%M%S')}"
os.makedirs(LOOT_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOOT_DIR, "lora_packets.csv")

# MicroPython survey script to upload and run on device
MICROPYTHON_SCRIPT = f"""
import time
from machine import SPI, Pin
try:
    from sx1276 import SX1276  # LilyGo LoRa32
except ImportError:
    from sx1262 import SX1262 as SX1276  # Heltec v3

lora = SX1276(spi=SPI(1), cs=Pin(18), irq=Pin(26), rst=Pin(14))
lora.set_freq({int(FREQ_MHZ * 1e6)})

configs = [(7, 125000), (8, 125000), (9, 125000), (10, 125000),
           (7, 250000), (12, 125000)]

print("CSV_START")
print("timestamp,sf,bw,rssi,snr,length,hex_data")

end = time.ticks_ms() + {DURATION * 1000}
while time.ticks_ms() < end:
    for sf, bw in configs:
        lora.set_sf(sf)
        lora.set_bw(bw)
        lora.recv_start()
        start = time.ticks_ms()
        while time.ticks_ms() - start < 1000:
            if lora.rx_done():
                pkt = lora.read()
                rssi = lora.get_rssi()
                snr  = lora.get_snr()
                ts = time.time()
                hex_data = ''.join(f'{{b:02x}}' for b in pkt)
                print(f'{{ts}},{{sf}},{{bw}},{{rssi}},{{snr}},{{len(pkt)}},{{hex_data}}')
                break
"""

print(f" ==================================================")
print(f"  LoRa Survey — LilyGo/Heltec LoRa32")
print(f"  Frequency: {FREQ_MHZ} MHz | Duration: {DURATION}s")
print(f"  Output: {LOG_FILE}")
print(f" ==================================================")
print("[*] Connecting to device REPL...")

try:
    ser = serial.Serial(SERIAL_PORT, 115200, timeout=2)
    time.sleep(1)

    # Send Ctrl+C to interrupt any running script, then paste our code
    ser.write(b'\x03\x03')
    time.sleep(0.5)
    ser.write(b'\x01')  # Raw REPL mode
    time.sleep(0.2)

    for line in MICROPYTHON_SCRIPT.strip().split('\n'):
        ser.write(line.encode() + b'\n')
        time.sleep(0.05)

    ser.write(b'\x04')  # Execute (Ctrl+D)
    time.sleep(1)

    print(f"[*] Listening for {DURATION}s...")
    with open(LOG_FILE, 'w') as log:
        log.write("timestamp,sf,bw,rssi,snr,length,hex_data\n")
        start = time.time()
        while (time.time() - start) < (DURATION + 5):
            line = ser.readline().decode(errors='ignore').strip()
            if ',' in line and not line.startswith('CSV'):
                log.write(line + '\n')
                parts = line.split(',')
                if len(parts) >= 5:
                    print(f"  [RX] SF{parts[1]} BW{parts[2]} RSSI={parts[3]}dBm SNR={parts[4]}dB len={parts[5]}")

except serial.SerialException as e:
    print(f"[!] Serial error: {e}")
    print(f"    Try: mpremote connect {SERIAL_PORT} run lora_survey_script.py")
except KeyboardInterrupt:
    pass

COUNT = sum(1 for _ in open(LOG_FILE)) - 1 if os.path.exists(LOG_FILE) else 0
print(f"\n[+] Packets captured: {COUNT}")
print(f"[+] Log: {LOG_FILE}")
