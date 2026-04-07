#!/usr/bin/env python3
"""
lora-lorawan-sniff.py
Description : Passive LoRaWAN frame capture and decode. Identifies
              Join-Request, Join-Accept, uplink and downlink frames.
              Extracts DevEUI, AppEUI, DevAddr, FCnt for device tracking.
              Does NOT decrypt (requires AppSKey — for authorized testing).
Requires    : pylorawan or lorawanpacket, mpremote for device communication
Usage       : python3 lora-lorawan-sniff.py <serial_port> [freq_mhz] [duration_s]
"""

import sys
import time
import os
import struct
import binascii
import serial
from datetime import datetime

SERIAL_PORT = sys.argv[1] if len(sys.argv) > 1 else "/dev/ttyUSB0"
FREQ_MHZ    = float(sys.argv[2]) if len(sys.argv) > 2 else 868.1
DURATION    = int(sys.argv[3])   if len(sys.argv) > 3 else 300

LOOT_DIR = f"./loot/lorawan-sniff-{datetime.now().strftime('%Y%m%d_%H%M%S')}"
os.makedirs(LOOT_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOOT_DIR, "lorawan_frames.csv")

def parse_lorawan(data: bytes) -> dict:
    """Minimal LoRaWAN frame parser (unencrypted fields only)."""
    if len(data) < 4:
        return {}
    mhdr = data[0]
    mtype = (mhdr >> 5) & 0x7
    types = {0: 'JoinRequest', 1: 'JoinAccept', 2: 'UnconfDataUp',
             3: 'UnconfDataDn', 4: 'ConfDataUp', 5: 'ConfDataDn'}
    result = {'mtype': types.get(mtype, f'Unknown({mtype})')}

    if mtype == 0 and len(data) >= 23:  # Join Request
        result['AppEUI'] = binascii.hexlify(data[1:9][::-1]).decode()
        result['DevEUI'] = binascii.hexlify(data[9:17][::-1]).decode()
        result['DevNonce'] = struct.unpack('<H', data[17:19])[0]
    elif mtype in (2, 4) and len(data) >= 9:  # Data uplink
        result['DevAddr'] = binascii.hexlify(data[1:5][::-1]).decode()
        result['FCnt'] = struct.unpack('<H', data[6:8])[0]
        result['FPort'] = data[8] if len(data) > 8 else 'N/A'
    return result

print(f" ==================================================")
print(f"  LoRaWAN Sniffer")
print(f"  Frequency: {FREQ_MHZ} MHz | Duration: {DURATION}s")
print(f"  Output: {LOG_FILE}")
print(f" ==================================================")
print("[*] Watching for Join-Request, uplink, and downlink frames...")

try:
    ser = serial.Serial(SERIAL_PORT, 115200, timeout=2)
    # Brief device reset + enable RX forwarding via REPL
    ser.write(b'\x03\x03\r\n')
    time.sleep(0.5)

    with open(LOG_FILE, 'w') as log:
        log.write("timestamp,mtype,DevEUI,AppEUI,DevAddr,FCnt,FPort,rssi,snr,hex\n")
        start = time.time()

        while (time.time() - start) < DURATION:
            line = ser.readline().decode(errors='ignore').strip()
            if not line or ',' not in line:
                continue

            parts = line.split(',')
            if len(parts) < 4:
                continue

            try:
                rssi = parts[0]; snr = parts[1]
                hex_data = parts[-1]
                raw = bytes.fromhex(hex_data)
                parsed = parse_lorawan(raw)

                ts = datetime.now().strftime('%H:%M:%S.%f')[:-3]
                mtype = parsed.get('mtype', 'Unknown')
                deveui = parsed.get('DevEUI', '')
                appeui = parsed.get('AppEUI', '')
                devaddr = parsed.get('DevAddr', '')
                fcnt = parsed.get('FCnt', '')
                fport = parsed.get('FPort', '')

                log.write(f"{ts},{mtype},{deveui},{appeui},{devaddr},{fcnt},{fport},{rssi},{snr},{hex_data}\n")

                if mtype == 'JoinRequest':
                    print(f"  [{ts}] *** JOIN REQUEST ***")
                    print(f"    DevEUI={deveui} AppEUI={appeui} DevNonce={parsed.get('DevNonce','')}")
                elif 'Data' in mtype:
                    print(f"  [{ts}] {mtype}: DevAddr={devaddr} FCnt={fcnt} RSSI={rssi}dBm")

            except Exception:
                continue

except serial.SerialException as e:
    print(f"[!] Serial error: {e}")
except KeyboardInterrupt:
    pass

COUNT = sum(1 for _ in open(LOG_FILE)) - 1 if os.path.exists(LOG_FILE) else 0
print(f"\n[+] Frames decoded: {COUNT}")
print(f"[+] Log: {LOG_FILE}")
