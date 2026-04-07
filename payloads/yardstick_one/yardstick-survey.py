#!/usr/bin/env python3
"""
yardstick-survey.py
Description : Passive sub-GHz RF survey using Yardstick One (rfcat).
              Sweeps common ISM frequencies and measures RSSI,
              logging active signals to CSV.
Requires    : rfcat (pip install rfcat)
Usage       : sudo python3 yardstick-survey.py [start_mhz] [stop_mhz] [dwell_ms]
Defaults    : 300-950 MHz, 100ms dwell per channel
"""

import sys
import time
import csv
import os
from datetime import datetime

try:
    from rfcat import RfCat, MOD_ASK_OOK
    import rfcat.chipcon_usb as cc
except ImportError:
    print("[!] rfcat not found. Install with: pip install rfcat")
    sys.exit(1)

START_MHZ = float(sys.argv[1]) if len(sys.argv) > 1 else 300.0
STOP_MHZ  = float(sys.argv[2]) if len(sys.argv) > 2 else 950.0
DWELL_MS  = int(sys.argv[3])   if len(sys.argv) > 3 else 100
STEP_MHZ  = 1.0  # 1 MHz step

LOOT_DIR = f"./loot/yardstick-survey-{datetime.now().strftime('%Y%m%d_%H%M%S')}"
os.makedirs(LOOT_DIR, exist_ok=True)
CSV_FILE = os.path.join(LOOT_DIR, "spectrum_survey.csv")

print(f" ==================================================")
print(f"  Yardstick One — Sub-GHz Survey")
print(f"  Range: {START_MHZ:.0f}-{STOP_MHZ:.0f} MHz | Step: {STEP_MHZ} MHz")
print(f"  Output: {CSV_FILE}")
print(f" ==================================================")
print("[*] Press Ctrl+C to stop")

try:
    d = RfCat()
    d.setModeIDLE()
    d.setMdmModulation(MOD_ASK_OOK)

    freq = START_MHZ
    with open(CSV_FILE, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['timestamp', 'freq_mhz', 'rssi_dbm'])

        while True:
            d.setFreq(int(freq * 1e6))
            d.setModeRX()
            time.sleep(DWELL_MS / 1000.0)

            try:
                rssi = d.getRSSI()
            except Exception:
                rssi = -120

            ts = datetime.now().strftime('%H:%M:%S.%f')[:-3]
            writer.writerow([ts, f"{freq:.1f}", rssi])

            if rssi > -80:  # Only print strong signals
                print(f"  [{ts}] {freq:.1f} MHz  RSSI: {rssi} dBm  *** ACTIVE ***")

            freq += STEP_MHZ
            if freq > STOP_MHZ:
                freq = START_MHZ

except KeyboardInterrupt:
    print(f"\n[+] Survey complete. Data: {CSV_FILE}")
except Exception as e:
    print(f"[!] Error: {e}")
finally:
    try:
        d.setModeIDLE()
        d.cleanup()
    except Exception:
        pass
