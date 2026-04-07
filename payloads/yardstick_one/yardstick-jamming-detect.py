#!/usr/bin/env python3
"""
yardstick-jamming-detect.py
Description : Passive detection of continuous-wave (CW) jamming or
              high-power interference on a frequency using Yardstick One.
              Monitors RSSI and alerts on sustained high-power signals
              that indicate active jamming or interference sources.
Requires    : rfcat
Usage       : sudo python3 yardstick-jamming-detect.py <freq_mhz> [threshold_dbm] [window_s]
Example     : sudo python3 yardstick-jamming-detect.py 433.92 -70 5
"""

import sys
import time
import os
from collections import deque
from datetime import datetime

try:
    from rfcat import RfCat, MOD_ASK_OOK
except ImportError:
    print("[!] rfcat not found. Install with: pip install rfcat")
    sys.exit(1)

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <freq_mhz> [threshold_dbm=-75] [window_s=5]")
    sys.exit(1)

FREQ_MHZ   = float(sys.argv[1])
THRESHOLD  = int(sys.argv[2]) if len(sys.argv) > 2 else -75
WINDOW_S   = int(sys.argv[3]) if len(sys.argv) > 3 else 5
POLL_MS    = 50  # RSSI poll interval

LOOT_DIR = "./loot/jamming-detect"
os.makedirs(LOOT_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOOT_DIR, f"jamming_{FREQ_MHZ:.2f}MHz_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")

print(f" ==================================================")
print(f"  Yardstick One — Jamming/Interference Detector")
print(f"  Frequency : {FREQ_MHZ} MHz")
print(f"  Threshold : {THRESHOLD} dBm (sustained = jamming)")
print(f"  Window    : {WINDOW_S}s")
print(f" ==================================================")
print("[*] Press Ctrl+C to stop")

WINDOW_SAMPLES = int((WINDOW_S * 1000) / POLL_MS)
rssi_window = deque(maxlen=WINDOW_SAMPLES)
alert_active = False

try:
    d = RfCat()
    d.setModeIDLE()
    d.setFreq(int(FREQ_MHZ * 1e6))
    d.setMdmModulation(MOD_ASK_OOK)
    d.setModeRX()

    with open(LOG_FILE, 'w') as log:
        log.write(f"Timestamp,RSSI_dBm,Status\n")
        while True:
            rssi = d.getRSSI()
            rssi_window.append(rssi)
            ts = datetime.now().strftime('%H:%M:%S.%f')[:-3]

            # If enough samples and all above threshold → jamming
            if len(rssi_window) == WINDOW_SAMPLES:
                above = sum(1 for r in rssi_window if r > THRESHOLD)
                pct = above / WINDOW_SAMPLES * 100

                if pct >= 90 and not alert_active:
                    alert_active = True
                    msg = f"[!] JAMMING DETECTED at {FREQ_MHZ} MHz! RSSI sustained above {THRESHOLD} dBm ({pct:.0f}% of window)"
                    print(msg)
                    log.write(f"{ts},{rssi},JAMMING_ALERT\n")
                elif pct < 50 and alert_active:
                    alert_active = False
                    print(f"[*] Jamming cleared at {ts}")
                    log.write(f"{ts},{rssi},CLEARED\n")
                else:
                    log.write(f"{ts},{rssi},normal\n")
            else:
                log.write(f"{ts},{rssi},warming_up\n")

            if rssi > THRESHOLD:
                print(f"  [{ts}] RSSI: {rssi} dBm {'*** HIGH ***' if rssi > THRESHOLD else ''}")

            time.sleep(POLL_MS / 1000.0)

except KeyboardInterrupt:
    print(f"\n[+] Log: {LOG_FILE}")
except Exception as e:
    print(f"[!] Error: {e}")
finally:
    try:
        d.setModeIDLE()
        d.cleanup()
    except Exception:
        pass
