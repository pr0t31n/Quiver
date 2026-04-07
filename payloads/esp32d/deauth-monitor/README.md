# 802.11 Deauth / Disassoc Monitor

Passive 802.11 deauthentication and disassociation frame monitor. Runs on host with a monitor-mode WiFi adapter, or reads JSON events from an ESP32 running custom monitor firmware via serial.

## Requirements
- Python 3.7+
- scapy: `pip3 install scapy`
- Monitor-mode WiFi adapter (e.g. Alfa AWUS036ACH)
- Root/sudo privileges for raw packet sniffing

## Usage
```bash
# Put adapter in monitor mode first:
sudo airmon-ng start wlan0

# Run monitor:
sudo python3 deauth_monitor.py -i wlan0mon

# Read from ESP32 serial (custom firmware):
python3 deauth_monitor.py --serial /dev/ttyUSB0

# Save events to file:
sudo python3 deauth_monitor.py -i wlan0mon --output deauth_log.json
```

## Detection
- Deauth frames: 802.11 type=0, subtype=12
- Disassoc frames: 802.11 type=0, subtype=10
- Storm alert: >10 deauths in 5 seconds from same BSSID
- Displays BSSID, reason code, target MAC, RSSI, running count
