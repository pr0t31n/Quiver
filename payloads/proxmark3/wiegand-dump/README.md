# Wiegand Card Dump & Replay

Wiegand protocol card dump and replay for access control systems via Proxmark3 Iceman firmware.

## Supported Formats
- HID Prox (26-bit, Corporate 1000, etc.)
- EM4100 / EM410x (125 kHz)
- Indala (125 kHz)

## Requirements
- Proxmark3 with Iceman firmware
- `pm3` command in PATH
- Python 3.7+

## Usage
```bash
python3 wiegand.py
python3 wiegand.py --port /dev/ttyACM0
```

## Features
- Auto-detect card type (`lf search` + `hf search`)
- Scan for HID Prox cards (`lf hid read`)
- Scan for EM4100 cards (`lf em 410x reader`)
- Scan for Indala cards (`lf indala reader`)
- Clone HID Prox FC/CN to T5577 blank
- Clone EM4100 UID to T5577 blank
- Simulate / replay HID Prox cards
- Save all results to JSON in `./loot/wiegand/`
