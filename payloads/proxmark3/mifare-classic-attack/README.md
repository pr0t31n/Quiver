# MIFARE Classic Attack Automation

Full MIFARE Classic key recovery and card cloning automation via Proxmark3 Iceman firmware.

## Attack Methods (in order)
1. `hf mf autopwn` — full automated attack (nested + hardnested + dictionary)
2. `hf mf nested` — nested authentication attack (requires one known key)
3. `hf mf darkside` — CRYPTO1 PRNG darkside attack

## Requirements
- Proxmark3 with Iceman firmware
- `pm3` in PATH
- Python 3.7+

## Usage
```bash
python3 mifare.py
python3 mifare.py --port /dev/ttyACM0
```

## Features
- Full automated attack sequence with automatic fallback
- Dump full card memory to `.bin` after key recovery
- Clone card to Magic Card Gen1a (UID changeable)
- Clone card to Magic Card Gen2 (CUID)
- Saves all keys and results to `./loot/mifare/`
