# mDNS / Bonjour Service Discovery Scanner

Discovers mDNS/Bonjour services on the local network using the zeroconf library, with a raw multicast socket fallback.

## Requirements
- Python 3.7+
- zeroconf (recommended): `pip3 install zeroconf`
- Raw socket fallback requires no extra dependencies

## Usage
```bash
python3 mdns_scanner.py
python3 mdns_scanner.py --timeout 60
python3 mdns_scanner.py --raw          # force raw socket mode
python3 mdns_scanner.py --output scan.json
```

## Discovered Service Types
`_http._tcp`, `_https._tcp`, `_ssh._tcp`, `_ftp._tcp`, `_smb._tcp`, `_ipp._tcp`,
`_airplay._tcp`, `_googlecast._tcp`, `_homekit._tcp`, `_raop._tcp`, `_mqtt._tcp`,
`_rfb._tcp`, `_printer._tcp`, `_workstation._tcp`, and more.

## Output
- Live service display as discovered
- Formatted summary table (name, type, address, port, TXT records)
- JSON output file with all discovered services
