# T-Deck mDNS Scanner (Arduino)

mDNS/Bonjour service discovery scanner for the LilyGo T-Deck. Connects to WiFi, queries service types using the ESP32 ESPmDNS library, and displays results on the T-Deck's 320x240 display with trackball scrolling.

## Hardware
- LilyGo T-Deck (ESP32-S3)
- Built-in 320x240 ST7789 display
- Built-in trackball for scrolling results

## Required Libraries
- `TFT_eSPI` (display)
- `ESPmDNS` (built into ESP32 Arduino core)
- `WiFi` (built into ESP32 Arduino core)

## Configuration
Edit before flashing (or leave blank to prompt via Serial at boot):
```cpp
#define WIFI_SSID  "your-network"
#define WIFI_PASS  "your-password"
```

## Queried Service Types
`_http`, `_https`, `_ssh`, `_smb`, `_ftp`, `_homekit`, `_googlecast`, `_airplay`,
`_raop`, `_ipp`, `_printer`, `_rfb`, `_mqtt`, `_workstation`

## Serial Output
JSON per discovered service:
```json
{"type":"service","name":"macbook.local","service_type":"_ssh._tcp","host":"macbook.local","ip":"192.168.1.50","port":22}
```

## Navigation
- Trackball UP/DOWN: scroll results list
