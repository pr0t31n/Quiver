# T-Deck Deauth Monitor (Arduino)

802.11 deauthentication and disassociation frame monitor for the LilyGo T-Deck (ESP32-S3). Uses ESP32 promiscuous WiFi mode to sniff management frames and displays per-BSSID counts on the 320x240 ST7789 LCD.

## Hardware
- LilyGo T-Deck (ESP32-S3)
- Built-in 320x240 ST7789 display

## Required Libraries (Arduino IDE / PlatformIO)
- `TFT_eSPI` (or `LovyanGFX`)
- ESP32 Arduino core (for `esp_wifi.h`)

## Pin Defines
| Signal   | GPIO |
|----------|------|
| TFT_CS   | 12   |
| TFT_DC   | 11   |
| TFT_RST  | 10   |
| TFT_MOSI | 41   |
| TFT_SCLK | 40   |
| TFT_BL   | 42   |

## Features
- Sniffs deauth (subtype 12) and disassoc (subtype 10) frames
- Displays top 5 BSSIDs by frame count, updated every second
- Storm detection: alerts when >10 deauths in 5 seconds from same BSSID
- Serial JSON output: `{"type":"deauth","bssid":"xx:xx:xx:xx:xx:xx","reason":7,"target":"ff:ff:ff:ff:ff:ff"}`
- Channel configurable (default: ch 6); optional channel hopping (uncomment in loop())

## Flash
1. Open in Arduino IDE, set board to "LilyGo T-Deck"
2. Configure TFT_eSPI User_Setup.h for ST7789 320x240
3. Compile and upload via USB
