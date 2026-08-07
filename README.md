# Quiver

**Browser-based hardware hacking command centre** — unified device management, interactive shells, payload deployment, and real-time script orchestration for 45+ pentest hardware tools in a single Flask application.

Quiver abstracts the CLI complexity of dozens of physical tools into a single web interface on **port 5002**. Connect a device, open its page, and either run a managed script (interactive prompts surface as modal dialogs) or drop into a native shell — SSH for network-attached Hak5 gear, serial for MicroPython REPLs, PTY for interactive CLIs like `pm3` and `rfcat`, or WebSocket for WiFi Duck. A background thread detects every connected device every five seconds and pushes live presence indicators to all browsers. Payload libraries are JSON-indexed, per device, and uploadable from the UI.

---

## Features

- **45-device registry** — every tool has a named entry with detection credentials, shell type, USB VID/PIDs, default SSH host, and optional web UI link; 8 category groups for navigation
- **4-mode interactive shells** — `ssh` (paramiko, xterm-256color, 220×50 PTY), `serial` (pyserial, auto VID:PID detection), `process` (OS PTY via `pty.openpty`, full terminal resize), `websocket` (relay to WiFi Duck at `ws://192.168.4.1/ws`)
- **Script runner with web-mode protocol** — device scripts run as subprocesses with `QUIVER_WEB_MODE=1`; emit `LOG:{json}` lines for structured output and `PROMPT:{json}` for interactive questions; responses piped back over stdin
- **Background device detection** — daemon thread scans all 45 devices every 5 s using TCP ping (SSH), serial VID:PID scan (pyserial), pyusb/lsusb lookup (USB), and WiFi TCP probe; pushes `device_status_update` SocketIO events on change
- **Peer Quiver discovery** — daemon thread scans `10.87.86.0/23` every 30 s for other Quiver instances on port 5002; results surfaced in-UI with direct links
- **Reverse proxy** — `/proxy/<device_id>/` transparently proxies any device's web interface through Quiver, rewriting HTML/CSS URLs and injecting a JS shim to intercept `fetch()` and XHR
- **Payload library** — JSON-indexed per-device payload library; upload new scripts from the browser; scripts auto-detected for USB save (macOS `diskutil` / Linux `/sys/block`); `QUIVER_SELECTED_PAYLOAD` env var passed to device script on launch
- **Firmware status** — GitHub API check per device for latest release tag; `GITHUB_TOKEN` env var for authenticated requests
- **400-line console ring buffer** — per-session in-memory console history replayed on reconnect

---

## Requirements

- Python 3.10+
- Linux or macOS (PTY shells require POSIX)

```bash
pip install -r requirements.txt
```

**Core dependencies:**

| Package | Purpose |
|---------|---------|
| `flask>=3.0` | Web framework |
| `flask-socketio>=5.3` | Real-time WebSocket events |
| `paramiko>=3.0` | SSH shells (Hak5 network devices) |
| `pyserial>=3.5` | Serial shells + device detection |
| `requests>=2.28` | Reverse proxy + GitHub API |
| `pyusb>=1.2.1` | USB presence detection |
| `esptool>=4.7` | ESP32 firmware flashing |
| `mpremote>=1.22` | MicroPython file transfer |
| `pyflipper>=0.2` + `flipperzero-protobuf>=0.8` | Flipper Zero management |
| `pyhackrf>=2024.2` | HackRF One |
| `bellows>=0.36` + `zigpy>=0.60` | Sonoff ZBDongle-E Zigbee coordinator |
| `zigpy-znp>=0.11` | LilyGo T-Zigbee ZNP coordinator |
| `cynthion>=1.0` + `facedancer>=3.1.2` | Cynthion USB sniffing/emulation |
| `greatfet>=2021.2.1` | GreatFET One |
| `pyocd>=0.36` | STM32 debug (ST-Link / Nucleo) |
| `pylink-square>=1.0` | J-Link EDU Mini |
| `scapy>=2.5` | PCAP parsing (Ubertooth) |
| `websocket-client>=1.6` | WiFi Duck WebSocket relay |

**System tools** (via package manager):

```bash
# macOS
brew install hackrf ubertooth stlink proxmark3
brew install --cask segger-jlink

# Linux (Kali / Debian / Ubuntu)
sudo apt install hackrf ubertooth stlink-tools proxmark3
```

---

## Installation

```bash
git clone https://github.com/yourorg/quiver
cd quiver
pip install -r requirements.txt
python3 app.py
```

Open **http://localhost:5002** in your browser.

---

## Supported Devices

### Hak5 Gear

| Device | Shell | Default Host | Default Credentials |
|--------|-------|-------------|---------------------|
| **Bash Bunny** | SSH | `172.16.64.1` | `root` / `hak5bunny` |
| **WiFi Pineapple MK7** | SSH | `172.16.42.1` | `root` / `hak5pineapple` |
| **Shark Jack** | SSH | `172.16.24.1` | `root` / `hak5shark` |
| **Packet Squirrel** | SSH | `172.16.32.1` | `root` / `hak5squirrel` |
| **LAN Turtle** | SSH | `172.16.84.1` | `root` / `sh3llz` |
| **Signal Owl** | SSH | `172.16.56.1` | `root` / `hak5owl` |
| **Key Croc** | SSH | DHCP (enter IP manually) | `root` / `hak5croc` |
| **Screen Crab** | — | — | — |
| **Plunder Bug** | — | — | — |
| **Rubber Ducky 3** | — | `—` | HID / storage mode |
| **O.MG Cable / Elite** | — | `192.168.4.1` | web UI |
| **Wi-Fi Coconut** | — | — | 14× AR9271 USB hub |

### RF & SDR

| Device | Shell | USB VID:PID |
|--------|-------|------------|
| **HackRF One** | — (libusb) | `1D50:6089` |
| **Yardstick One** | `rfcat -r` (PTY) | `1D50:605B` |
| **Ubertooth One** | — (libusb) | `1D50:6002` |
| **WiFi Duck** | WebSocket `ws://192.168.4.1/ws` | `2341:8037` + others |
| **Evil Crow RF** | — | `10C4:EA60` / `303A:0002` |
| **BugBlat MiniSniffer 2** | — | `16D0:05B4` |

### RFID / NFC

| Device | Shell | USB VID:PID |
|--------|-------|------------|
| **Proxmark3 Iceman** | `pm3 {port}` (PTY) | `9AC4:4B8F` + others |
| **Flipper Zero** | Serial REPL (115200) | `0483:5740` |
| **Chameleon Ultra** | `chameleon_cli_main.py` (PTY) | `6868:*` |

### Zigbee / BLE

| Device | Shell | USB VID:PID |
|--------|-------|------------|
| **Sonoff ZBDongle-E** | — | `1A86:55D4` / `10C4:EA60` |
| **LilyGo T-Zigbee v1.2** | Serial UART console | `303A:1001` + others |
| **Nordic nRF52840** | Serial CDC console | `1915:521F` / `1915:520F` |
| **Nordic nRF52833-DK** | — (nRF Sniffer via J-Link) | `1366:1015` / `1366:1051` |
| **TI CC26X2R1 LaunchPad** | — (Sniffle via XDS110) | `0451:BEF3` |
| **TI CC1352P-4 LaunchPad** | — (Sniffle, PA-path 2.4 GHz) | `0451:BEF3` |
| **Bluefruit LE Sniffer** | — (nRF Sniffer v2, BLE 4.0) | `10C4:EA60` |
| **CC2531** | Serial CDC UART | `0451:16AE` |

Firmware/tooling for the four BLE boards above (Sniffle, the nRF Sniffer for
Bluetooth LE, the Adafruit sniffer host scripts, and crackle) is fetched into
`firmware/<tool_id>/` by the downloader:

```bash
python3 firmware/download.py --tools cc1352p4,cc26x2r1,nrf52833_dk,bluefruit_le_sniffer --yes
```

`--yes` runs non-interactively; omit `--tools` to select interactively. Both TI
boards use a **prebuilt Sniffle hex** (CC26X2R1 → `sniffle_cc2652r1.hex`,
CC1352P-4 → `sniffle_cc1352p1_cc2652p1.hex`) — no from-source build or TI SDK is
needed. **Flashing** these boards requires **TI UniFlash** (`dslite`): the XDS110
uses 2-pin cJTAG, which OpenOCD cannot drive, so UniFlash is the flasher (free,
needs a TI account; Quiver auto-discovers `dslite` or guides the GUI). On the
CC1352P-4, run a BLE capture after flashing to confirm 2.4 GHz reception (the -4
routes 2.4 GHz through its high-power PA path).

**Passive firmware detection.** The Firmware tab reads the installed version
directly off the device — read-only, no flashing — so you can see whether the
correct firmware is already present before prepping an update. Supported devices
expose it via `python3 <script> --probe-fw-version` (JSON) and a `fw_probe` flag
in the tool registry: **CC1352P-4** and **CC26X2R1** (Sniffle `probe_fw_version`
over the XDS110 serial), **HackRF One** (`hackrf_info`), and **Ubertooth One**
(`ubertooth-util -v`). Other devices fall back to "Run script to detect".

**XDS110 board identity.** The CC1352P-4 and CC26X2R1 both present their onboard
XDS110 debug probe as USB `0451:BEF3`, so they are indistinguishable by USB alone
— flashing the wrong tool would target the wrong chip. Quiver identifies them by
the probe's unique **serial number**, pinned to a board (via each tool's *Identify
this board* menu option, or on first flash) in `xds110_boards.json`. Once pinned,
autodetect shows only the correct board, and every flash re-checks the serial and
**refuses** if it belongs to the other board. Unpinned probes are flagged
`unverified` and require confirmation before flashing.

### Microcontrollers & Embedded

| Device | Shell | Chip | Notes |
|--------|-------|------|-------|
| **ESP32-D** | Serial MicroPython REPL | ESP32 | esptool flash support |
| **Raspberry Pi Pico** | Serial MicroPython REPL | RP2040 | UF2 boot |
| **Raspberry Pi Pico W** | Serial MicroPython REPL | RP2040 + CYW43439 | WiFi |
| **Raspberry Pi Pico 2W** | Serial MicroPython REPL | RP2350 + CYW43439 | WiFi |
| **LilyGo T-Deck** | Serial ESP32-S3 console | ESP32-S3 | Keyboard + display |
| **LilyGo LoRa32 v1.6.1** | Serial MicroPython REPL | ESP32 + SX1276 | LoRa |
| **Heltec WiFi LoRa32 v3** | Serial MicroPython REPL | ESP32-S3 + SX1262 | LoRa |
| **Bus Pirate 5** | Serial REPL | — | `1209:7331` |
| **Bus Pirate 3.6** | Serial REPL | — | `04D8:FB00` |
| **DWM3001CDK** | Serial CDC console | nRF52833 | UWB ranging |
| **Particle Photon 2** | Serial monitor | — | `2B04:C305` |

### Debug Probes

| Device | Shell | Purpose |
|--------|-------|---------|
| **ST-Link V2** | — | STM32 flash/debug via `st-flash` |
| **Nucleo-F429ZI** | Serial VCP (USART3, 115200) | STM32F429ZI eval board + **Click Shield (mikroBUS) pentest toolkit** |
| **J-Link EDU Mini** | `JLinkExe` (PTY) | ARM debug / RTT capture |
| **GreatFET One** | `gf shell` (PTY) | Hardware analysis / SWD |
| **Cynthion** | — | USB sniffing / Facedancer |

#### Nucleo Click Shield (mikroBUS) pentest toolkit

The Nucleo-F429ZI module includes a configurable **Click Shield** subsystem for the
chain *Nucleo → MIKROE Click Shield for Nucleo-144 → Click(s) in socket 1–4*. It
drives the Click peripherals through companion **"Quiver Click" firmware** on the
STM32 (line protocol over the ST-Link VCP) and exposes per-bus sniffing and
injection:

| Click | Bus | Sniff | Inject | Flood/DoS | Replay | Other |
|-------|-----|:---:|:---:|:---:|:---:|-------|
| CAN SPI (MCP2515) | SPI | ✅ | ✅ | ✅ | ✅ | — |
| RS485 8 | UART | ✅ | ✅ | ✅ | ✅ | — |
| RS232 4 | UART | ✅ | ✅ | — | ✅ | — |
| XBee 2 (802.15.4) | UART | ✅ | ✅ | ✅ | ✅ | — |
| UWB 3 (DW3000) | SPI | ✅ | — | — | — | range / relay |
| NFC 2 (PN7150) | I²C | ✅ | — | — | — | read / emulate / relay |
| 5G NB IoT | UART | — | — | — | — | AT enumeration only |

- **Autodetect** — firmware `SCAN` probes each socket by chip signature (SPI ID /
  I²C addr / UART response) and auto-populates the config; the shield itself is
  passive (no ID chip) so it is *inferred* from the Nucleo + detected Clicks.
  Passive RS-232/RS-485 transceivers can't be uniquely identified and prompt for
  confirmation.
- **Diagnostics** — a 6-stage health walk (Nucleo → VCP → firmware → shield →
  config → per-socket self-test) that pinpoints the first failing link with
  basic + intermediate remediation and per-Click hints.
- Config persists to `~/.quiver/click_shield_config.json`; captures to
  `~/.quiver/click_captures/`.
- **Authorized testing only** — every active op (inject/flood/replay/emulate/relay)
  is gated behind an in-scope confirmation. Cellular RF jamming/DoS is intentionally
  **not** provided (illegal).

> Requires the companion Quiver Click firmware on the STM32 (flash via the module's
> *Flash Click Firmware* action); the module documents the host↔MCU command protocol.

---

## Payload Library

Each device has a payload library — named scripts stored under `payloads/<device>/` and indexed in `payloads/payloads.json`. Select a payload from the device page; it is passed to the device script via `QUIVER_SELECTED_PAYLOAD`.

### Built-in Payloads

**Bash Bunny:**
`cross-platform-enum`, `sysaudit-target-audit`, `privesc-windows-audit`, `keyboard-id-spoof-test`, `passive-network-capture`, `ethernet-mode`

**Hak5 Network Devices:**
- Screen Crab: `motion-login`, `interval-monitor`, `video-session`, `stealth-slow`
- Plunder Bug: `capture-full`, `capture-passive`, `capture-dns`, `capture-creds`, `capture-voip`, `capture-ics`
- Signal Owl: `wifi-survey-passive`
- Key Croc: `keylog-credential-harvest`
- LAN Turtle: `autossh-reverse`, `responder-lan-turtle`
- Shark Jack: `network-recon-full`, `msf-import-sharkjack`
- Packet Squirrel: `full-capture-timed`, `credsniff-passive`, `openvpn-tunnel`
- WiFi Pineapple: `wifi-survey`

**RFID / Hardware:**
- Proxmark3: `rfid-survey`, `rfid-clone-em410x`, `rfid-mifare-classic-audit`, `rfid-desfire-enum`, `rfid-hid-clone`
- Chameleon Ultra: `chameleon-load-uid`, `chameleon-mifare-emulate`, `chameleon-slot-survey`

**SDR / RF:**
- HackRF One: `hackrf-spectrum-survey`, `hackrf-record-replay`, `hackrf-pager-sniff`, `hackrf-adsb-decode`, `hackrf-gsm-survey`
- Ubertooth One: `ubertooth-ble-survey`, `ubertooth-bredr-sniff`, `ubertooth-spectrum`
- Yardstick One: `yardstick-survey`, `yardstick-ook-record`, `yardstick-ook-replay`, `yardstick-jamming-detect`

**Zigbee / BLE / LoRa:**
- `zigbee-channel-survey`, `zigbee-pcap-capture`, `zigbee-replay-attack`, `zigbee-key-extract`, `killerbee-launch`
- `lora-survey`, `lora-lorawan-sniff`, `lora-replay-test`
- BLE connection sniffing (pairing capture → `crackle`): TI CC26X2R1 / CC1352P-4 via **Sniffle** (`sniff_receiver.py`, 2 Mbaud XDS110); Nordic nRF52833-DK & Adafruit Bluefruit LE Sniffer via **nRF Sniffer** (Wireshark extcap). TI boards flash prebuilt Sniffle hexes via **TI UniFlash** (`dslite`; OpenOCD can't drive the XDS110 cJTAG).

**Debug Probes:**
- Bus Pirate 5: `buspirate-uart-sniff`, `buspirate-i2c-scan`, `buspirate-spi-flash-dump`, `buspirate-jtag-idcode`
- STM32: `stm32-flash-dump`, `stm32-rdp-check`
- J-Link: `jlink-rtt-capture`
- Cynthion: `cynthion-usb-sniff`, `facedancer-hid-fuzz`, `facedancer-mass-storage`
- GreatFET: `greatfet-logic-capture`, `greatfet-swd-dump`

**Microcontrollers:**
- ESP32-D: `wifi-scanner`, `ble-scanner`, `deauth-monitor`, `mdns-scanner`
- Raspberry Pi Pico: `hid-keyboard`, `ducky-runner`
- Raspberry Pi Pico W: `wifi-exfil`, `wireless-sysaudit`
- LilyGo T-Deck: `wifi-deauth`, `network-recon`
- Nordic nRF52840: `ble-fingerprint`, `ble-mitm-setup`

**Manual (USB Drive) / Platform Audit Scripts:**
- SysAudit: Windows, Debian, RedHat, macOS
- PrivescAudit: Windows, Linux, macOS
- CredExposure: Windows, Linux, macOS
- LateralMovement: Windows, Linux
- PersistenceSurvey: Windows, Linux, macOS

---

## Web Mode Protocol

Device scripts run as managed subprocesses with `QUIVER_WEB_MODE=1` set in their environment. They communicate with Flask over stdin/stdout using two line-prefixed protocols (defined in `common.py`).

### Output — `LOG:{json}`

```
LOG:{"level": "ok",      "text": "Device connected"}
LOG:{"level": "err",     "text": "Flash failed"}
LOG:{"level": "warn",    "text": "No SSID found"}
LOG:{"level": "progress","pct": 42, "text": "Flashing...", "step": "chunk 42/100"}
LOG:{"level": "wait_start",   "text": "Waiting for device..."}
LOG:{"level": "wait_done",    "text": "Connected"}
LOG:{"level": "wait_timeout", "text": "Timed out"}
```

| Level | UI treatment |
|-------|-------------|
| `ok` | Green checkmark line |
| `warn` | Yellow warning line |
| `err` | Red error line |
| `info` | Cyan info line |
| `heading` / `banner` | Section header |
| `progress` | Progress bar update (`pct`, `text`, `step`) |
| `wait_start` | Modal spinner open |
| `wait_done` | Modal spinner close (success) |
| `wait_timeout` | Modal spinner close (timeout) |
| `wait_status` | Modal spinner status text update |

### Interactive Prompts — `PROMPT:{json}`

```
PROMPT:{"type": "text",     "question": "Enter SSID",      "default": ""}
PROMPT:{"type": "password", "question": "Enter password",   "default": ""}
PROMPT:{"type": "confirm",  "question": "Reboot device?",   "default": true}
PROMPT:{"type": "menu",     "question": "Select attack",    "options": ["Clone EM410x", "Read tag"]}
PROMPT:{"type": "pause",    "question": "Press ENTER to continue…"}
```

Flask responds with one JSON line: `{"value": "user-entered-answer"}`. Prompts time out after 30 minutes. Password answers are masked in the console log as `< [hidden]`.

---

## REST API

| Method | Route | Purpose |
|--------|-------|---------|
| GET | `/` | Home — device grid by category |
| GET | `/tool/<tool_id>` | Device page — scripts, shell, payloads |
| GET | `/api/device-status` | Full device presence snapshot |
| GET | `/api/firmware-status/<tool_id>` | GitHub latest release check |
| GET | `/api/peer-instances` | Discovered peer Quiver instances |
| GET | `/api/peer-subnet-active` | Whether on `10.87.86.0/23` subnet |
| GET | `/api/network-devices` | Network appliance status |
| GET/POST/… | `/proxy/<device_id>/` | Reverse proxy to device web UI |
| GET/POST/… | `/proxy/<device_id>/<path>` | Reverse proxy subpath |
| GET | `/api/usb/save-info?payload=<path>` | Payload content + mounted USB volumes |
| GET | `/api/payloads/<tool_id>` | Payload list for a tool |
| POST | `/api/payloads/add` | Upload new payload (multipart form) |

---

## SocketIO Events

### Client → Server

| Event | Payload | Purpose |
|-------|---------|---------|
| `request_device_status` | — | Request full device presence snapshot |
| `request_network_devices` | — | Request network appliance snapshot |
| `request_peer_instances` | — | Request peer Quiver snapshot |
| `join_session` | `{session_id}` | Join session room; replays console history |
| `start_script` | `{session_id, tool_id, payload_path?}` | Launch device script |
| `script_answer` | `{session_id, answer}` | Answer pending prompt |
| `kill_script` | `{session_id}` | Terminate running script |
| `ssh_connect` | `{session_id, tool_id, host?}` | Open shell |
| `ssh_input` | `{session_id, data}` | Send keystrokes to shell |
| `ssh_resize` | `{session_id, cols, rows}` | Resize PTY |
| `ssh_disconnect` | `{session_id}` | Close shell |

### Server → Client

| Event | Payload | Purpose |
|-------|---------|---------|
| `device_status_update` | `{tool_id, name, icon, status}` | Device appeared / disappeared |
| `device_status_snapshot` | `{tool_id: status, …}` | Full presence snapshot |
| `netdev_update` | `{id, name, icon, web_url, connected}` | Appliance state change |
| `netdev_snapshot` | `[{id, name, …}]` | Full appliance snapshot |
| `peer_instances_update` | `{peers: [{ip, url, since}]}` | Peer list changed |
| `peer_instances_snapshot` | `{peers, subnet_active}` | Full peer snapshot |
| `session_state` | `{console_history}` | Replay on rejoin |
| `script_started` | `{pid}` | Script launched |
| `script_output` | `{text, stream, ts}` | Console line |
| `script_prompt` | `{type, question, options?, default?}` | Interactive prompt |
| `prompt_resolved` | — | Prompt answered / dismissed |
| `script_progress` | `{pct, text, step}` | Progress bar update |
| `script_wait_start/done/timeout/status` | `{text}` | Modal spinner lifecycle |
| `script_error` | `{error}` | Script error |
| `script_done` | `{returncode}` | Script exited |
| `script_stopped` | — | Script killed |
| `ssh_connected` | `{host}` | Shell opened |
| `ssh_output` | `{data}` | Terminal data from shell |
| `ssh_error` | `{error}` | Shell error |
| `ssh_disconnected` | — | Shell closed |

---

## Background Services

Three daemon threads run from startup:

| Thread | Interval | Workers | Purpose |
|--------|----------|---------|---------|
| Device detection | 5 s | 12 | Scans all devices; pushes `device_status_update` on change |
| Peer discovery | 30 s | 64 | Sweeps `10.87.86.0/23` on port 5002; pushes `peer_instances_update` |
| Network appliances | 10 s | — | Probes `NETWORK_DEVICES` by subnet + TCP; pushes `netdev_update` |

**Detection strategy per connection type:**

| Type | Method | Timeout |
|------|--------|---------|
| SSH | TCP connect to `host:22` | 0.5 s |
| Serial | `pyserial.list_ports` match by VID:PID | — |
| USB (no serial) | `pyusb.find()` → lsusb / system_profiler fallback | — |
| WiFi web | TCP connect to `wifi.ip:80` | 0.3 s |

---

## Project Structure

```
quiver/
├── app.py              Flask + SocketIO server (2,430 lines)
│                       ├── TOOLS registry (45 devices)
│                       ├── TOOL_GROUPS (8 categories)
│                       ├── Background threads (detection, peers, appliances)
│                       ├── Shell managers (SSH, serial, PTY, WebSocket)
│                       ├── Reverse proxy with URL/JS rewriting
│                       ├── Payload library management
│                       └── REST API + SocketIO events
├── common.py           Shared device script library (1,751 lines)
│                       ├── Web mode protocol (LOG: / PROMPT:)
│                       ├── Logging functions (ok, warn, err, info, heading)
│                       ├── Interactive prompts (text, password, confirm, menu)
│                       ├── Platform helpers (OS/distro detection, sudo wrappers)
│                       └── Hardware helpers (serial port, USB, SSH utilities)
├── <device>.py         Per-device management script (~45 files)
├── requirements.txt    Python dependencies
├── firmware/
│   ├── download.py     Firmware auto-downloader (release assets + git repos)
│   ├── cc1352p4/       Sniffle checkout + crackle (BLE 5 / Sub-1GHz)
│   ├── cc26x2r1/       Sniffle checkout + crackle (Bluetooth 5 sniffer)
│   ├── nrf52833_dk/    nRF Sniffer for BLE hex (nrfutil) + crackle
│   ├── bluefruit_le_sniffer/  Adafruit_BLESniffer_Python + crackle
│   └── nucleo_f429zi/  STM32CubeF4 (HAL/CMSIS build dep for Click firmware)
├── payloads/
│   ├── payloads.json   Payload index
│   ├── bash_bunny/     Bash Bunny payloads + stagers
│   ├── flipper_zero/   Flipper Zero BadUSB payloads
│   ├── proxmark3/      Proxmark3 RFID scripts
│   ├── hackrf_one/     HackRF shell scripts
│   ├── zigbee/         Zigbee assessment scripts
│   ├── lora/           LoRa / LoRaWAN scripts
│   ├── cynthion/       Facedancer HID / storage payloads
│   ├── other/          Platform audit scripts (Win / Linux / macOS)
│   └── …               (one directory per device)
├── templates/
│   ├── base.html       Layout shell with theme system
│   ├── index.html      Device grid home page
│   └── tool.html       Per-device page (scripts, shell, payloads)
└── static/
    └── css/style.css   Gauntlet theme system
```

---

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `GITHUB_TOKEN` | Authenticated GitHub API requests for firmware checks |
| `QUIVER_WEB_MODE` | Set to `1` by `app.py` when launching device scripts (do not set manually) |
| `QUIVER_SELECTED_PAYLOAD` | Path to selected payload, passed to device script on launch |

---

## Contributors

Quiver depends on the following external tools and libraries. Credits and links are provided for each.

### Python Libraries

| Library | Creator | Handle | Link |
|---------|---------|--------|------|
| Flask | Armin Ronacher | @mitsuhiko | https://github.com/pallets/flask |
| Flask-SocketIO | Miguel Grinberg | @miguelgrinberg | https://github.com/miguelgrinberg/Flask-SocketIO |
| paramiko | Jeff Forcier | @bitprophet | https://github.com/paramiko/paramiko |
| pyserial | pyserial maintainers | — | https://github.com/pyserial/pyserial |
| requests | Kenneth Reitz / PSF | @kennethreitz | https://github.com/psf/requests |
| pyusb | pyusb contributors | — | https://github.com/pyusb/pyusb |
| esptool | Fredrik Ahlberg + Espressif | @themadinventor | https://github.com/espressif/esptool |
| mpremote | MicroPython contributors | — | https://github.com/micropython/micropython |
| pyflipper | Flipper community | — | https://github.com/wh00hw/pyflipper |
| flipperzero-protobuf | Flipper Devices Inc | — | https://github.com/flipperdevices/flipperzero-protobuf |
| pyhackrf | HackRF Python contributors | — | https://github.com/dressel/pyhackrf |
| bellows | zigpy contributors | — | https://github.com/zigpy/bellows |
| zigpy | zigpy contributors | — | https://github.com/zigpy/zigpy |
| zigpy-znp | zigpy-znp contributors | — | https://github.com/zigpy/zigpy-znp |
| cynthion | Great Scott Gadgets | @greatscottgadgets | https://github.com/greatscottgadgets/cynthion |
| apollo-fpga | Great Scott Gadgets | @greatscottgadgets | https://github.com/greatscottgadgets/apollo |
| facedancer | Kate Temkin | @ktemkin | https://github.com/greatscottgadgets/facedancer |
| greatfet | Great Scott Gadgets + Kate Temkin | @ktemkin | https://github.com/greatscottgadgets/greatfet |
| pyocd | pyocd contributors | — | https://github.com/pyocd/pyOCD |
| pylink-square | Square engineering | — | https://github.com/square/pylink |
| scapy | Philippe Biondi | @p-biondi | https://github.com/secdev/scapy |
| websocket-client | websocket-client contributors | — | https://github.com/websocket-client/websocket-client |

### Hardware Firmware and System Tools

| Tool / Hardware | Creator | Handle | Link |
|-----------------|---------|--------|------|
| Flipper Zero firmware | Flipper Devices Inc | — | https://github.com/flipperdevices/flipperzero-firmware |
| Proxmark3 Iceman firmware | iceman1001 | @iceman1001 | https://github.com/RfidResearchGroup/proxmark3 |
| HackRF | Michael Ossmann | @mossmann | https://github.com/greatscottgadgets/hackrf |
| Ubertooth One | Michael Ossmann | @mossmann | https://github.com/greatscottgadgets/ubertooth |
| GreatFET | Michael Ossmann + Kate Temkin | @ktemkin | https://github.com/greatscottgadgets/greatfet |
| Cynthion / Facedancer | Kate Temkin + Great Scott Gadgets | @ktemkin | https://github.com/greatscottgadgets/cynthion |
| ChameleonUltra | RRG / Iceman | @iceman1001 | https://github.com/RfidResearchGroup/ChameleonUltra |
| Bash Bunny / Hak5 gear | Hak5 | — | https://github.com/hak5 |
| Yardstick One / rfcat | Michael Ossmann | @mossmann | https://github.com/greatscottgadgets/yardstick |
| WiFi Pineapple | Hak5 | — | https://shop.hak5.org |
