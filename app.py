#!/usr/bin/env python3
"""
Quiver — Flask Web App
Mirrors the Gauntlet UI theme system; runs device management scripts
interactively via WebSocket and provides a native shell for each device.

Shell types supported:
  ssh       — paramiko SSH (network-attached devices)
  serial    — pyserial raw terminal (REPL / VCP console)
  process   — PTY subprocess (pm3, rfcat -r, gf shell, JLinkExe, etc.)
  websocket — WebSocket relay (WiFi Duck ws://192.168.4.1/ws)
  none      — no interactive shell (libusb-only devices with no CLI)
"""

VERSION = "1.10.0"

import concurrent.futures
import ipaddress
import json
import os
import queue
import re
import requests
import socket as _socket
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

# ── Optional imports ────────────────────────────────────────────────────────────

try:
    import pty as _pty
    import fcntl as _fcntl
    import termios as _termios
    import struct as _struct
    import select as _select
    HAS_PTY = True
except ImportError:
    HAS_PTY = False

try:
    # paramiko — SSH client library; Jeff Forcier @bitprophet — https://github.com/paramiko/paramiko
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    paramiko = None  # type: ignore
    HAS_PARAMIKO = False

try:
    # pyserial — serial port library; pyserial maintainers — https://github.com/pyserial/pyserial
    import serial as _serial
    import serial.tools.list_ports as _list_ports
    HAS_SERIAL = True
except ImportError:
    HAS_SERIAL = False

try:
    # websocket-client — WebSocket relay for WiFi Duck — https://github.com/websocket-client/websocket-client
    import websocket as _websocket_lib
    HAS_WEBSOCKET = True
except ImportError:
    HAS_WEBSOCKET = False

# Flask — Armin Ronacher @mitsuhiko — https://github.com/pallets/flask
from flask import Flask, render_template, request, redirect, url_for, jsonify, Response, stream_with_context, session
# Flask-SocketIO — Miguel Grinberg @miguelgrinberg — https://github.com/miguelgrinberg/Flask-SocketIO
from flask_socketio import SocketIO, emit, join_room
import _auth

# ── App setup ──────────────────────────────────────────────────────────────────

BASE_DIR     = Path(__file__).parent
PAYLOAD_DIR  = BASE_DIR / "payloads"
PAYLOAD_JSON = PAYLOAD_DIR / "payloads.json"

app = Flask(__name__)
app.config["SECRET_KEY"]               = _auth.load_secret_key()
app.config["SESSION_COOKIE_SECURE"]    = False  # self-signed cert; HTTPS enforced server-side
app.config["SESSION_COOKIE_HTTPONLY"]  = True
app.config["SESSION_COOKIE_SAMESITE"]  = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)
_auth.init_auth()
socketio = SocketIO(app, async_mode="threading", cors_allowed_origins="*")


@app.after_request
def _security_headers(response):
    if "text/html" in response.content_type:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return _auth.apply_security_headers(response)


@app.before_request
def _auth_gate():
    return _auth.auth_gate()

# ── Tool registry ──────────────────────────────────────────────────────────────
#
# Each entry may have:
#   name    — display name
#   script  — Python script filename (run as subprocess)
#   icon    — emoji icon
#   ssh     — dict with SSH credentials, or None
#   shell   — dict describing the interactive shell, or None
#             shell types: "ssh" | "serial" | "process" | "websocket" | "none"
#   usb     — USB VID/PID info (used by device scripts and shell auto-detect)
#
# The "ssh" key is for network-attached devices.
# New devices use "shell" with the appropriate type.
# ──────────────────────────────────────────────────────────────────────────────

TOOLS = {
    # ── Network-attached devices ───────────────────────────────────────────────
    "bash_bunny": {
        "name":   "Bash Bunny",
        "script": "bash_bunny.py",
        "icon":   "🐇",
        "ssh":    {"host": "172.16.64.1",  "user": "root", "password": "hak5bunny",     "port": 22},
        "shell":  None,
    },
    "usb_rubber_ducky": {
        "name":   "USB Rubber Ducky",
        "script": "usb_rubber_ducky.py",
        "icon":   "🦆",
        "ssh":    None,
        "shell":  None,
    },
    "wifi_pineapple": {
        "name":    "WiFi Pineapple MK7",
        "script":  "wifi_pineapple.py",
        "icon":    "🍍",
        "ssh":     {"host": "172.16.42.1",  "user": "root", "password": "hak5pineapple", "port": 22},
        "shell":   None,
        "web_url": "http://172.16.42.1:1471",
    },
    "shark_jack": {
        "name":   "Shark Jack",
        "script": "shark_jack.py",
        "icon":   "🦈",
        "ssh":    {"host": "172.16.24.1",  "user": "root", "password": "hak5shark",     "port": 22},
        "shell":  None,
    },
    "packet_squirrel": {
        "name":   "Packet Squirrel",
        "script": "packet_squirrel.py",
        "icon":   "🐿",
        "ssh":    {"host": "172.16.32.1",  "user": "root", "password": "hak5squirrel",  "port": 22},
        "shell":  None,
    },
    "lan_turtle": {
        "name":   "LAN Turtle",
        "script": "lan_turtle.py",
        "icon":   "🐢",
        "ssh":    {"host": "172.16.84.1",  "user": "root", "password": "sh3llz",        "port": 22},
        "shell":  None,
    },
    "key_croc": {
        "name":   "Key Croc",
        "script": "key_croc.py",
        "icon":   "🐊",
        "ssh":    {"host": None, "user": "root", "password": "hak5croc", "port": 22,
                   "note": "WiFi DHCP — enter device IP manually"},
        "shell":  None,
    },
    "signal_owl": {
        "name":   "Signal Owl",
        "script": "signal_owl.py",
        "icon":   "🦉",
        "ssh":    {"host": "172.16.56.1",  "user": "root", "password": "hak5owl",       "port": 22},
        "shell":  None,
    },
    "screen_crab": {
        "name":   "Screen Crab",
        "script": "screen_crab.py",
        "icon":   "🦀",
        "ssh":    None,
        "shell":  None,
    },
    "plunder_bug": {
        "name":   "Plunder Bug",
        "script": "plunder_bug.py",
        "icon":   "🐛",
        "ssh":    None,
        "shell":  None,
    },

    # ── Bus Pirate 5 ───────────────────────────────────────────────────────────
    "bus_pirate_5": {
        "name":   "Bus Pirate 5",
        "script": "bus_pirate_5.py",
        "icon":   "🔌",
        "ssh":    None,
        "shell":  {
            "type":     "serial",
            "baud":     115200,
            "vid_pids": [(0x1209, 0x7331)],
            "label":    "Bus Pirate 5 REPL",
        },
        "usb":    {
            "vid_pids":    [(0x1209, 0x7331)],
            "boot_vid_pid": (0x2E8A, 0x0003),
        },
    },

    # ── Cynthion ──────────────────────────────────────────────────────────────
    "cynthion": {
        "name":   "Cynthion",
        "script": "cynthion.py",
        "icon":   "🔍",
        "ssh":    None,
        "shell":  {"type": "none"},
        "usb":    {"vid_pids": [(0x1D50, 0x615C)]},
    },

    # ── Chameleon Ultra ───────────────────────────────────────────────────────
    "chameleon_ultra": {
        "name":   "Chameleon Ultra",
        "script": "chameleon_ultra.py",
        "icon":   "🎭",
        "ssh":    None,
        "shell":  {
            "type":  "process",
            "cmd":   ["python3",
                      "ChameleonUltra/software/script/chameleon_cli_main.py"],
            "label": "Chameleon Ultra CLI",
        },
        "usb":    {
            "vid_pids":    [(0x6868, None)],
            "dfu_vid_pid": (0x1915, 0x521F),
        },
    },

    # ── Flipper Zero ──────────────────────────────────────────────────────────
    "flipper_zero": {
        "name":   "Flipper Zero",
        "script": "flipper_zero.py",
        "icon":   "🐬",
        "ssh":    None,
        "shell":  {
            "type":     "serial",
            "baud":     115200,
            "vid_pids": [(0x0483, 0x5740)],
            "label":    "Flipper Zero CLI",
        },
        "usb":    {
            "vid_pids":    [(0x0483, 0x5740)],
            "dfu_vid_pid": (0x0483, 0xDF11),
        },
    },

    # ── HackRF One ────────────────────────────────────────────────────────────
    "hackrf_one": {
        "name":   "HackRF One",
        "script": "hackrf_one.py",
        "icon":   "📡",
        "ssh":    None,
        "shell":  {"type": "none"},
        "github_repo": "greatscottgadgets/hackrf",
        "fw_probe": True,   # passive: hackrf_info firmware version
        "usb":    {
            "vid_pids":    [(0x1D50, 0x6089)],
            "dfu_vid_pid": (0x1FC9, 0x000C),
        },
    },

    # ── LilyGo T-Zigbee v1.2 ─────────────────────────────────────────────────
    "lilygo_tzigbee": {
        "name":   "LilyGo T-Zigbee v1.2",
        "script": "lilygo_tzigbee.py",
        "icon":   "🐝",
        "ssh":    None,
        "shell":  {
            "type":     "serial",
            "baud":     115200,
            "vid_pids": [(0x303A, 0x1001),
                         (0x1A86, 0x7523),
                         (0x10C4, 0xEA60)],
            "label":    "T-Zigbee UART Console",
        },
        "usb":    {
            "vid_pids": [(0x303A, 0x1001),
                         (0x1A86, 0x7523),
                         (0x10C4, 0xEA60)],
        },
    },

    # ── LilyGo LoRa32 v1.6.1 ─────────────────────────────────────────────────
    "lilygo_lora32": {
        "name":   "LilyGo LoRa32 v1.6.1",
        "script": "lilygo_lora32.py",
        "icon":   "📶",
        "ssh":    None,
        "shell":  {
            "type":     "serial",
            "baud":     115200,
            "vid_pids": [(0x10C4, 0xEA60),
                         (0x1A86, 0x55D4),
                         (0x1A86, 0x7522),
                         (0x1A86, 0x7523)],
            "label":    "LoRa32 MicroPython REPL",
        },
        "usb":    {
            "vid_pids": [(0x10C4, 0xEA60),
                         (0x1A86, 0x55D4),
                         (0x1A86, 0x7522),
                         (0x1A86, 0x7523)],
        },
        "esp_chip":  "esp32",
        "lora_chip": "SX1276",
    },

    # ── Heltec WiFi LoRa32 v3 ─────────────────────────────────────────────────
    "heltec_lora32_v3": {
        "name":   "Heltec WiFi LoRa32 v3",
        "script": "heltec_lora32_v3.py",
        "icon":   "📡",
        "ssh":    None,
        "shell":  {
            "type":     "serial",
            "baud":     115200,
            "vid_pids": [(0x10C4, 0xEA60),
                         (0x303A, 0x1001)],
            "label":    "Heltec MicroPython REPL",
        },
        "usb":    {
            "vid_pids": [(0x10C4, 0xEA60),
                         (0x303A, 0x1001)],
        },
        "esp_chip":  "esp32s3",
        "lora_chip": "SX1262",
        "flash_size": "8MB",
    },

    # ── Nucleo-F429ZI ─────────────────────────────────────────────────────────
    "nucleo_f429zi": {
        "name":   "Nucleo-F429ZI",
        "script": "nucleo_f429zi.py",
        "icon":   "🔧",
        "ssh":    None,
        "shell":  {
            "type":     "serial",
            "baud":     115200,
            "vid_pids": [(0x0483, 0x374B),
                         (0x0483, 0x5740)],
            "label":    "Nucleo VCP Console (USART3)",
        },
        "usb":    {
            "vid_pids":    [(0x0483, 0x374B)],
            "user_cdc_pid": 0x5740,
            "dfu_pid":      0xDF11,
        },
        "pyocd_target": "stm32f429zi",
    },

    # ── Proxmark3 Iceman ──────────────────────────────────────────────────────
    "proxmark3": {
        "name":   "Proxmark3 Iceman",
        "script": "proxmark3.py",
        "icon":   "📟",
        "ssh":    None,
        "shell":  {
            "type":     "process",
            "cmd":      ["pm3", "{port}"],
            "vid_pids": [(0x9AC4, 0x4B8F),
                         (0x2D2D, 0x504D),
                         (0x502D, 0x502D)],
            "label":    "PM3 Interactive Client",
        },
        "usb":    {
            "vid_pids": [(0x9AC4, 0x4B8F),
                         (0x2D2D, 0x504D),
                         (0x502D, 0x502D)],
        },
    },

    # ── Sonoff ZBDongle-E ─────────────────────────────────────────────────────
    "sonoff_zbdongle_e": {
        "name":   "Sonoff ZBDongle-E",
        "script": "sonoff_zbdongle_e.py",
        "icon":   "📡",
        "ssh":    None,
        "shell":  {"type": "none"},
        "usb":    {
            "vid_pids": [(0x1A86, 0x55D4),
                         (0x10C4, 0xEA60)],
        },
    },

    # ── ST-Link V2 ────────────────────────────────────────────────────────────
    "stlink_v2": {
        "name":   "ST-Link V2",
        "script": "stlink_v2.py",
        "icon":   "🔗",
        "ssh":    None,
        "shell":  {"type": "none"},
        "usb":    {
            "vid_pids": [(0x0483, 0x3748),
                         (0x0483, 0x374B),
                         (0x0483, 0x374E),
                         (0x0483, 0x374F)],
        },
    },

    # ── Ubertooth One ─────────────────────────────────────────────────────────
    "ubertooth_one": {
        "name":   "Ubertooth One",
        "script": "ubertooth_one.py",
        "icon":   "🔵",
        "ssh":    None,
        "shell":  {"type": "none"},
        "github_repo": "greatscottgadgets/ubertooth",
        "fw_probe": True,   # passive: ubertooth-util -v firmware version
        "usb":    {
            "vid_pids":    [(0x1D50, 0x6002)],
            "dfu_vid_pid": (0x1D50, 0x6003),
        },
    },

    # ── WiFi Duck ─────────────────────────────────────────────────────────────
    "wifi_duck": {
        "name":    "WiFi Duck",
        "script":  "wifi_duck.py",
        "icon":    "🦆",
        "ssh":     None,
        "shell":   {
            "type":   "websocket",
            "ws_url": "ws://192.168.4.1/ws",
            "label":  "WiFi Duck CLI (WebSocket)",
        },
        "web_url": "http://192.168.4.1",
        "usb":     {
            "vid_pids": [(0x2341, 0x8037),
                         (0x2341, 0x0036),
                         (0x1B4F, 0x9206),
                         (0x303A, None)],
        },
        "wifi":   {
            "ssid":   "wifiduck",
            "password": "wifiduck",
            "ip":     "192.168.4.1",
        },
    },

    # ── Yardstick One ─────────────────────────────────────────────────────────
    "yardstick_one": {
        "name":   "Yardstick One",
        "script": "yardstick_one.py",
        "icon":   "📻",
        "ssh":    None,
        "shell":  {
            "type":  "process",
            "cmd":   ["rfcat", "-r"],
            "label": "RfCat Interactive REPL",
        },
        "usb":    {
            "vid_pids":    [(0x1D50, 0x605B)],
            "boot_vid_pid": (0x1D50, 0x6002),
        },
    },

    # ── GreatFET One ──────────────────────────────────────────────────────────
    "greatfet_one": {
        "name":   "GreatFET One",
        "script": "greatfet_one.py",
        "icon":   "⚡",
        "ssh":    None,
        "shell":  {
            "type":  "process",
            "cmd":   ["gf", "shell"],
            "label": "GreatFET IPython Shell",
        },
        "usb":    {
            "vid_pids":    [(0x1D50, 0x60E6)],
            "dfu_vid_pid": (0x1FC9, 0x000C),
        },
    },

    # ── J-Link EDU Mini ───────────────────────────────────────────────────────
    "jlink_edu_mini": {
        "name":   "J-Link EDU Mini",
        "script": "jlink_edu_mini.py",
        "icon":   "🔬",
        "ssh":    None,
        "shell":  {
            "type":  "process",
            "cmd":   ["JLinkExe"],
            "label": "JLinkExe Commander",
        },
        "usb":    {
            "vid_pids": [(0x1366, 0x0101),
                         (0x1366, 0x0105),
                         (0x1366, 0x1015)],
        },
    },

    # ── Manual (USB Drive) ────────────────────────────────────────────────────
    # No hardware connection — payloads are delivered manually via USB drive.
    # Payload list is sourced from the "other" category in payloads.json.
    "manual_usb_drive": {
        "name":   "Manual (USB Drive)",
        "script": None,
        "icon":   "💾",
        "ssh":    None,
        "shell":  None,
    },

    # ── ESP32-D ───────────────────────────────────────────────────────────────
    "esp32d": {
        "name":   "ESP32-D",
        "script": "esp32d.py",
        "icon":   "🔷",
        "ssh":    None,
        "shell":  {
            "type":     "serial",
            "baud":     115200,
            "vid_pids": [
                (0x10C4, 0xEA60),   # CP2104 / CP2102
                (0x1A86, 0x7523),   # CH340G
                (0x1A86, 0x7522),   # CH340C
                (0x1A86, 0x55D4),   # CH9102
                (0x0403, 0x6001),   # FT232RL
            ],
            "label": "ESP32-D Serial Console",
        },
        "usb": {
            "vid_pids": [
                (0x10C4, 0xEA60),
                (0x1A86, 0x7523),
                (0x1A86, 0x7522),
                (0x1A86, 0x55D4),
                (0x0403, 0x6001),
            ],
        },
        "esp_chip": "esp32",
    },

    # ── Raspberry Pi Pico (RP2040) ────────────────────────────────────────────
    "rpi_pico": {
        "name":   "Raspberry Pi Pico",
        "script": "rpi_pico.py",
        "icon":   "🍓",
        "ssh":    None,
        "shell":  {
            "type":     "serial",
            "baud":     115200,
            "vid_pids": [
                (0x2E8A, 0x0005),   # MicroPython CDC
                (0x2E8A, 0x000A),   # Pico SDK CDC
            ],
            "label": "Pico MicroPython REPL",
        },
        "usb": {
            "vid_pids":    [(0x2E8A, 0x0005), (0x2E8A, 0x000A)],
            "uf2_vid_pid": (0x2E8A, 0x0003),
        },
    },

    # ── Raspberry Pi Pico W ───────────────────────────────────────────────────
    "rpi_pico_w": {
        "name":   "Raspberry Pi Pico W",
        "script": "rpi_pico_w.py",
        "icon":   "🍓",
        "ssh":    None,
        "shell":  {
            "type":     "serial",
            "baud":     115200,
            "vid_pids": [
                (0x2E8A, 0x0005),   # MicroPython CDC
                (0x2E8A, 0x000A),   # SDK CDC
            ],
            "label": "Pico W MicroPython REPL",
        },
        "usb": {
            "vid_pids":    [(0x2E8A, 0x0005), (0x2E8A, 0x000A)],
            "uf2_vid_pid": (0x2E8A, 0x0003),
        },
        "wifi_chip": "CYW43439",
    },

    # ── Raspberry Pi Pico 2W (RP2350) ─────────────────────────────────────────
    "rpi_pico_2w": {
        "name":   "Raspberry Pi Pico 2W",
        "script": "rpi_pico_2w.py",
        "icon":   "🍓",
        "ssh":    None,
        "shell":  {
            "type":     "serial",
            "baud":     115200,
            "vid_pids": [
                (0x2E8A, 0x0005),   # MicroPython CDC
                (0x2E8A, 0x000A),   # SDK CDC
            ],
            "label": "Pico 2W MicroPython REPL",
        },
        "usb": {
            "vid_pids":    [(0x2E8A, 0x0005), (0x2E8A, 0x000A)],
            "uf2_vid_pid": (0x2E8A, 0x000F),
        },
        "wifi_chip": "CYW43439",
    },

    # ── Particle Photon 2 ─────────────────────────────────────────────────────
    "photon_2": {
        "name":    "Photon 2",
        "script":  "photon_2.py",
        "icon":    "⚛",
        "ssh":     None,
        "shell":   {
            "type":     "serial",
            "baud":     115200,
            "vid_pids": [(0x2B04, 0xC305), (0x2B04, 0xD305)],
            "label":    "Photon 2 Serial Monitor",
        },
        "usb": {
            "vid_pids":    [(0x2B04, 0xC305)],
            "dfu_vid_pid": (0x2B04, 0xD305),
        },
        "web_url": "https://console.particle.io",
    },

    # ── Nordic nRF52840 ───────────────────────────────────────────────────────
    "nordic_nrf52840": {
        "name":   "Nordic nRF52840",
        "script": "nordic_nrf52840.py",
        "icon":   "🔷",
        "ssh":    None,
        "shell":  {
            "type":     "serial",
            "baud":     115200,
            "vid_pids": [
                (0x1915, 0x521F),   # nRF52840 Dongle — Open Bootloader CDC
                (0x1915, 0x520F),   # nRF52840 Dongle — application CDC
            ],
            "label": "nRF52840 CDC Console",
        },
        "usb": {
            "vid_pids": [
                (0x1915, 0x521F),
                (0x1915, 0x520F),
                (0x1366, 0x1015),   # J-Link (nRF52840-DK)
            ],
        },
    },

    # ── Bus Pirate 3.6 ────────────────────────────────────────────────────────
    "bus_pirate_36": {
        "name":   "Bus Pirate 3.6",
        "script": "bus_pirate_36.py",
        "icon":   "🔌",
        "ssh":    None,
        "shell":  {
            "type":     "serial",
            "baud":     115200,
            "vid_pids": [
                (0x04D8, 0xFB00),   # Microchip USB CDC (Bus Pirate 3.x)
                (0x0403, 0x6001),   # FTDI FT232RL (some clones)
            ],
            "label": "Bus Pirate 3.6 REPL",
        },
        "usb": {
            "vid_pids":     [(0x04D8, 0xFB00), (0x0403, 0x6001)],
            "boot_vid_pid": (0x04D8, 0xFB01),
        },
    },

    # ── LilyGo T-Deck ─────────────────────────────────────────────────────────
    "lilygo_tdeck": {
        "name":   "LilyGo T-Deck",
        "script": "lilygo_tdeck.py",
        "icon":   "⌨",
        "ssh":    None,
        "shell":  {
            "type":     "serial",
            "baud":     115200,
            "vid_pids": [(0x303A, 0x1001)],
            "label":    "T-Deck ESP32-S3 Console",
        },
        "usb": {
            "vid_pids": [(0x303A, 0x1001)],
        },
        "esp_chip": "esp32s3",
    },

    # ── DWM3001CDK UWB Development Kit ────────────────────────────────────────
    "dwm3001cdk": {
        "name":   "DWM3001CDK",
        "script": "dwm3001cdk.py",
        "icon":   "📡",
        "ssh":    None,
        "shell":  {
            "type":     "serial",
            "baud":     115200,
            "vid_pids": [
                (0x1915, 0x521F),   # Nordic nRF52833 CDC UART
                (0x1366, 0x1015),   # Segger J-Link (on-board debugger)
            ],
            "label": "DWM3001CDK CDC Console",
        },
        "usb": {
            "vid_pids": [
                (0x1915, 0x521F),
                (0x1366, 0x1015),
            ],
        },
    },

    # ── BadUSB (ATmega32U4-based HID injection) ────────────────────────────────
    "badusb": {
        "name":   "BadUSB",
        "script": "badusb.py",
        "icon":   "💀",
        "ssh":    None,
        "shell":  {"type": "none"},
        "usb": {
            "vid_pids": [
                (0x16C0, 0x05DC),   # DigiSpark (Digistump)
                (0x1B4F, 0x9205),   # SparkFun Pro Micro 5V
                (0x1B4F, 0x9206),   # SparkFun Pro Micro 3.3V
                (0x2341, 0x8037),   # Arduino Micro
                (0x03EB, 0x2FF4),   # Atmel DFU ATmega32U4 bootloader
            ],
        },
    },

    # ── Evil Crow RF ──────────────────────────────────────────────────────────
    "evil_crow": {
        "name":    "Evil Crow RF",
        "script":  "evil_crow.py",
        "icon":    "🐦",
        "ssh":     None,
        "shell":   {"type": "none"},
        "usb": {
            "vid_pids": [
                (0x10C4, 0xEA60),   # CP2102/CP2104 USB-serial
                (0x303A, 0x0002),   # ESP32-S2 native USB
            ],
        },
        "web_url": "http://192.168.4.1",
        "wifi": {
            "ssid":     "EvilCrowRF",
            "password": "EvilCrowRF",
            "ip":       "192.168.4.1",
        },
    },

    # ── BugBlat MiniSniffer 2 ─────────────────────────────────────────────────
    "bugblat_minisniffer2": {
        "name":   "BugBlat MiniSniffer 2",
        "script": "bugblat_minisniffer2.py",
        "icon":   "🔎",
        "ssh":    None,
        "shell":  {"type": "none"},
        "usb": {
            "vid_pids": [
                (0x16D0, 0x05B4),   # BugBlat MiniSniffer (verify with vendor)
                (0x16D0, 0x0753),   # BugBlat alternative PID
            ],
        },
    },

    # ── CC-2531 Zigbee USB Dongle ─────────────────────────────────────────────
    "cc2531": {
        "name":   "CC-2531",
        "script": "cc2531.py",
        "icon":   "🐝",
        "ssh":    None,
        "shell":  {
            "type":     "serial",
            "baud":     115200,
            "vid_pids": [(0x0451, 0x16AE)],
            "label":    "CC2531 CDC UART",
        },
        "usb": {
            "vid_pids": [(0x0451, 0x16AE)],
        },
    },

    # ── O.MG Cable / Elite ────────────────────────────────────────────────────
    "omg_cable": {
        "name":    "O.MG Cable / Elite",
        "script":  "omg_cable.py",
        "icon":    "🔌",
        "ssh":     None,
        "web_url": "http://192.168.4.1",
        "shell":   {"type": "none"},
        "wifi": {
            "ap_ssid_prefix": "O.MG",
            "default_host":   "192.168.4.1",
            "port":           80,
        },
        "category": "hid",
    },

    # ── Wi-Fi Coconut ─────────────────────────────────────────────────────────
    "wifi_coconut": {
        "name":   "Wi-Fi Coconut",
        "script": "wifi_coconut.py",
        "icon":   "🥥",
        "ssh":    None,
        "shell":  {"type": "none"},
        "usb": {
            # 14× Atheros AR9271 (0CF3:9271) on an internal hub
            "vid_pids": [(0x0CF3, 0x9271)],
        },
        "category": "rf",
    },

    # ── USB Rubber Ducky 3 ────────────────────────────────────────────────────
    "rubber_ducky_3": {
        "name":   "Rubber Ducky 3",
        "script": "rubber_ducky_3.py",
        "icon":   "🦆",
        "ssh":    None,
        "shell":  {"type": "none"},
        "usb": {
            # Hak5 storage mode (RP2040), deployed HID mode (Apple keyboard spoof)
            "vid_pids": [(0x1B4F, 0x9204), (0x05AC, 0x8102)],
        },
        "category": "hid",
    },

    # ── TI CC26X2R1 LaunchPad (Sniffle BLE 5 sniffer) ─────────────────────────
    "cc26x2r1": {
        "name":   "TI CC26X2R1 LaunchPad",
        "script": "cc26x2r1.py",
        "icon":   "📶",
        "ssh":    None,
        "shell":  {"type": "none"},
        "github_repo": "nccgroup/Sniffle",
        "fw_probe": True,   # passive: Sniffle probe_fw_version() over serial
        "usb": {
            "vid_pids": [(0x0451, 0xBEF3)],   # XDS110 debug probe
        },
    },

    # ── TI CC1352P-4 LaunchPad (Sniffle BLE + Sub-GHz) ────────────────────────
    "cc1352p4": {
        "name":   "TI CC1352P-4 LaunchPad",
        "script": "cc1352p4.py",
        "icon":   "📶",
        "ssh":    None,
        "shell":  {"type": "none"},
        "github_repo": "nccgroup/Sniffle",
        "fw_probe": True,   # passive: Sniffle probe_fw_version() over serial
        "usb": {
            "vid_pids": [(0x0451, 0xBEF3)],   # XDS110 debug probe
        },
    },

    # ── Nordic nRF52833-DK (nRF Sniffer BLE) ──────────────────────────────────
    "nrf52833_dk": {
        "name":   "Nordic nRF52833-DK",
        "script": "nrf52833_dk.py",
        "icon":   "🔷",
        "ssh":    None,
        "shell":  {"type": "none"},
        "usb": {
            "vid_pids": [(0x1366, 0x1015), (0x1366, 0x1051)],   # SEGGER J-Link OB
        },
    },

    # ── Adafruit Bluefruit LE Sniffer (nRF51822, BLE 4.0) ─────────────────────
    "bluefruit_le_sniffer": {
        "name":   "Bluefruit LE Sniffer",
        "script": "bluefruit_le_sniffer.py",
        "icon":   "🔵",
        "ssh":    None,
        "shell":  {"type": "none"},
        "usb": {
            "vid_pids": [(0x10C4, 0xEA60)],   # CP2104 USB-UART (shared VID:PID)
        },
    },
}

# ── Tool category groups ───────────────────────────────────────────────────────
TOOL_GROUPS = {
    "rf": {
        "label": "RF & SDR",
        "icon":  "📡",
        "tools": ["hackrf_one", "yardstick_one", "ubertooth_one", "wifi_coconut",
                  "wifi_pineapple", "signal_owl", "bugblat_minisniffer2"],
    },
    "hid": {
        "label": "HID Injection",
        "icon":  "⌨",
        "tools": ["bash_bunny", "usb_rubber_ducky", "rubber_ducky_3", "key_croc",
                  "omg_cable", "badusb", "wifi_duck", "evil_crow"],
    },
    "zigbee_ble": {
        "label": "Zigbee / BLE",
        "icon":  "📶",
        "tools": ["cc2531", "sonoff_zbdongle_e", "lilygo_tzigbee", "nordic_nrf52840",
                  "nrf52833_dk", "cc26x2r1", "cc1352p4", "bluefruit_le_sniffer",
                  "chameleon_ultra"],
    },
    "rfid_nfc": {
        "label": "RFID / NFC",
        "icon":  "🏷",
        "tools": ["proxmark3", "flipper_zero", "chameleon_ultra"],
    },
    "microcontrollers": {
        "label": "Microcontrollers",
        "icon":  "🎛",
        "tools": ["esp32d", "rpi_pico", "rpi_pico_w", "rpi_pico_2w", "lilygo_tdeck",
                  "lilygo_lora32", "heltec_lora32_v3", "photon_2", "dwm3001cdk",
                  "bus_pirate_36"],
    },
    "network": {
        "label": "Network",
        "icon":  "🌐",
        "tools": ["lan_turtle", "shark_jack", "packet_squirrel", "plunder_bug"],
    },
    "debug": {
        "label": "Debug Probes",
        "icon":  "🔬",
        "tools": ["stlink_v2", "jlink_edu_mini", "nucleo_f429zi", "greatfet_one",
                  "cynthion", "bus_pirate_36"],
    },
    "hak5": {
        "label": "Hak5 Gear",
        "icon":  "🕶",
        "tools": ["wifi_pineapple", "bash_bunny", "key_croc", "lan_turtle",
                  "shark_jack", "packet_squirrel", "screen_crab", "signal_owl",
                  "plunder_bug", "rubber_ducky_3", "omg_cable", "wifi_coconut"],
    },
}

# ── Payload helpers ────────────────────────────────────────────────────────────

def _load_payloads() -> dict:
    try:
        data = json.loads(PAYLOAD_JSON.read_text())
    except Exception:
        data = {tid: [] for tid in TOOLS}
    # Expose "other" payloads under the manual_usb_drive tool key
    data.setdefault("manual_usb_drive", data.get("other", []))
    return data


def _save_payloads(data: dict):
    PAYLOAD_JSON.write_text(json.dumps(data, indent=2))


# ── Shell capability helpers ───────────────────────────────────────────────────

def _tool_has_shell(tool: dict) -> bool:
    """Return True if this tool has any interactive shell (SSH, serial, process, WS)."""
    if tool.get("ssh") is not None:
        return True
    shell = tool.get("shell")
    if shell and shell.get("type") not in ("none", None):
        return True
    return False


def _tool_shell_label(tool: dict) -> str:
    """Return display label for the shell tab."""
    if tool.get("ssh") is not None:
        ssh = tool["ssh"]
        host = ssh.get("host") or "DHCP"
        return f"SSH Shell ({ssh.get('user', 'root')}@{host})"
    shell = tool.get("shell") or {}
    stype = shell.get("type", "none")
    label = shell.get("label", "")
    if label:
        return label
    if stype == "serial":
        return "Serial Terminal"
    if stype == "process":
        return "Interactive Shell"
    if stype == "websocket":
        return "WebSocket Console"
    return "Shell"


def _tool_needs_ip(tool: dict) -> bool:
    """Return True if the SSH host IP is unknown and must be entered manually."""
    ssh = tool.get("ssh")
    return ssh is not None and ssh.get("host") is None


# ── Device presence detection ─────────────────────────────────────────────────
#
# A background thread polls all tools every DETECT_INTERVAL seconds.
# Results are stored in _device_status and pushed to connected browsers
# via the "device_status_update" Socket.IO event whenever a device appears
# or disappears.
#
# Detection strategy per tool type:
#   ssh     → TCP connect to host:22 (0.5 s timeout)
#   serial  → scan serial.tools.list_ports by VID:PID
#   usb     → pyusb find() by VID:PID, fallback to lsusb text match
#   wifi    → TCP connect to wifi.ip:80 (0.3 s timeout)
# ──────────────────────────────────────────────────────────────────────────────

DETECT_INTERVAL = 5   # seconds between full scans

_device_status: dict[str, dict] = {}   # tool_id → status dict
_status_lock   = threading.Lock()


def _usb_list_text() -> str:
    """Return raw lsusb output (Linux) or system_profiler USB section (macOS)."""
    try:
        if sys.platform == "darwin":
            r = subprocess.run(
                ["system_profiler", "SPUSBDataType"],
                capture_output=True, text=True, timeout=3,
            )
        else:
            r = subprocess.run(
                ["lsusb"], capture_output=True, text=True, timeout=3,
            )
        return r.stdout.lower() if r.returncode == 0 else ""
    except Exception:
        return ""


def _serial_ports_snapshot() -> list:
    """Return comports() list, or [] if pyserial unavailable."""
    if not HAS_SERIAL:
        return []
    try:
        return list(_list_ports.comports())
    except Exception:
        return []


def _pyusb_present(vid_pids: list) -> bool:
    """Return True if any (vid, pid) is found via pyusb."""
    try:
        import usb.core  # type: ignore
        for vid, pid in vid_pids:
            if usb.core.find(idVendor=vid, idProduct=pid) is not None:
                return True
    except Exception:
        pass
    return False


def _lsusb_present(vid_pids: list, raw: str) -> bool:
    """Return True if any (vid, pid) appears in lsusb/system_profiler output."""
    for vid, pid in vid_pids:
        if pid is None:
            needle = f"{vid:04x}:"
        else:
            needle = f"{vid:04x}:{pid:04x}"
        if needle in raw:
            return True
    return False


# CC1352P-4 and CC26X2R1 both enumerate as XDS110 (0451:BEF3); tell them apart
# by the probe serial pinned in xds110_boards.json (written by the tool modules).
_XDS110_VID_PID = (0x0451, 0xBEF3)
_XDS110_SHARED  = ("cc1352p4", "cc26x2r1")


def _xds110_pins() -> dict:
    try:
        import json
        return json.loads((BASE_DIR / "xds110_boards.json").read_text())
    except Exception:
        return {}


def _detect_xds110_board(tool_id: str, ports: list, st: dict) -> dict:
    """Resolve connected status for an XDS110-shared board using probe serials.
    A probe pinned to a different board does NOT count as this tool being present;
    an unpinned probe counts but is flagged 'unverified' so the UI can warn."""
    xds = [p for p in ports if (p.vid, p.pid) == _XDS110_VID_PID]
    if not xds:
        return st
    pins = _xds110_pins()
    match, identity = None, None
    for p in xds:
        pinned = pins.get(getattr(p, "serial_number", "") or "", "")
        if pinned == tool_id:
            match, identity = p, "confirmed"
            break
        if not pinned and match is None:
            match, identity = p, "unverified"
        # pinned to a different board → ignore for this tool
    if match is not None:
        st.update(connected=True, method="serial", port=match.device,
                  identity=identity,
                  xds110_serial=getattr(match, "serial_number", None))
    return st


def _detect_one(tool_id: str, tool: dict,
                ports: list, usb_raw: str) -> dict:
    """
    Determine connection status for a single tool.
    Returns {"connected": bool, "method": str|None, "port": str|None, "web_url": str|None}.
    """
    st = {"connected": False, "method": None, "port": None,
          "web_url": tool.get("web_url")}

    # ── 1. SSH / TCP reachability ─────────────────────────────────────────
    ssh = tool.get("ssh")
    if ssh and ssh.get("host"):
        try:
            with _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex((ssh["host"], ssh.get("port", 22))) == 0:
                    st.update(connected=True, method="ssh")
                    return st
        except Exception:
            pass

    # ── 2. Serial port by VID:PID ─────────────────────────────────────────
    # XDS110-shared boards must be disambiguated by probe serial FIRST, so a
    # CC26X2R1 does not make the CC1352P-4 look present (and vice versa).
    if tool_id in _XDS110_SHARED:
        return _detect_xds110_board(tool_id, ports, st)

    vid_pids: list = []
    usb_cfg  = tool.get("usb") or {}
    vid_pids.extend(usb_cfg.get("vid_pids", []))
    shell_cfg = tool.get("shell") or {}
    if not vid_pids and shell_cfg.get("type") == "serial":
        vid_pids.extend(shell_cfg.get("vid_pids", []))

    if vid_pids and ports:
        for p in ports:
            for vid, pid in vid_pids:
                if p.vid == vid and (pid is None or p.pid == pid):
                    st.update(connected=True, method="serial", port=p.device)
                    return st

    # ── 3. libusb / lsusb presence ───────────────────────────────────────
    if vid_pids:
        if _pyusb_present(vid_pids) or _lsusb_present(vid_pids, usb_raw):
            st.update(connected=True, method="usb")
            return st

    # ── 4. WiFi-reachable web interface (WiFi Duck, etc.) ─────────────────
    wifi = tool.get("wifi")
    if wifi and wifi.get("ip"):
        try:
            with _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM) as s:
                s.settimeout(0.3)
                if s.connect_ex((wifi["ip"], 80)) == 0:
                    st.update(connected=True, method="wifi")
                    return st
        except Exception:
            pass

    return st


def _run_detection_cycle() -> dict[str, dict]:
    """Run detection for all tools; returns {tool_id: status_dict}."""
    ports   = _serial_ports_snapshot()
    usb_raw = _usb_list_text()

    results: dict[str, dict] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as exe:
        futs = {
            exe.submit(_detect_one, tid, tool, ports, usb_raw): tid
            for tid, tool in TOOLS.items()
        }
        for fut in concurrent.futures.as_completed(futs):
            tid = futs[fut]
            try:
                results[tid] = fut.result()
            except Exception:
                results[tid] = {"connected": False, "method": None,
                                "port": None, "web_url": TOOLS[tid].get("web_url")}
    return results


def _detection_worker():
    """Background daemon thread: poll all tools and push status deltas."""
    while True:
        try:
            new_results = _run_detection_cycle()
            changed = []
            with _status_lock:
                for tid, new_st in new_results.items():
                    old_st = _device_status.get(tid, {})
                    _device_status[tid] = new_st
                    if old_st.get("connected") != new_st.get("connected"):
                        changed.append((tid, new_st))

            for tid, st in changed:
                socketio.emit(
                    "device_status_update",
                    {"tool_id": tid, "name": TOOLS[tid]["name"],
                     "icon": TOOLS[tid]["icon"], "status": st},
                    broadcast=True,
                )
        except Exception:
            pass
        time.sleep(DETECT_INTERVAL)


# Start background detection thread at import time (daemon so it exits with process)
_detect_thread = threading.Thread(target=_detection_worker, daemon=True)
_detect_thread.start()


# ── Peer Quiver instance discovery ────────────────────────────────────────────
#
# If this server has any interface IP in 10.87.86.0/23, we periodically scan
# that subnet for other hosts listening on port 5200 (the Quiver default port).
# Discovered peers are broadcast to all connected browsers.
# ──────────────────────────────────────────────────────────────────────────────

PEER_SUBNET       = ipaddress.IPv4Network("10.87.86.0/23", strict=False)
PEER_PORT         = 5200
PEER_SCAN_INTERVAL = 30   # seconds between full subnet sweeps

_peer_instances: dict[str, dict] = {}   # ip → {"ip": str, "url": str, "since": str}
_peer_lock       = threading.Lock()


def _get_local_ips() -> list[str]:
    """Return all IPv4 addresses assigned to local interfaces."""
    ips: list[str] = []
    # Approach 1 – netifaces (optional dep)
    try:
        import netifaces  # type: ignore
        for iface in netifaces.interfaces():
            for addr in netifaces.ifaddresses(iface).get(netifaces.AF_INET, []):
                ip = addr.get("addr", "")
                if ip:
                    ips.append(ip)
        return ips
    except Exception:
        pass
    # Approach 2 – ip -4 addr show (Linux)
    try:
        r = subprocess.run(
            ["ip", "-4", "addr", "show"],
            capture_output=True, text=True, timeout=3,
        )
        if r.returncode == 0:
            for m in re.finditer(r"inet\s+(\d+\.\d+\.\d+\.\d+)", r.stdout):
                ips.append(m.group(1))
            if ips:
                return ips
    except Exception:
        pass
    # Approach 3 – ifconfig (macOS / BSD)
    try:
        r = subprocess.run(
            ["ifconfig"], capture_output=True, text=True, timeout=3,
        )
        if r.returncode == 0:
            for m in re.finditer(r"inet\s+(\d+\.\d+\.\d+\.\d+)", r.stdout):
                ips.append(m.group(1))
            if ips:
                return ips
    except Exception:
        pass
    # Fallback – hostname lookup (may only return one IP)
    try:
        ips.append(_socket.gethostbyname(_socket.gethostname()))
    except Exception:
        pass
    return ips


def _subnet_local_ips() -> list[str]:
    """Return local IPs that fall within PEER_SUBNET."""
    return [
        ip for ip in _get_local_ips()
        if ipaddress.IPv4Address(ip) in PEER_SUBNET
    ]


def _probe_peer(ip: str) -> bool:
    """Return True if PEER_PORT is open on ip."""
    try:
        with _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM) as s:
            s.settimeout(0.3)
            return s.connect_ex((ip, PEER_PORT)) == 0
    except Exception:
        return False


def _run_peer_scan(exclude_ips: set) -> dict[str, dict]:
    """Scan PEER_SUBNET for Quiver instances, skipping exclude_ips."""
    hosts = [
        str(h) for h in PEER_SUBNET.hosts()
        if str(h) not in exclude_ips
    ]
    found: dict[str, dict] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as exe:
        futs = {exe.submit(_probe_peer, ip): ip for ip in hosts}
        for fut in concurrent.futures.as_completed(futs):
            ip = futs[fut]
            try:
                if fut.result():
                    found[ip] = {
                        "ip":    ip,
                        "url":   f"http://{ip}:{PEER_PORT}",
                        "since": datetime.now(timezone.utc).strftime("%H:%M:%S UTC"),
                    }
            except Exception:
                pass
    return found


def _peer_discovery_worker():
    """Background daemon thread: scan subnet for peer Quiver instances."""
    while True:
        try:
            local_in_subnet = _subnet_local_ips()
            if local_in_subnet:
                exclude = set(_get_local_ips())
                new_peers = _run_peer_scan(exclude)
                with _peer_lock:
                    old_peers = dict(_peer_instances)
                    _peer_instances.clear()
                    _peer_instances.update(new_peers)

                added   = [p for ip, p in new_peers.items() if ip not in old_peers]
                removed = [p for ip, p in old_peers.items() if ip not in new_peers]

                if added or removed:
                    with _peer_lock:
                        snapshot = list(_peer_instances.values())
                    socketio.emit(
                        "peer_instances_update",
                        {"peers": snapshot},
                        broadcast=True,
                    )
            else:
                # Not on the target subnet — clear any stale entries
                with _peer_lock:
                    if _peer_instances:
                        _peer_instances.clear()
                        socketio.emit("peer_instances_update", {"peers": []}, broadcast=True)
        except Exception:
            pass
        time.sleep(PEER_SCAN_INTERVAL)


_peer_thread = threading.Thread(target=_peer_discovery_worker, daemon=True)
_peer_thread.start()


# ── Network device detection ───────────────────────────────────────────────────
#
# Well-known network appliances reachable on specific subnets.  For each entry,
# if this server has at least one interface IP inside `subnet`, we probe `host`
# on `probe_port`.  If alive, the device is surfaced in the UI with a link to
# its `web_url` management portal.
# ──────────────────────────────────────────────────────────────────────────────

NETWORK_DEVICES: list[dict] = [
    {
        "id":         "managed_switch",
        "name":       "Managed Switch",
        "icon":       "🔀",
        "subnet":     ipaddress.IPv4Network("192.168.8.0/24", strict=False),
        "host":       "192.168.8.1",
        "probe_port": 443,
        "web_url":    "https://192.168.8.1",
    },
]

NETDEV_SCAN_INTERVAL = 10   # seconds between appliance checks

_netdev_status: dict[str, bool] = {}   # device id → connected bool
_netdev_lock   = threading.Lock()


def _probe_netdev(host: str, port: int) -> bool:
    """Return True if host:port is reachable within 0.5 s."""
    try:
        with _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            return s.connect_ex((host, port)) == 0
    except Exception:
        return False


def _netdev_worker():
    """Background daemon: periodically probe each NETWORK_DEVICE."""
    while True:
        try:
            local_ips = _get_local_ips()
            changed: list[dict] = []

            for dev in NETWORK_DEVICES:
                # Only probe when this server has an interface in the device's subnet
                on_subnet = any(
                    ipaddress.IPv4Address(ip) in dev["subnet"]
                    for ip in local_ips
                )
                alive = on_subnet and _probe_netdev(dev["host"], dev["probe_port"])

                with _netdev_lock:
                    old = _netdev_status.get(dev["id"])
                    _netdev_status[dev["id"]] = alive
                    if old != alive:
                        changed.append({**dev, "connected": alive,
                                        "subnet": str(dev["subnet"])})

            for payload in changed:
                socketio.emit("netdev_update", payload, broadcast=True)

        except Exception:
            pass
        time.sleep(NETDEV_SCAN_INTERVAL)


_netdev_thread = threading.Thread(target=_netdev_worker, daemon=True)
_netdev_thread.start()


# ── In-memory session state ────────────────────────────────────────────────────

_active_procs:    dict[str, subprocess.Popen] = {}
_answer_queues:   dict[str, queue.Queue]       = {}
_console_buffer:  dict[str, list]              = {}
_pending_prompts: dict[str, dict]              = {}
_sid_to_session:  dict[str, str]              = {}

# Shell state — one per session (only one type active at a time)
_ssh_channels:    dict = {}   # paramiko channels (SSH)
_ssh_clients_map: dict = {}   # paramiko clients  (SSH)
_shell_serials:   dict = {}   # serial.Serial     (serial)
_shell_procs:     dict = {}   # subprocess.Popen  (process PTY)
_shell_fds:       dict = {}   # PTY master fd     (process PTY)
_shell_wss:       dict = {}   # websocket.WebSocket (websocket)

_MAX_CONSOLE = 400


def _room(session_id: str) -> str:
    return f"session:{session_id}"


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _buf_append(buf: dict, key: str, item):
    buf.setdefault(key, [])
    buf[key].append(item)
    if len(buf[key]) > _MAX_CONSOLE:
        buf[key] = buf[key][-_MAX_CONSOLE:]


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/api/nexus-status")
def api_nexus_status():
    """Unauthenticated status probe for the Nexus hub."""
    return jsonify({"app": "quiver", "tool": "quiver", "hostname": _socket.gethostname(), "scanning": False, "version": VERSION})


@app.route("/", methods=["GET"])
def index():
    payloads = _load_payloads()
    return render_template("index.html", tools=TOOLS, payloads=payloads, tool_groups=TOOL_GROUPS)


@app.route("/tool/<tool_id>", methods=["GET"])
def tool_page(tool_id: str):
    if tool_id not in TOOLS:
        return redirect(url_for("index"))
    tool     = TOOLS[tool_id]
    payloads = _load_payloads().get(tool_id, [])
    sess_id  = str(uuid.uuid4())
    selected_payload = request.args.get("payload", "")
    return render_template(
        "tool.html",
        tool_id=tool_id,
        tool=tool,
        payloads=payloads,
        session_id=sess_id,
        selected_payload=selected_payload,
        has_ssh=_tool_has_shell(tool),
        ssh_needs_ip=_tool_needs_ip(tool),
        shell_label=_tool_shell_label(tool),
        web_url=tool.get("web_url", ""),
    )


@app.route("/api/device-status", methods=["GET"])
def api_device_status():
    """Return current device presence status for all tools."""
    with _status_lock:
        snapshot = dict(_device_status)
    # Annotate with tool name/icon for convenience
    out = {}
    for tid, st in snapshot.items():
        out[tid] = {**st, "name": TOOLS[tid]["name"], "icon": TOOLS[tid]["icon"]}
    return jsonify(out)


@app.route("/api/firmware-status/<tool_id>", methods=["GET"])
def api_firmware_status(tool_id: str):
    """Return current vs latest firmware version for a tool (async GitHub check)."""
    if tool_id not in TOOLS:
        return jsonify({"error": "unknown tool"}), 404

    import sys, importlib, subprocess as _sp
    # Pull github_repo from tool definition if present
    tool = TOOLS[tool_id]
    github_repo = tool.get("github_repo", "")

    result = {
        "tool_id":    tool_id,
        "tool_name":  tool["name"],
        "current":    None,
        "latest":     None,
        "up_to_date": None,
        "release_url": "",
        "note":       "",
    }

    if not github_repo:
        result["note"] = "No GitHub repo configured for this tool."
        return jsonify(result)

    owner, repo = (github_repo.split("/", 1) + [""])[:2]
    if not repo:
        result["note"] = "Invalid github_repo format (expected owner/repo)."
        return jsonify(result)

    # Check GitHub for latest release
    try:
        import urllib.request as _urlreq, json as _json
        headers = {"Accept": "application/vnd.github+json",
                   "X-GitHub-Api-Version": "2022-11-28",
                   "User-Agent": "Quiver/1.0"}
        import os as _os
        token = _os.environ.get("GITHUB_TOKEN", "")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = _urlreq.Request(
            f"https://api.github.com/repos/{owner}/{repo}/releases/latest",
            headers=headers)
        with _urlreq.urlopen(req, timeout=8) as resp:
            data = _json.loads(resp.read())
        result["latest"]      = data.get("tag_name", "")
        result["release_url"] = data.get("html_url", "")
    except Exception as e:
        result["note"] = f"GitHub check failed: {e}"

    # Passive current-firmware probe (read-only — no flashing). Runs the tool's
    # module in --probe-fw-version mode; it prints one small JSON blob and exits.
    # This is what lets the Firmware tab show the installed version WITHOUT the
    # operator running the full script or risking a flash.
    if tool.get("fw_probe"):
        try:
            script_path = BASE_DIR / tool["script"]
            proc = _sp.run(
                [sys.executable, str(script_path), "--probe-fw-version"],
                cwd=str(BASE_DIR), capture_output=True, text=True, timeout=15,
            )
            blob = ""
            for ln in reversed((proc.stdout or "").splitlines()):
                ln = ln.strip()
                if ln.startswith("{") and ln.endswith("}"):
                    blob = ln
                    break
            if blob:
                pj = _json.loads(blob)
                result["installed"] = bool(pj.get("installed"))
                result["current"]   = pj.get("version")
                pnote = pj.get("note", "")
                if pnote:
                    result["note"] = (f"{result['note']} {pnote}".strip()
                                      if result["note"] else pnote)
                cur, lat = result.get("current"), result.get("latest")
                if cur and lat:
                    import re as _re
                    ca = [int(x) for x in _re.findall(r"\d+", cur)]
                    la = [int(x) for x in _re.findall(r"\d+", lat)]
                    n = max(len(ca), len(la))
                    ca += [0] * (n - len(ca))
                    la += [0] * (n - len(la))
                    result["up_to_date"] = ca >= la
            elif not result["note"]:
                result["note"] = "Firmware probe returned no data."
        except _sp.TimeoutExpired:
            result["note"] = (f"{result['note']} Firmware probe timed out.").strip()
        except Exception as e:
            result["note"] = (f"{result['note']} Firmware probe error: {e}").strip()

    return jsonify(result)


@app.route("/api/peer-instances", methods=["GET"])
def api_peer_instances():
    """Return currently discovered peer Quiver instances on the local subnet."""
    with _peer_lock:
        return jsonify(list(_peer_instances.values()))


@app.route("/api/peer-subnet-active", methods=["GET"])
def api_peer_subnet_active():
    """Return whether this server has an interface in the peer-discovery subnet."""
    return jsonify({"active": bool(_subnet_local_ips()), "subnet": str(PEER_SUBNET)})


@app.route("/api/network-devices", methods=["GET"])
def api_network_devices():
    """Return current status of well-known network appliances."""
    with _netdev_lock:
        snapshot = dict(_netdev_status)
    out = []
    for dev in NETWORK_DEVICES:
        out.append({
            "id":        dev["id"],
            "name":      dev["name"],
            "icon":      dev["icon"],
            "web_url":   dev["web_url"],
            "connected": snapshot.get(dev["id"], False),
        })
    return jsonify(out)


# ── Reverse proxy ──────────────────────────────────────────────────────────────
#
# /proxy/<device_id>/          → root of the device's web_url
# /proxy/<device_id>/<subpath> → deeper paths
#
# Works for any entry in NETWORK_DEVICES or TOOLS that has a web_url.
# The server issues the request using its own routing table, so interfaces
# only reachable on the server (e.g. 192.168.8.x) are transparently accessible
# to any browser that can reach Quiver.
# ──────────────────────────────────────────────────────────────────────────────

# Headers that must not be forwarded between proxy hops
_HOP_BY_HOP = frozenset([
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
    "content-encoding",   # we decode on the server side
    "content-length",     # recalculated after any rewriting
])


def _proxy_target_base(device_id: str) -> Optional[str]:
    """Return the base web_url for a known device id, or None."""
    for dev in NETWORK_DEVICES:
        if dev["id"] == device_id:
            return dev["web_url"].rstrip("/")
    tool = TOOLS.get(device_id)
    if tool and tool.get("web_url"):
        return tool["web_url"].rstrip("/")
    return None


_JS_SHIM_TEMPLATE = """<script>
(function(){{
  var P='{proxy_root}';
  function _rw(u){{
    if(typeof u==='string'&&u.charAt(0)==='/'&&u.slice(0,7)!=='/proxy/')
      return P+u;
    return u;
  }}
  var _fetch=window.fetch;
  window.fetch=function(u,o){{return _fetch.call(this,_rw(u),o);}};
  var _open=XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open=function(m,u){{
    arguments[1]=_rw(u);
    return _open.apply(this,arguments);
  }};
}})();
</script>"""


def _rewrite_urls(content: bytes, content_type: str,
                  target_base: str, device_id: str) -> bytes:
    """
    Rewrite HTML/CSS responses so all URLs route through /proxy/<device_id>/.
    Also injects a JS shim that intercepts fetch() and XHR so JS-driven
    API calls (root-relative paths) are transparently proxied as well.
    """
    proxy_root = f"/proxy/{device_id}"

    if "text/html" in content_type:
        text = content.decode("utf-8", errors="replace")

        # Root-relative URLs — guard against double-rewriting
        text = re.sub(
            r'((?:href|src|action|data-src|srcset)\s*=\s*["\'])/(?!proxy/)',
            rf'\g<1>{proxy_root}/',
            text,
        )
        # Absolute URLs pointing at the target origin
        escaped = re.escape(target_base)
        text = re.sub(
            rf'((?:href|src|action|data-src|srcset)\s*=\s*["\']){escaped}(/|(?=["\']))',
            rf'\g<1>{proxy_root}/',
            text,
        )

        # Remove any existing <base> tag (it would conflict with ours)
        text = re.sub(r'<base\b[^>]*>', '', text, flags=re.IGNORECASE)

        # Inject <base> as first child of <head> so relative URLs resolve correctly
        base_tag = f'<base href="{proxy_root}/">'
        text = re.sub(r'(<head\b[^>]*>)', rf'\1{base_tag}', text, count=1,
                      flags=re.IGNORECASE)

        # Inject JS shim before </head> so it runs before any page scripts
        shim = _JS_SHIM_TEMPLATE.format(proxy_root=proxy_root)
        if re.search(r'</head>', text, re.IGNORECASE):
            text = re.sub(r'(</head>)', shim + r'\1', text, count=1,
                          flags=re.IGNORECASE)
        elif re.search(r'<body\b', text, re.IGNORECASE):
            text = re.sub(r'(<body\b[^>]*>)', r'\1' + shim, text, count=1,
                          flags=re.IGNORECASE)
        else:
            text = shim + text

        return text.encode("utf-8")

    if "text/css" in content_type:
        text = content.decode("utf-8", errors="replace")
        # url('/path') → url('/proxy/id/path')  — guard double-rewrite
        text = re.sub(r"url\(\s*(['\"]?)/(?!proxy/)", rf"url(\g<1>{proxy_root}/", text)
        return text.encode("utf-8")

    return content


@app.route("/proxy/<device_id>/", defaults={"subpath": ""}, methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
@app.route("/proxy/<device_id>/<path:subpath>",            methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
def device_proxy(device_id: str, subpath: str):
    """Reverse-proxy a request to a network device's web interface."""
    target_base = _proxy_target_base(device_id)
    if not target_base:
        return Response("Unknown device", status=404)

    target_url = f"{target_base}/{subpath}"
    if request.query_string:
        target_url += "?" + request.query_string.decode("utf-8", errors="replace")

    # Forward headers, stripping hop-by-hop and rewriting Host
    fwd_headers = {
        k: v for k, v in request.headers
        if k.lower() not in _HOP_BY_HOP and k.lower() != "host"
    }
    fwd_headers["Host"] = target_base.split("://", 1)[-1]

    try:
        upstream = requests.request(
            method=request.method,
            url=target_url,
            headers=fwd_headers,
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            verify=False,           # local devices typically use self-signed certs
            stream=True,
            timeout=15,
        )
    except requests.exceptions.ConnectionError:
        return Response("Device unreachable", status=502)
    except requests.exceptions.Timeout:
        return Response("Device timed out", status=504)

    # Rewrite Location header on redirects so the browser stays in the proxy
    resp_headers = {
        k: v for k, v in upstream.headers.items()
        if k.lower() not in _HOP_BY_HOP
    }
    if "location" in upstream.headers:
        loc = upstream.headers["location"]
        if loc.startswith(target_base):
            loc = f"/proxy/{device_id}/" + loc[len(target_base):].lstrip("/")
        elif loc.startswith("/"):
            loc = f"/proxy/{device_id}{loc}"
        resp_headers["Location"] = loc

    content_type = upstream.headers.get("content-type", "")

    # For rewritable text content, buffer and rewrite; otherwise stream
    if any(t in content_type for t in ("text/html", "text/css")):
        body = _rewrite_urls(upstream.content, content_type, target_base, device_id)
        resp_headers.pop("Content-Length", None)
        return Response(body, status=upstream.status_code,
                        headers=resp_headers, content_type=content_type)

    # Binary / large responses: stream directly
    def _generate():
        for chunk in upstream.iter_content(chunk_size=8192):
            yield chunk

    resp_headers.pop("Content-Length", None)
    return Response(
        stream_with_context(_generate()),
        status=upstream.status_code,
        headers=resp_headers,
        content_type=content_type,
    )


def _detect_usb_volumes() -> list:
    """Return a list of USB/removable volume mount paths."""
    import platform, subprocess, plistlib
    found = []
    system = platform.system()

    if system == "Darwin":
        # "diskutil list external" limits output to external (non-internal) disks,
        # which covers USB, USB-C, and SD card mounts without needing bus-type checks.
        try:
            list_result = subprocess.run(
                ["diskutil", "list", "-plist", "external"],
                capture_output=True, timeout=5,
            )
            plist = plistlib.loads(list_result.stdout)
            all_disks = plist.get("AllDisksAndPartitions", [])
        except Exception:
            all_disks = []

        seen = set()
        for disk in all_disks:
            # Collect whole-disk identifier and every partition identifier
            candidates = [disk.get("DeviceIdentifier", "")]
            for part in disk.get("Partitions", []):
                candidates.append(part.get("DeviceIdentifier", ""))

            for dev in candidates:
                if not dev or dev in seen:
                    continue
                seen.add(dev)
                try:
                    info_result = subprocess.run(
                        ["diskutil", "info", "-plist", dev],
                        capture_output=True, timeout=3,
                    )
                    dinfo = plistlib.loads(info_result.stdout)
                except Exception:
                    continue

                mount = dinfo.get("MountPoint", "")
                # Only include partitions with a real mount point (skip unmounted)
                if mount and mount != "/":
                    found.append(mount)

    elif system == "Linux":
        # Cross-reference /sys/block removable+USB devices with /proc/mounts
        import os
        removable_devs = set()
        try:
            for blk in os.listdir("/sys/block"):
                removable_path = f"/sys/block/{blk}/removable"
                uevent_path = f"/sys/block/{blk}/device/uevent"
                try:
                    is_removable = open(removable_path).read().strip() == "1"
                    uevent = open(uevent_path).read() if os.path.exists(uevent_path) else ""
                    if is_removable and "USB" in uevent.upper():
                        removable_devs.add(blk)
                except Exception:
                    pass
        except Exception:
            pass

        try:
            with open("/proc/mounts") as fh:
                for line in fh:
                    parts = line.split()
                    if len(parts) < 2:
                        continue
                    dev, mount = parts[0], parts[1]
                    # Map e.g. /dev/sdb1 -> sdb
                    base_dev = dev.lstrip("/").replace("dev/", "").rstrip("0123456789")
                    if base_dev in removable_devs and mount not in ("/", "/boot"):
                        found.append(mount)
        except Exception:
            pass

    return sorted(set(found))


@app.route("/api/usb/save-info", methods=["GET"])
def api_usb_save_info():
    """Return payload file content + detected USB volume paths for client-side save."""
    payload_path = request.args.get("payload", "").strip()
    if not payload_path:
        return jsonify({"ok": False, "error": "No payload path specified"})

    # Resolve and validate the path stays inside PAYLOAD_DIR
    target = (BASE_DIR / payload_path).resolve()
    try:
        target.relative_to(PAYLOAD_DIR.resolve())
    except ValueError:
        return jsonify({"ok": False, "error": "Invalid payload path"})

    if not target.is_file():
        return jsonify({"ok": False, "error": "Payload file not found"})

    try:
        content = target.read_text(errors="replace")
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)})

    return jsonify({
        "ok":        True,
        "filename":  target.name,
        "content":   content,
        "usb_paths": _detect_usb_volumes(),
    })


@app.route("/api/payloads/<tool_id>", methods=["GET"])
def api_payloads(tool_id: str):
    if tool_id not in TOOLS:
        return jsonify([])
    return jsonify(_load_payloads().get(tool_id, []))


@app.route("/api/payloads/add", methods=["POST"])
def api_add_payload():
    tool_id = request.form.get("tool_id", "")
    name    = request.form.get("name", "").strip()
    file    = request.files.get("file")

    if not tool_id or tool_id not in TOOLS:
        return jsonify({"error": "Invalid tool"}), 400
    if not name:
        return jsonify({"error": "Name is required"}), 400
    if not file or not file.filename:
        return jsonify({"error": "File is required"}), 400

    tool_payload_dir = PAYLOAD_DIR / tool_id
    tool_payload_dir.mkdir(parents=True, exist_ok=True)

    safe_name = re.sub(r"[^\w.\-]", "_", file.filename)
    dest = tool_payload_dir / safe_name
    file.save(str(dest))

    payloads = _load_payloads()
    payloads.setdefault(tool_id, [])
    payloads[tool_id].append({
        "name":  name,
        "path":  str(dest.relative_to(BASE_DIR)),
        "added": _ts(),
    })
    _save_payloads(payloads)
    return jsonify({"ok": True, "path": str(dest.relative_to(BASE_DIR))})


# ── Script runner SocketIO ─────────────────────────────────────────────────────

@socketio.on("connect")
def on_connect():
    if not session.get("authenticated"):
        return False  # reject unauthenticated WebSocket connections


@socketio.on("disconnect")
def on_disconnect():
    sid = request.sid
    sess_id = _sid_to_session.pop(sid, None)
    if sess_id:
        _kill_process(sess_id)
        _disconnect_all_shells(sess_id)


@socketio.on("request_device_status")
def on_request_device_status():
    """Client asks for the current full status snapshot (used on initial page load)."""
    with _status_lock:
        snapshot = dict(_device_status)
    out = {}
    for tid, st in snapshot.items():
        out[tid] = {**st, "name": TOOLS[tid]["name"], "icon": TOOLS[tid]["icon"]}
    emit("device_status_snapshot", out)


@socketio.on("request_network_devices")
def on_request_network_devices():
    """Client asks for the current network appliance status snapshot."""
    with _netdev_lock:
        snapshot = dict(_netdev_status)
    out = []
    for dev in NETWORK_DEVICES:
        out.append({
            "id":        dev["id"],
            "name":      dev["name"],
            "icon":      dev["icon"],
            "web_url":   dev["web_url"],
            "connected": snapshot.get(dev["id"], False),
        })
    emit("netdev_snapshot", out)


@socketio.on("request_peer_instances")
def on_request_peer_instances():
    """Client asks for the current snapshot of discovered peer Quiver instances."""
    with _peer_lock:
        peers = list(_peer_instances.values())
    active = bool(_subnet_local_ips())
    emit("peer_instances_snapshot", {"peers": peers, "subnet_active": active})


@socketio.on("join_session")
def on_join_session(data):
    d       = data or {}
    sess_id = d.get("session_id", "")
    if not sess_id:
        return
    _sid_to_session[request.sid] = sess_id
    join_room(_room(sess_id))
    history = _console_buffer.get(sess_id, [])
    emit("session_state", {"console_history": history})
    pending = _pending_prompts.get(sess_id)
    if pending:
        emit("script_prompt", pending)


@socketio.on("start_script")
def on_start_script(data):
    d            = data or {}
    sess_id      = d.get("session_id", "")
    tool_id      = d.get("tool_id", "")
    payload_path = d.get("payload_path", "")
    room         = _room(sess_id)

    if not sess_id or tool_id not in TOOLS:
        emit("script_error", {"error": "Invalid session or tool"})
        return

    if sess_id in _active_procs:
        emit("script_error", {"error": "Script already running"})
        return

    script = BASE_DIR / TOOLS[tool_id]["script"]
    env    = {**os.environ, "QUIVER_WEB_MODE": "1"}
    if payload_path:
        env["QUIVER_SELECTED_PAYLOAD"] = payload_path

    try:
        proc = subprocess.Popen(
            [sys.executable, str(script)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=0,
            env=env,
        )
    except Exception as e:
        emit("script_error", {"error": f"Failed to start: {e}"})
        return

    answer_q = queue.Queue()
    _active_procs[sess_id]   = proc
    _answer_queues[sess_id]  = answer_q
    _console_buffer[sess_id] = []

    socketio.emit("script_started", {"pid": proc.pid}, room=room)

    threading.Thread(target=_stdout_reader, args=(proc, sess_id, answer_q), daemon=True).start()
    threading.Thread(target=_stderr_reader, args=(proc, sess_id),            daemon=True).start()


def _stdout_reader(proc: subprocess.Popen, sess_id: str, answer_q: queue.Queue):
    room = _room(sess_id)

    def emit_line(text: str, stream: str = "stdout"):
        msg = {"text": text, "stream": stream, "ts": _ts()}
        _buf_append(_console_buffer, sess_id, msg)
        socketio.emit("script_output", msg, room=room)

    try:
        for raw in proc.stdout:
            line = raw.rstrip("\n")

            if line.startswith("LOG:"):
                try:
                    payload = json.loads(line[4:])
                    level   = payload.get("level", "stdout")
                    text    = payload.get("text", "")

                    if level in ("wait_start", "wait_done", "wait_timeout", "wait_status"):
                        socketio.emit(f"script_{level}", {"text": text}, room=room)
                        if level == "wait_done" and text:
                            emit_line(text, "ok")
                        elif level == "wait_timeout" and text:
                            emit_line(text, "warn")
                    elif level == "progress":
                        pct  = payload.get("pct", 0)
                        step = payload.get("step", "")
                        socketio.emit("script_progress", {
                            "pct": pct, "text": text, "step": step
                        }, room=room)
                    else:
                        stream = {
                            "ok":      "ok",
                            "warn":    "warn",
                            "err":     "stderr",
                            "info":    "info",
                            "heading": "heading",
                            "banner":  "heading",
                        }.get(level, "stdout")
                        emit_line(text, stream)
                except Exception:
                    emit_line(line)

            elif line.startswith("PROMPT:"):
                try:
                    payload = json.loads(line[7:])
                    _pending_prompts[sess_id] = payload
                    socketio.emit("script_prompt", payload, room=room)
                    try:
                        answer = answer_q.get(timeout=1800)
                        _pending_prompts.pop(sess_id, None)
                        proc.stdin.write(json.dumps({"value": answer}) + "\n")
                        proc.stdin.flush()
                        ptype = payload.get("type", "text")
                        echo  = "< [hidden]" if ptype == "password" else f"< {answer}"
                        emit_line(echo, "system")
                    except queue.Empty:
                        _pending_prompts.pop(sess_id, None)
                        socketio.emit("prompt_resolved", {}, room=room)
                        socketio.emit("script_error", {"error": "Prompt timed out (30 min)"}, room=room)
                        break
                except Exception:
                    emit_line(line)
            else:
                emit_line(line)

    except Exception as e:
        socketio.emit("script_error", {"error": f"Read error: {e}"}, room=room)

    ret = proc.wait()
    socketio.emit("script_done", {"returncode": ret}, room=room)
    _active_procs.pop(sess_id, None)
    _answer_queues.pop(sess_id, None)
    _pending_prompts.pop(sess_id, None)


def _stderr_reader(proc: subprocess.Popen, sess_id: str):
    room = _room(sess_id)
    try:
        for line in proc.stderr:
            text = line.rstrip("\n")
            msg  = {"text": text, "stream": "stderr", "ts": _ts()}
            _buf_append(_console_buffer, sess_id, msg)
            socketio.emit("script_output", msg, room=room)
    except Exception:
        pass


@socketio.on("script_answer")
def on_script_answer(data):
    d       = data or {}
    sess_id = d.get("session_id", "") or _sid_to_session.get(request.sid, "")
    answer  = str(d.get("answer", ""))
    q       = _answer_queues.get(sess_id)
    if q:
        q.put(answer)
        _pending_prompts.pop(sess_id, None)
        socketio.emit("prompt_resolved", {}, room=_room(sess_id))
        # Note: the answer echo (masked for passwords) is emitted by
        # _stdout_reader when it forwards the answer to the script's stdin.
        # Do NOT echo here too — it would duplicate the line and would leak
        # password values in cleartext to every viewer.


@socketio.on("kill_script")
def on_kill_script(data):
    d       = data or {}
    sess_id = d.get("session_id", "") or _sid_to_session.get(request.sid, "")
    _kill_process(sess_id)
    socketio.emit("script_stopped", {}, room=_room(sess_id))


def _kill_process(sess_id: str):
    proc = _active_procs.pop(sess_id, None)
    if proc:
        try:
            proc.kill()
        except Exception:
            pass
    _answer_queues.pop(sess_id, None)
    _pending_prompts.pop(sess_id, None)


# ── Shell SocketIO — unified handler (SSH / serial / process / websocket) ──────

@socketio.on("ssh_connect")
def on_ssh_connect(data):
    d        = data or {}
    sess_id  = d.get("session_id", "")
    tool_id  = d.get("tool_id", "")
    room     = _room(sess_id)

    if not sess_id or tool_id not in TOOLS:
        emit("ssh_error", {"error": "Invalid session or tool"})
        return

    tool      = TOOLS[tool_id]
    ssh_cfg   = tool.get("ssh")
    shell_cfg = tool.get("shell") or {}

    # ── SSH path (network-attached devices) ───────────────────────────────────
    if ssh_cfg is not None:
        host_override = d.get("host", "").strip()
        host = host_override or ssh_cfg.get("host")
        if not host:
            emit("ssh_error", {"error": "Device IP unknown — enter IP manually"})
            return
        threading.Thread(
            target=_do_ssh_connect,
            args=(sess_id, host, ssh_cfg, room),
            daemon=True,
        ).start()
        return

    # ── New polymorphic shell path ─────────────────────────────────────────────
    shell_type = shell_cfg.get("type", "none")

    if shell_type == "serial":
        threading.Thread(
            target=_do_serial_shell,
            args=(sess_id, shell_cfg, room),
            daemon=True,
        ).start()

    elif shell_type == "process":
        threading.Thread(
            target=_do_process_shell,
            args=(sess_id, shell_cfg, room),
            daemon=True,
        ).start()

    elif shell_type == "websocket":
        threading.Thread(
            target=_do_ws_shell,
            args=(sess_id, shell_cfg, room),
            daemon=True,
        ).start()

    else:
        emit("ssh_error", {
            "error": f"{tool['name']} has no interactive shell. "
                     "Use the Run Script tab to manage this device."
        })


# ── SSH (paramiko) ─────────────────────────────────────────────────────────────

def _do_ssh_connect(sess_id: str, host: str, ssh_cfg: dict, room: str):
    if not HAS_PARAMIKO:
        socketio.emit("ssh_error",
                      {"error": "paramiko not installed — run: pip install paramiko"},
                      room=room)
        return
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            host,
            port=ssh_cfg["port"],
            username=ssh_cfg["user"],
            password=ssh_cfg["password"],
            timeout=15,
            banner_timeout=15,
            auth_timeout=15,
            look_for_keys=False,
            allow_agent=False,
        )
        channel = client.invoke_shell(term="xterm-256color", width=220, height=50)
        _ssh_channels[sess_id]    = channel
        _ssh_clients_map[sess_id] = client
        socketio.emit("ssh_connected", {"host": host}, room=room)
        while True:
            if channel.recv_ready():
                data_out = channel.recv(4096)
                if not data_out:
                    break
                socketio.emit("ssh_output",
                              {"data": data_out.decode("utf-8", errors="replace")},
                              room=room)
            elif channel.closed or channel.eof_received:
                break
            else:
                time.sleep(0.02)
        socketio.emit("ssh_disconnected", {}, room=room)
    except Exception as e:
        socketio.emit("ssh_error", {"error": str(e)}, room=room)
    finally:
        _disconnect_ssh(sess_id)


def _disconnect_ssh(sess_id: str):
    ch = _ssh_channels.pop(sess_id, None)
    if ch:
        try:
            ch.close()
        except Exception:
            pass
    cl = _ssh_clients_map.pop(sess_id, None)
    if cl:
        try:
            cl.close()
        except Exception:
            pass


# ── Serial shell ───────────────────────────────────────────────────────────────

def _find_port_for_shell(vid_pids: list) -> Optional[str]:
    """Auto-detect serial port from a list of (vid, pid) tuples."""
    if not HAS_SERIAL:
        return None
    for p in _list_ports.comports():
        for vid, pid in vid_pids:
            if p.vid == vid and (pid is None or p.pid == pid):
                return p.device
    return None


def _do_serial_shell(sess_id: str, shell_cfg: dict, room: str):
    if not HAS_SERIAL:
        socketio.emit("ssh_error",
                      {"error": "pyserial not installed — run: pip install pyserial"},
                      room=room)
        return

    vid_pids = shell_cfg.get("vid_pids", [])
    port     = _find_port_for_shell(vid_pids)
    if not port:
        socketio.emit("ssh_error",
                      {"error": "Device not detected. Connect it via USB and try again."},
                      room=room)
        return

    baud = shell_cfg.get("baud", 115200)
    try:
        ser = _serial.Serial(
            port=port, baudrate=baud,
            bytesize=8, parity="N", stopbits=1,
            timeout=0.05, xonxoff=False, rtscts=False, dsrdtr=False,
        )
        _shell_serials[sess_id] = ser
        socketio.emit("ssh_connected", {"host": port}, room=room)

        while ser.is_open:
            try:
                waiting = ser.in_waiting
                if waiting:
                    raw = ser.read(waiting)
                    if raw:
                        socketio.emit("ssh_output",
                                      {"data": raw.decode("utf-8", errors="replace")},
                                      room=room)
                else:
                    time.sleep(0.02)
            except Exception:
                break

        socketio.emit("ssh_disconnected", {}, room=room)
    except Exception as e:
        socketio.emit("ssh_error", {"error": str(e)}, room=room)
    finally:
        _disconnect_serial(sess_id)


def _disconnect_serial(sess_id: str):
    ser = _shell_serials.pop(sess_id, None)
    if ser:
        try:
            ser.close()
        except Exception:
            pass


# ── Process PTY shell ──────────────────────────────────────────────────────────

def _do_process_shell(sess_id: str, shell_cfg: dict, room: str):
    import shutil

    if not HAS_PTY:
        socketio.emit("ssh_error",
                      {"error": "PTY not available on this OS (Windows not supported)."},
                      room=room)
        return

    cmd = list(shell_cfg.get("cmd", []))
    if not cmd:
        socketio.emit("ssh_error", {"error": "No shell command configured."}, room=room)
        return

    # Resolve binary
    if not shutil.which(cmd[0]):
        socketio.emit("ssh_error",
                      {"error": f"Command not found: '{cmd[0]}'. "
                                f"Install the required software and ensure it is in PATH."},
                      room=room)
        return

    # Auto-detect port if {port} placeholder is present
    if any("{port}" in c for c in cmd):
        vid_pids = shell_cfg.get("vid_pids", [])
        port     = _find_port_for_shell(vid_pids)
        if not port:
            socketio.emit("ssh_error",
                          {"error": "Device not detected. Connect via USB first."},
                          room=room)
            return
        cmd = [c.replace("{port}", port) for c in cmd]

    try:
        master_fd, slave_fd = _pty.openpty()
        # Set initial terminal size 220×50
        winsize = _struct.pack("HHHH", 50, 220, 0, 0)
        _fcntl.ioctl(slave_fd, _termios.TIOCSWINSZ, winsize)

        proc = subprocess.Popen(
            cmd,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            close_fds=True,
            preexec_fn=os.setsid,
        )
        os.close(slave_fd)

        _shell_procs[sess_id] = proc
        _shell_fds[sess_id]   = master_fd
        socketio.emit("ssh_connected", {"host": " ".join(cmd)}, room=room)

        while proc.poll() is None:
            try:
                r, _, _ = _select.select([master_fd], [], [], 0.05)
                if r:
                    data = os.read(master_fd, 4096)
                    if data:
                        socketio.emit("ssh_output",
                                      {"data": data.decode("utf-8", errors="replace")},
                                      room=room)
            except (OSError, IOError):
                break

        socketio.emit("ssh_disconnected", {}, room=room)
    except Exception as e:
        socketio.emit("ssh_error", {"error": str(e)}, room=room)
    finally:
        _disconnect_process(sess_id)


def _disconnect_process(sess_id: str):
    proc = _shell_procs.pop(sess_id, None)
    if proc:
        try:
            proc.kill()
        except Exception:
            pass
    fd = _shell_fds.pop(sess_id, None)
    if fd is not None:
        try:
            os.close(fd)
        except Exception:
            pass


# ── WebSocket relay shell (WiFi Duck) ─────────────────────────────────────────

def _do_ws_shell(sess_id: str, shell_cfg: dict, room: str):
    if not HAS_WEBSOCKET:
        socketio.emit("ssh_error",
                      {"error": "websocket-client not installed — run: pip install websocket-client"},
                      room=room)
        return

    ws_url = shell_cfg.get("ws_url", "ws://192.168.4.1/ws")
    try:
        ws = _websocket_lib.WebSocket()
        ws.connect(ws_url, timeout=10)
        _shell_wss[sess_id] = ws
        socketio.emit("ssh_connected", {"host": ws_url}, room=room)

        while True:
            try:
                ws.settimeout(0.1)
                msg = ws.recv()
                if msg:
                    socketio.emit("ssh_output", {"data": msg + "\n"}, room=room)
            except _websocket_lib.WebSocketTimeoutException:
                continue
            except Exception:
                break

        socketio.emit("ssh_disconnected", {}, room=room)
    except Exception as e:
        socketio.emit("ssh_error", {"error": str(e)}, room=room)
    finally:
        _disconnect_ws(sess_id)


def _disconnect_ws(sess_id: str):
    ws = _shell_wss.pop(sess_id, None)
    if ws:
        try:
            ws.close()
        except Exception:
            pass


# ── Unified input / resize / disconnect events ────────────────────────────────

@socketio.on("ssh_input")
def on_ssh_input(data):
    d       = data or {}
    sess_id = d.get("session_id", "") or _sid_to_session.get(request.sid, "")
    text    = d.get("data", "")
    if not text:
        return

    # SSH channel
    ch = _ssh_channels.get(sess_id)
    if ch and not ch.closed:
        try:
            ch.send(text)
        except Exception:
            pass
        return

    # Serial
    ser = _shell_serials.get(sess_id)
    if ser and ser.is_open:
        try:
            ser.write(text.encode("utf-8", errors="replace"))
        except Exception:
            pass
        return

    # Process PTY
    fd = _shell_fds.get(sess_id)
    if fd is not None:
        try:
            os.write(fd, text.encode("utf-8", errors="replace"))
        except Exception:
            pass
        return

    # WebSocket relay
    ws = _shell_wss.get(sess_id)
    if ws:
        try:
            ws.send(text.strip())
        except Exception:
            pass


@socketio.on("ssh_resize")
def on_ssh_resize(data):
    d       = data or {}
    sess_id = d.get("session_id", "") or _sid_to_session.get(request.sid, "")
    cols    = d.get("cols", 220)
    rows    = d.get("rows", 50)

    # SSH channel
    ch = _ssh_channels.get(sess_id)
    if ch:
        try:
            ch.resize_pty(width=cols, height=rows)
        except Exception:
            pass
        return

    # PTY resize
    fd = _shell_fds.get(sess_id)
    if fd is not None and HAS_PTY:
        try:
            winsize = _struct.pack("HHHH", rows, cols, 0, 0)
            _fcntl.ioctl(fd, _termios.TIOCSWINSZ, winsize)
        except Exception:
            pass


@socketio.on("ssh_disconnect")
def on_ssh_disconnect(data):
    d       = data or {}
    sess_id = d.get("session_id", "") or _sid_to_session.get(request.sid, "")
    _disconnect_all_shells(sess_id)
    socketio.emit("ssh_disconnected", {}, room=_room(sess_id))


def _disconnect_all_shells(sess_id: str):
    _disconnect_ssh(sess_id)
    _disconnect_serial(sess_id)
    _disconnect_process(sess_id)
    _disconnect_ws(sess_id)


# ── Auth routes ────────────────────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if not _auth.validate_csrf(request.form.get("csrf_token")):
            return render_template("login.html", error="Invalid request token.", csrf_token=_auth.generate_csrf())
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if _auth.verify_credentials(username, password):
            session.permanent = True
            session["authenticated"] = True
            session["username"] = username
            if _auth.must_change_password():
                return redirect(url_for("change_password"))
            return redirect(url_for("index"))
        return render_template("login.html", error="Invalid credentials.", username=username,
                               csrf_token=_auth.generate_csrf())
    return render_template("login.html", csrf_token=_auth.generate_csrf())


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/api/session_ping", methods=["POST"])
def session_ping():
    if not session.get("authenticated"):
        return jsonify({"ok": False}), 401
    session.modified = True
    return jsonify({"ok": True})


@app.route("/auth/change-password", methods=["GET", "POST"])
def change_password():
    force = _auth.must_change_password()
    if request.method == "POST":
        if not _auth.validate_csrf(request.form.get("csrf_token")):
            return render_template("change_password.html", error="Invalid request token.",
                                   force=force, csrf_token=_auth.generate_csrf())
        new_pw  = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        if force:
            new_user = request.form.get("new_username", "").strip()
            err = _auth.is_weak_username(new_user)
            if err:
                return render_template("change_password.html", error=err,
                                       force=force, csrf_token=_auth.generate_csrf())
            if len(new_pw) < 8:
                return render_template("change_password.html", error="Password must be at least 8 characters.",
                                       force=force, csrf_token=_auth.generate_csrf())
            if new_pw != confirm:
                return render_template("change_password.html", error="Passwords do not match.",
                                       force=force, csrf_token=_auth.generate_csrf())
            err = _auth.is_weak_password(new_pw, new_user)
            if err:
                return render_template("change_password.html", error=err,
                                       force=force, csrf_token=_auth.generate_csrf())
            _auth.update_credentials(new_user, new_pw)
            session["username"] = new_user
            return redirect(url_for("index"))
        else:
            current = request.form.get("current_password", "")
            if not _auth.check_current_password(current):
                return render_template("change_password.html", error="Current password is incorrect.",
                                       force=force, csrf_token=_auth.generate_csrf())
            if len(new_pw) < 8:
                return render_template("change_password.html", error="Password must be at least 8 characters.",
                                       force=force, csrf_token=_auth.generate_csrf())
            if new_pw != confirm:
                return render_template("change_password.html", error="Passwords do not match.",
                                       force=force, csrf_token=_auth.generate_csrf())
            err = _auth.is_weak_password(new_pw, _auth.get_username())
            if err:
                return render_template("change_password.html", error=err,
                                       force=force, csrf_token=_auth.generate_csrf())
            _auth.update_password(new_pw)
            return redirect(url_for("index"))
    return render_template("change_password.html", force=force, csrf_token=_auth.generate_csrf())


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 54)
    print(f"  Quiver — Hardware Hacking Command Centre  v{VERSION}")
    print("  https://0.0.0.0:5200")
    print("=" * 54)
    socketio.run(app, debug=False, host="0.0.0.0", port=5200,
                 allow_unsafe_werkzeug=True, ssl_context=_auth.make_ssl_context())
