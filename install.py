#!/usr/bin/env python3
"""
install.py — Quiver installer
Installs all Python dependencies, system tools, and GitHub-based tools
required by the Quiver hardware hacking command centre.

Usage:
    sudo python3 install.py           # full install
    python3 install.py --check        # dry-run, show what would be installed
    python3 install.py --skip-apt     # skip system package installs
    python3 install.py --skip-python  # skip pip installs
    python3 install.py --skip-git     # skip GitHub tool clones

Platform:
    macOS  — uses Homebrew (brew) for system packages
    Linux  — uses apt/apt-get for system packages
"""

import argparse
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path


# ─────────────────────────────────────────────────────────────────────────────
# Colour helpers
# ─────────────────────────────────────────────────────────────────────────────

RESET  = "\033[0m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
RED    = "\033[31m"
CYAN   = "\033[36m"
BOLD   = "\033[1m"

SYSTEM   = platform.system()   # 'Linux', 'Darwin', 'Windows'
IS_MACOS = SYSTEM == "Darwin"
IS_LINUX = SYSTEM == "Linux"


def _print(msg: str, colour: str = RESET) -> None:
    print(f"{colour}{msg}{RESET}", flush=True)


def ok(msg: str)   -> None: _print(f"[+] {msg}", GREEN)
def info(msg: str) -> None: _print(f"[*] {msg}", CYAN)
def warn(msg: str) -> None: _print(f"[~] {msg}", YELLOW)
def err(msg: str)  -> None: _print(f"[!] {msg}", RED)


def run_silent(cmd: list, *, timeout: int = 300,
               env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd, capture_output=True, text=True,
        timeout=timeout, env=env or os.environ.copy(),
    )


def which(name: str) -> str | None:
    return shutil.which(name)


# ─────────────────────────────────────────────────────────────────────────────
# Python packages (pip)
# ─────────────────────────────────────────────────────────────────────────────

PIP_PACKAGES: list[tuple[str, str]] = [
    # Flask web framework — Armin Ronacher @mitsuhiko (https://github.com/pallets/flask)
    ("flask>=3.0.0",          "Flask web framework — Quiver server"),
    # Flask-SocketIO — Miguel Grinberg @miguelgrinberg (https://github.com/miguelgrinberg/Flask-SocketIO)
    ("flask-socketio>=5.3.0", "WebSocket real-time events — Quiver UI"),
    # paramiko — Jeff Forcier @bitprophet (https://github.com/paramiko/paramiko)
    ("paramiko>=3.0.0",       "SSH shells for Hak5 network devices"),
    # pyserial — pyserial maintainers (https://github.com/pyserial/pyserial)
    ("pyserial>=3.5",         "Serial port detection and shells"),
    ("requests>=2.28.0",      "HTTP — reverse proxy and GitHub firmware checks"),
    ("pyusb>=1.2.1",          "USB presence detection via libusb"),
    # esptool — Fredrik Ahlberg @themadinventor + Espressif (https://github.com/espressif/esptool)
    ("esptool>=4.7.0",        "ESP32 firmware flashing"),
    ("mpremote>=1.22.0",      "MicroPython file transfer"),
    # pyflipper / flipperzero-protobuf — Flipper Devices Inc (https://github.com/flipperdevices)
    ("pyflipper>=0.2.0",      "Flipper Zero Python library"),
    ("flipperzero-protobuf>=0.8.0", "Flipper Zero protobuf definitions"),
    # pyhackrf — Michael Ossmann @mossmann (https://github.com/greatscottgadgets/hackrf)
    ("pyhackrf>=2024.2",      "HackRF One Python bindings"),
    # bellows / zigpy — zigpy project (https://github.com/zigpy/zigpy)
    ("bellows>=0.36.0",       "EZSP/Zigbee coordinator (Sonoff ZBDongle-E)"),
    ("zigpy>=0.60.0",         "Zigbee protocol stack"),
    ("universal-silabs-flasher>=0.0.17", "Silicon Labs firmware flasher"),
    # zigpy-znp — zigpy-znp contributors (https://github.com/zigpy/zigpy-znp)
    ("zigpy-znp>=0.11.0",     "ZNP/TI CC2652 Zigbee coordinator"),
    # cynthion / facedancer / apollo-fpga — Kate Temkin @ktemkin (https://github.com/greatscottgadgets/cynthion)
    ("cynthion>=1.0.0",       "Cynthion USB analysis platform"),
    ("apollo-fpga>=1.0.0",    "Apollo FPGA configuration tool"),
    ("facedancer>=3.1.2",     "Facedancer USB emulation library"),
    # greatfet — Great Scott Gadgets (https://github.com/greatscottgadgets/greatfet)
    ("greatfet>=2021.2.1",    "GreatFET hardware analysis library"),
    ("pyocd>=0.36.0",         "STM32 debug probe (ST-Link / Nucleo)"),
    ("pylink-square>=1.0.0",  "J-Link EDU Mini debug probe"),
    # scapy — Philippe Biondi @p-biondi (https://github.com/secdev/scapy)
    ("scapy>=2.5.0",          "PCAP parsing for Ubertooth One captures"),
    # websocket-client — websocket-client contributors (https://github.com/websocket-client/websocket-client)
    ("websocket-client>=1.6.0", "WebSocket relay for WiFi Duck"),
]


# ─────────────────────────────────────────────────────────────────────────────
# System packages
# ─────────────────────────────────────────────────────────────────────────────

APT_PACKAGES: list[tuple[str, str]] = [
    # HackRF — Michael Ossmann @mossmann (https://github.com/greatscottgadgets/hackrf)
    ("hackrf",          "HackRF system tools and udev rules"),
    # Ubertooth — Michael Ossmann @mossmann (https://github.com/greatscottgadgets/ubertooth)
    ("ubertooth",       "Ubertooth One Bluetooth sniffing tools"),
    ("stlink-tools",    "ST-Link V2 flash and debug utilities"),
    # Proxmark3 Iceman — iceman1001 @iceman1001 (https://github.com/RfidResearchGroup/proxmark3)
    ("proxmark3",       "Proxmark3 Iceman firmware and pm3 binary"),
    ("libusb-1.0-0-dev","libusb development headers for pyusb"),
    ("libusb-dev",      "libusb legacy headers"),
    ("git",             "Git version control — required for rfcat clone"),
    ("python3-pip",     "Python 3 pip package manager"),
    ("python3-dev",     "Python 3 headers"),
]

BREW_PACKAGES: list[tuple[str, str]] = [
    # HackRF — Michael Ossmann @mossmann (https://github.com/greatscottgadgets/hackrf)
    ("hackrf",          "HackRF system tools"),
    # Ubertooth — Michael Ossmann @mossmann (https://github.com/greatscottgadgets/ubertooth)
    ("ubertooth",       "Ubertooth One tools"),
    ("stlink",          "ST-Link flash and debug utilities"),
    # Proxmark3 Iceman — iceman1001 @iceman1001 (https://github.com/RfidResearchGroup/proxmark3)
    # NOTE: requires tap RfidResearchGroup/homebrew-proxmark3 (handled in stage_system)
    ("proxmark3",       "Proxmark3 Iceman tools"),
    ("libusb",          "libusb — required by pyusb"),
]

BREW_CASK_PACKAGES: list[tuple[str, str]] = [
    # SEGGER J-Link — https://www.segger.com/downloads/jlink/
    ("segger-jlink",    "SEGGER J-Link software suite (J-Link EDU Mini)"),
]


# ─────────────────────────────────────────────────────────────────────────────
# GitHub tools cloned to /opt/
# ─────────────────────────────────────────────────────────────────────────────

# (repo_url, local_path, pip_deps)
GIT_TOOLS: list[tuple[str, str, list[str]]] = [
    # rfcat — atlas0fd00m (https://github.com/atlas0fd00m/rfcat)
    # Yardstick One Python control library; PyPI version lags behind
    (
        "https://github.com/atlas0fd00m/rfcat.git",
        "/opt/rfcat",
        ["/opt/rfcat"],
    ),
    # ChameleonUltra — RRG/Iceman (https://github.com/RfidResearchGroup/ChameleonUltra)
    (
        "https://github.com/RfidResearchGroup/ChameleonUltra.git",
        "/opt/ChameleonUltra",
        [],
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _apt_cmd() -> str | None:
    return which("apt-get") or which("apt")


def _brew_cmd() -> str | None:
    return which("brew")


def require_root() -> None:
    if IS_LINUX and os.geteuid() != 0:
        err("On Linux this script must be run as root or via sudo.")
        err("    sudo python3 install.py")
        sys.exit(1)
    info("Privilege check passed.")


# ─────────────────────────────────────────────────────────────────────────────
# Stage: pip install
# ─────────────────────────────────────────────────────────────────────────────

def stage_pip(check_mode: bool = False) -> None:
    _print("\n" + "─" * 60, BOLD)
    _print("Stage: pip install (Python packages)", BOLD)
    _print("─" * 60, BOLD)
    for spec, desc in PIP_PACKAGES:
        if check_mode:
            info(f"  [check] would pip install: {spec}  — {desc}")
            continue
        info(f"pip install {spec}  — {desc}")
        cmd = [sys.executable, "-m", "pip", "install", "--quiet", "--break-system-packages", spec]
        r = run_silent(cmd)
        if r.returncode == 0:
            ok(f"  {spec} installed")
        else:
            warn(f"  {spec} failed: {r.stderr.strip()[:120]}")


# ─────────────────────────────────────────────────────────────────────────────
# Stage: system packages
# ─────────────────────────────────────────────────────────────────────────────

def stage_system(check_mode: bool = False) -> None:
    _print("\n" + "─" * 60, BOLD)
    _print("Stage: system packages", BOLD)
    _print("─" * 60, BOLD)

    if IS_LINUX:
        apt = _apt_cmd()
        if not apt:
            warn("apt/apt-get not found — skipping system packages.")
            return
        env = os.environ.copy()
        env["DEBIAN_FRONTEND"] = "noninteractive"
        if not check_mode:
            info("Running apt update ...")
            subprocess.run([apt, "update"], env=env, timeout=120)
        for pkg, desc in APT_PACKAGES:
            if check_mode:
                info(f"  [check] would apt install: {pkg}  — {desc}")
                continue
            info(f"apt install {pkg}  — {desc}")
            r = subprocess.run(
                [apt, "install", "-y", "-q", pkg,
                 "-o", "Dpkg::Options::=--force-confold"],
                env=env, timeout=120,
            )
            if r.returncode == 0:
                ok(f"  {pkg} installed")
            else:
                warn(f"  {pkg} install returned code {r.returncode}")

    elif IS_MACOS:
        brew = _brew_cmd()
        if not brew:
            warn("brew not found — install Homebrew first: https://brew.sh")
            return
        _brew_user = os.environ.get("SUDO_USER", "")
        _brew_pfx  = ["sudo", "-u", _brew_user] if _brew_user and _brew_user != "root" else []
        # proxmark3 requires the RfidResearchGroup tap
        if not check_mode:
            subprocess.run(_brew_pfx + [brew, "tap", "RfidResearchGroup/homebrew-proxmark3"],
                           timeout=120, check=False)
        for pkg, desc in BREW_PACKAGES:
            if check_mode:
                info(f"  [check] would brew install: {pkg}  — {desc}")
                continue
            info(f"brew install {pkg}  — {desc}")
            r = subprocess.run(_brew_pfx + [brew, "install", pkg], timeout=300)
            if r.returncode == 0:
                ok(f"  {pkg} installed")
            else:
                warn(f"  {pkg} brew install returned code {r.returncode}")
        for cask, desc in BREW_CASK_PACKAGES:
            if check_mode:
                info(f"  [check] would brew install --cask: {cask}  — {desc}")
                continue
            info(f"brew install --cask {cask}  — {desc}")
            r = subprocess.run(_brew_pfx + [brew, "install", "--cask", cask], timeout=300)
            if r.returncode == 0:
                ok(f"  {cask} installed")
            else:
                warn(f"  {cask} brew cask install returned code {r.returncode}")
    else:
        warn(f"Unsupported platform: {SYSTEM} — skipping system packages.")


# ─────────────────────────────────────────────────────────────────────────────
# Stage: git clone tools
# ─────────────────────────────────────────────────────────────────────────────

def stage_git(check_mode: bool = False) -> None:
    _print("\n" + "─" * 60, BOLD)
    _print("Stage: git clone / update tools", BOLD)
    _print("─" * 60, BOLD)
    for repo_url, local_path, pip_deps in GIT_TOOLS:
        tool_name = Path(local_path).name
        local = Path(local_path)
        if check_mode:
            action = "update" if local.exists() else "clone"
            info(f"  [check] would git {action}: {repo_url} → {local_path}")
            continue
        if local.exists():
            info(f"Updating {tool_name} ...")
            r = run_silent(["git", "-C", str(local), "pull", "--ff-only"])
            if r.returncode == 0:
                ok(f"  {tool_name} updated")
            else:
                warn(f"  git pull failed for {tool_name}: {r.stderr.strip()[:80]}")
        else:
            info(f"Cloning {tool_name} from {repo_url} → {local_path} ...")
            local.parent.mkdir(parents=True, exist_ok=True)
            r = run_silent(["git", "clone", "--depth=1", repo_url, str(local)])
            if r.returncode == 0:
                ok(f"  {tool_name} cloned to {local_path}")
            else:
                err(f"  git clone failed for {tool_name}: {r.stderr.strip()[:80]}")
                continue
        for dep in pip_deps:
            info(f"  pip install {dep} (dep for {tool_name})")
            cmd = [sys.executable, "-m", "pip", "install", "--quiet", "--break-system-packages", dep]
            run_silent(cmd)


# ─────────────────────────────────────────────────────────────────────────────
# Stage: verification summary
# ─────────────────────────────────────────────────────────────────────────────

_VERIFY_TOOLS = [
    "pm3", "rfcat", "hackrf_info", "ubertooth-util",
    "st-flash", "JLinkExe", "esptool",
]
_VERIFY_PYTHON = [
    ("flask",            "flask"),
    ("flask-socketio",   "flask_socketio"),
    ("paramiko",         "paramiko"),
    ("pyserial",         "serial"),
    ("pyusb",            "usb"),
    ("esptool",          "esptool"),
    ("pyhackrf",         "pyhackrf"),
    ("scapy",            "scapy"),
    ("websocket-client", "websocket"),
]


def print_summary() -> None:
    _print("\n" + "─" * 60, BOLD)
    _print("Post-install verification summary", BOLD)
    _print("─" * 60, BOLD)
    _print("\nSystem tools:", BOLD)
    for binary in _VERIFY_TOOLS:
        found = bool(which(binary))
        status = f"{GREEN}✓{RESET}" if found else f"{YELLOW}✗{RESET}"
        path = which(binary) or "(not found)"
        print(f"  {status}  {binary:<24} {path}")
    _print("\nPython packages:", BOLD)
    for pkg_name, module in _VERIFY_PYTHON:
        r = run_silent([sys.executable, "-c", f"import {module}"])
        found = r.returncode == 0
        status = f"{GREEN}✓{RESET}" if found else f"{YELLOW}✗{RESET}"
        print(f"  {status}  {pkg_name}")
    _print("\nQuiver run command:", BOLD)
    quiver_dir = Path(__file__).parent
    print(f"  cd {quiver_dir}")
    print(f"  python3 app.py")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# Stage: service installation
# ─────────────────────────────────────────────────────────────────────────────

def _install_service(check_mode: bool = False) -> None:
    """Install systemd (Linux) or launchd (macOS) service for boot-time autostart."""
    import shutil as _shutil
    app_dir = Path(__file__).parent.resolve()
    python_bin = _shutil.which("python3") or sys.executable
    main_script = str(app_dir / "app.py")
    APP_NAME = "quiver"
    DISPLAY  = "Quiver — Hardware Hacking Command Centre"
    PORT     = 5002

    if check_mode:
        info(f"[check] Would install service pr0t31n-{APP_NAME} (port {PORT})")
        return

    if IS_LINUX:
        service_name = f"pr0t31n-{APP_NAME}"
        svc_path = Path(f"/etc/systemd/system/{service_name}.service")
        svc_content = f"""[Unit]
Description={DISPLAY} (port {PORT})
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory={app_dir}
ExecStart={python_bin} {main_script}
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""
        try:
            svc_path.write_text(svc_content)
            subprocess.run(["systemctl", "daemon-reload"], check=False)
            subprocess.run(["systemctl", "enable", "--now", service_name], check=False)
            ok(f"Service {service_name} enabled and started  (port {PORT})")
        except PermissionError:
            warn("Cannot write to /etc/systemd — run as root to install service.")

    elif IS_MACOS:
        label = f"com.pr0t31n.{APP_NAME}"
        log_dir = Path("/var/log/pr0t31n")
        log_dir.mkdir(parents=True, exist_ok=True)
        plist_path = Path(f"/Library/LaunchDaemons/{label}.plist")
        plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{python_bin}</string>
        <string>{main_script}</string>
    </array>
    <key>WorkingDirectory</key>
    <string>{app_dir}</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/pr0t31n/{APP_NAME}.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/pr0t31n/{APP_NAME}.err</string>
</dict>
</plist>
"""
        try:
            plist_path.write_text(plist_content)
            subprocess.run(["launchctl", "load", "-w", str(plist_path)], check=False)
            ok(f"LaunchDaemon {label} loaded  (port {PORT})")
        except PermissionError:
            warn("Cannot write to /Library/LaunchDaemons — run as root to install service.")
    else:
        warn(f"Service installation not supported on {SYSTEM}.")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Quiver installer — Python deps, system tools, GitHub tools",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--skip-apt",     action="store_true",
                   help="Skip system package installs (apt/brew)")
    p.add_argument("--skip-python",  action="store_true",
                   help="Skip pip install stage")
    p.add_argument("--skip-git",     action="store_true",
                   help="Skip git clone/update stage")
    p.add_argument("--check",        action="store_true",
                   help="Dry run — show what would be installed")
    return p.parse_args()


def main() -> None:
    _print("=" * 60, BOLD)
    _print("  Quiver Installer", BOLD)
    _print(f"  Platform: {SYSTEM}", BOLD)
    _print("=" * 60, BOLD)

    args = parse_args()

    if IS_LINUX:
        require_root()

    if not args.skip_system:
        stage_system(check_mode=args.check)

    if not args.skip_python:
        stage_pip(check_mode=args.check)

    if not args.skip_git:
        stage_git(check_mode=args.check)

    _install_service(check_mode=args.check)

    if not args.check:
        print_summary()
    else:
        info("Check mode — no changes made.")


# Patch: argparse does not know --skip-system by the name above; alias it
import sys as _sys
_orig_parse = argparse.ArgumentParser.parse_args
def _patched_parse(self, *a, **kw):
    ns = _orig_parse(self, *a, **kw)
    if not hasattr(ns, "skip_system"):
        ns.skip_system = getattr(ns, "skip_apt", False)
    return ns
argparse.ArgumentParser.parse_args = _patched_parse  # type: ignore


if __name__ == "__main__":
    main()
