#!/usr/bin/env python3
"""
Quiver — Pentest Hardware Manager
Install script
Location: /opt/pr0t31n/Quiver/
Service:  pr0t31n-quiver (port 5002)
"""

import argparse
import os
import platform
import shutil
import subprocess
import sys

# ---------------------------------------------------------------------------
# ANSI colours
# ---------------------------------------------------------------------------
R  = "\033[1;31m"
G  = "\033[1;32m"
Y  = "\033[1;33m"
B  = "\033[1;34m"
C  = "\033[1;36m"
W  = "\033[0m"

def banner(msg):  print(f"\n{B}{'='*60}{W}\n{C}  {msg}{W}\n{B}{'='*60}{W}")
def info(msg):    print(f"{G}[+]{W} {msg}")
def warn(msg):    print(f"{Y}[!]{W} {msg}")
def error(msg):   print(f"{R}[x]{W} {msg}")
def step(msg):    print(f"{B}[>]{W} {msg}")

# ---------------------------------------------------------------------------
# OS detection
# ---------------------------------------------------------------------------
def detect_os():
    system = platform.system()
    if system == "Darwin":
        return "macos"
    if system == "Windows":
        return "windows"
    # Linux — read /etc/os-release
    try:
        with open("/etc/os-release") as f:
            data = f.read().lower()
    except FileNotFoundError:
        return "linux-unknown"
    if "kali" in data or "debian" in data or "ubuntu" in data:
        return "apt"
    if "rhel" in data or "centos" in data or "rocky" in data or "fedora" in data:
        return "dnf"
    if "suse" in data or "opensuse" in data:
        return "zypper"
    return "linux-unknown"

OS = detect_os()

# ---------------------------------------------------------------------------
# Privilege helpers
# ---------------------------------------------------------------------------
def is_root():
    return os.getuid() == 0 if hasattr(os, "getuid") else False

def get_sudo_user():
    return os.environ.get("SUDO_USER", "")

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
def run(cmd, check=True, capture=False):
    step(" ".join(cmd) if isinstance(cmd, list) else cmd)
    kwargs = dict(check=check)
    if capture:
        kwargs["capture_output"] = True
        kwargs["text"] = True
    return subprocess.run(cmd, **kwargs)

# ---------------------------------------------------------------------------
# brew helper — NEVER run as root
# ---------------------------------------------------------------------------
def brew_install(pkg, cask=False):
    brew_path = shutil.which("brew")
    if not brew_path:
        # Try common locations
        for p in ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"]:
            if os.path.isfile(p):
                brew_path = p
                break
    if not brew_path:
        warn(f"brew not found — skipping {pkg}")
        return

    cmd = [brew_path, "install"]
    if cask:
        cmd = [brew_path, "install", "--cask"]
    cmd.append(pkg)

    if is_root():
        sudo_user = get_sudo_user()
        if not sudo_user:
            warn(f"Running as root with no SUDO_USER — cannot run brew safely. Skipping {pkg}.")
            return
        cmd = ["sudo", "-u", sudo_user] + cmd

    run(cmd, check=False)

# ---------------------------------------------------------------------------
# Package managers
# ---------------------------------------------------------------------------
_apt_updated = False

def apt_install(packages):
    global _apt_updated
    if not _apt_updated:
        info("Running apt update + apt upgrade …")
        run(["apt-get", "update", "-y"])
        run(["apt-get", "upgrade", "-y"])
        _apt_updated = True
    run(["apt-get", "install", "-y"] + packages)

def dnf_install(packages):
    run(["dnf", "install", "-y"] + packages)

def zypper_install(packages):
    run(["zypper", "install", "-y"] + packages)

# ---------------------------------------------------------------------------
# pip
# ---------------------------------------------------------------------------
PIP_PACKAGES = [
    "flask>=3.0.0",
    "flask-socketio>=5.3.0",
    "paramiko>=3.0.0",
    "pyserial>=3.5",
    "requests>=2.28.0",
    "pyusb>=1.2.1",
    "esptool>=4.7.0",
    "mpremote>=1.22.0",
    "pyflipper>=0.2.0",
    "flipperzero-protobuf>=0.8.0",
    "pyhackrf>=2024.2",
    "bellows>=0.36.0",
    "zigpy>=0.60.0",
    "universal-silabs-flasher>=0.0.17",
    "zigpy-znp>=0.11.0",
    "cynthion>=1.0.0",
    "apollo-fpga>=1.0.0",
    "facedancer>=3.1.2",
    "greatfet>=2021.2.1",
    "pyocd>=0.36.0",
    "pylink-square>=1.0.0",
    "scapy>=2.5.0",
    "websocket-client>=1.6.0",
    "eventlet>=0.35.0",
]

def install_pip():
    banner("Phase: pip packages")
    run([sys.executable, "-m", "pip", "install", "--break-system-packages"] + PIP_PACKAGES, check=False)

# ---------------------------------------------------------------------------
# System packages
# ---------------------------------------------------------------------------
APT_PACKAGES = [
    "hackrf", "ubertooth", "stlink-tools", "proxmark3",
    "libusb-1.0-0-dev", "libusb-dev",
    "git", "python3-pip", "python3-dev",
    "gcc-arm-none-eabi",   # build Sniffle firmware for CC1352P-4 (PLATFORM=CC1352P_4)
    "openocd",             # open-source XDS110 flasher for the TI LaunchPads
]
DNF_PACKAGES = [
    "hackrf", "ubertooth", "stlink", "libusb-devel",
    "git", "python3-pip", "python3-devel",
    "arm-none-eabi-gcc-cs", "arm-none-eabi-newlib",  # CC1352P-4 Sniffle build
    "openocd",
]
ZYPPER_PACKAGES = [
    "hackrf", "ubertooth", "libusb-1_0-devel",
    "git", "python3-pip", "python3-devel",
    "cross-arm-none-eabi-gcc13", "cross-arm-none-eabi-newlib-devel",  # CC1352P-4 build
    "openocd",
]
BREW_PACKAGES  = ["hackrf", "ubertooth", "stlink", "proxmark3", "libusb", "open-ocd"]
BREW_CASKS     = ["segger-jlink", "gcc-arm-embedded"]  # gcc-arm-embedded = arm-none-eabi-gcc


def ensure_homebrew():
    """Install Homebrew on macOS if it is missing (needed for brew_install)."""
    if shutil.which("brew"):
        return
    for p in ("/opt/homebrew/bin/brew", "/usr/local/bin/brew"):
        if os.path.exists(p):
            return
    warn("Homebrew not found — installing it (needed for the board toolchains)…")
    installer = (
        '/bin/bash -c "$(curl -fsSL '
        'https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"'
    )
    env = dict(os.environ, NONINTERACTIVE="1")
    try:
        subprocess.run(installer, shell=True, env=env, check=False)
    except Exception as e:
        warn(f"Homebrew install failed ({e}). Install it manually: https://brew.sh")


def print_ti_toolchain_notice():
    """Flashing is handled by OpenOCD (auto-installed). Only the CC1352P-4 *build*
    still needs the TI SDK, which is login-gated — print guidance for that."""
    banner("TI CC1352P-4 build dependency — manual, one-time")
    info("Flashing is handled by OpenOCD (installed above) — no TI login needed.")
    info("The one thing that CANNOT be auto-installed (requires a TI account/login):")
    info("  • TI SimpleLink CC13xx/CC26xx SDK — ONLY needed to BUILD the CC1352P-4 hex")
    info("    https://www.ti.com/tool/SIMPLELINK-LOWPOWER-F2-SDK")
    info("    After install:  export SIMPLELINK_SDK=/path/to/simplelink_cc13xx_cc26xx_sdk_x")
    info("Note: the CC26X2R1 needs NONE of this — Quiver downloads its prebuilt hex and")
    info("      OpenOCD flashes it. It is the turnkey board (no build, no TI login).")
    info("Optional: TI UniFlash (dslite) still works as a fallback flasher if present.")

def install_system():
    banner("Phase: system packages")
    if OS == "apt":
        apt_install(APT_PACKAGES)
    elif OS == "dnf":
        dnf_install(DNF_PACKAGES)
    elif OS == "zypper":
        zypper_install(ZYPPER_PACKAGES)
    elif OS == "macos":
        ensure_homebrew()
        for pkg in BREW_PACKAGES:
            brew_install(pkg)
        for cask in BREW_CASKS:
            brew_install(cask, cask=True)
    elif OS == "windows":
        warn("Windows detected — system package installation not supported. Install tools manually.")
    else:
        warn(f"Unknown OS '{OS}' — skipping system packages.")
    print_ti_toolchain_notice()

# ---------------------------------------------------------------------------
# Go (not needed for Quiver but kept as phase for consistency)
# ---------------------------------------------------------------------------
def install_go():
    banner("Phase: go tools")
    info("No Go tools required for Quiver — phase complete.")

# ---------------------------------------------------------------------------
# Git tools
# ---------------------------------------------------------------------------
def git_clone_or_update(url, dest):
    if os.path.isdir(dest):
        info(f"Updating existing clone: {dest}")
        run(["git", "-C", dest, "pull", "--ff-only"], check=False)
    else:
        run(["git", "clone", url, dest])

def install_git():
    banner("Phase: git tools")

    # rfcat
    rfcat_dest = "/opt/rfcat"
    git_clone_or_update("https://github.com/atlas0fd00m/rfcat", rfcat_dest)
    info("Installing rfcat via pip …")
    run([sys.executable, "-m", "pip", "install", "--break-system-packages", rfcat_dest], check=False)

    # ChameleonUltra firmware tools (no build step)
    chameleon_dest = "/opt/ChameleonUltra"
    git_clone_or_update("https://github.com/RfidResearchGroup/ChameleonUltra", chameleon_dest)
    info("ChameleonUltra cloned — no build step required.")

# ---------------------------------------------------------------------------
# Service files
# ---------------------------------------------------------------------------
APP_DIR  = "/opt/pr0t31n/Quiver"
APP_FILE = f"{APP_DIR}/app.py"
SVC_NAME = "pr0t31n-quiver"
PORT     = 5002

SYSTEMD_UNIT = f"""\
[Unit]
Description=Quiver — Pentest Hardware Manager
After=network.target

[Service]
Type=simple
WorkingDirectory={APP_DIR}
ExecStart={sys.executable} {APP_FILE}
Restart=on-failure
RestartSec=5
Environment=FLASK_ENV=production
Environment=PORT={PORT}

[Install]
WantedBy=multi-user.target
"""

LAUNCHD_PLIST = f"""\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.pr0t31n.quiver</string>
    <key>ProgramArguments</key>
    <array>
        <string>{sys.executable}</string>
        <string>{APP_FILE}</string>
    </array>
    <key>WorkingDirectory</key>
    <string>{APP_DIR}</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PORT</key>
        <string>{PORT}</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/pr0t31n-quiver.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/pr0t31n-quiver.err</string>
</dict>
</plist>
"""

def install_service():
    banner("Service file installation")
    if OS in ("apt", "dnf", "zypper", "linux-unknown"):
        path = f"/etc/systemd/system/{SVC_NAME}.service"
        try:
            with open(path, "w") as f:
                f.write(SYSTEMD_UNIT)
            info(f"Wrote {path}")
            run(["systemctl", "daemon-reload"])
            run(["systemctl", "enable", SVC_NAME])
            info(f"Service {SVC_NAME} enabled.")
            info(f"Start with: systemctl start {SVC_NAME}")
        except PermissionError:
            warn("Not root — cannot write systemd unit. Run as root to install service.")
    elif OS == "macos":
        path = "/Library/LaunchDaemons/com.pr0t31n.quiver.plist"
        try:
            with open(path, "w") as f:
                f.write(LAUNCHD_PLIST)
            info(f"Wrote {path}")
            run(["launchctl", "load", path], check=False)
            info(f"LaunchDaemon loaded.")
            info(f"Start with: launchctl start com.pr0t31n.quiver")
        except PermissionError:
            warn("Not root — cannot write LaunchDaemon plist. Run as root to install service.")
    else:
        warn("Service installation not supported on this OS.")

# ---------------------------------------------------------------------------
# Check / verify
# ---------------------------------------------------------------------------
VERIFY_TOOLS   = ["pm3", "hackrf_info", "ubertooth-util", "st-flash"]
VERIFY_PYTHON  = ["flask", "flask_socketio", "paramiko", "serial", "usb", "esptool", "scapy", "websocket"]

def run_check():
    banner("Post-install verification")
    print(f"\n{C}Binary tools:{W}")
    for tool in VERIFY_TOOLS:
        found = shutil.which(tool)
        if found:
            info(f"{tool:30s} {G}FOUND{W} ({found})")
        else:
            warn(f"{tool:30s} {Y}NOT FOUND{W}")

    print(f"\n{C}Python imports:{W}")
    for pkg in VERIFY_PYTHON:
        try:
            __import__(pkg)
            info(f"{pkg:30s} {G}OK{W}")
        except ImportError:
            warn(f"{pkg:30s} {Y}MISSING{W}")

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
def print_summary(skips):
    banner("Post-install summary")
    info(f"Application : Quiver — Pentest Hardware Manager")
    info(f"Location    : {APP_DIR}")
    info(f"Service     : {SVC_NAME}  (port {PORT})")
    info(f"OS detected : {OS}")
    print()
    phases = ["system", "pip", "go", "git"]
    for p in phases:
        status = f"{Y}SKIPPED{W}" if p in skips else f"{G}DONE{W}"
        print(f"  {p:10s} {status}")
    print()
    if OS in ("apt", "dnf", "zypper", "linux-unknown"):
        info(f"Manage service : systemctl {{start|stop|status}} {SVC_NAME}")
    elif OS == "macos":
        info(f"Manage service : launchctl {{start|stop}} com.pr0t31n.quiver")
    warn("Aether/wireless tools are NOT required for Quiver.")
    warn("Ensure /opt/pr0t31n/Quiver/app.py exists before starting the service.")

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Quiver installer")
    parser.add_argument("--skip-apt",    "--skip-system", dest="skip_system", action="store_true")
    parser.add_argument("--skip-pip",    action="store_true")
    parser.add_argument("--skip-go",     action="store_true")
    parser.add_argument("--skip-git",    action="store_true")
    parser.add_argument("--check",       action="store_true", help="Verify installation only")
    args = parser.parse_args()

    banner("Quiver — Pentest Hardware Manager — Installer")
    info(f"Detected OS : {OS}")
    info(f"Python      : {sys.executable}")

    if args.check:
        run_check()
        return

    if OS == "windows":
        warn("Windows support is limited. Only pip packages will be installed.")

    skips = set()

    if not args.skip_system:
        install_system()
    else:
        skips.add("system"); warn("Skipping system packages.")

    if not args.skip_pip:
        install_pip()
    else:
        skips.add("pip"); warn("Skipping pip packages.")

    if not args.skip_go:
        install_go()
    else:
        skips.add("go"); warn("Skipping go tools.")

    if not args.skip_git:
        install_git()
    else:
        skips.add("git"); warn("Skipping git tools.")

    install_service()
    run_check()
    print_summary(skips)

if __name__ == "__main__":
    main()
