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
# pip pre-check
# ---------------------------------------------------------------------------
def _pip_installed(pkg_spec):
    import importlib.util
    name = pkg_spec.split(">=")[0].split("==")[0].split("[")[0].split("<")[0].strip()
    _IMPORT_MAP = {
        "flask-socketio": "flask_socketio",
        "flask-cors": "flask_cors",
        "flask-login": "flask_login",
        "python-engineio": "engineio",
        "python-socketio": "socketio",
        "python-dotenv": "dotenv",
        "pyyaml": "yaml",
        "pyserial": "serial",
        "pyusb": "usb",
        "websocket-client": "websocket",
        "pyflipper": "pyflipper",
        "flipperzero-protobuf": "flipperzero_protobuf",
        "pyhackrf": "pyhackrf",
        "zigpy-znp": "zigpy_znp",
        "universal-silabs-flasher": "universal_silabs_flasher",
        "apollo-fpga": "apollo_fpga",
        "pylink-square": "pylink",
        "pyocd": "pyocd",
    }
    mod = _IMPORT_MAP.get(name, name.replace("-", "_"))
    try:
        return importlib.util.find_spec(mod) is not None
    except (ModuleNotFoundError, ValueError):
        return False


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
    pip_cmd = [sys.executable, "-m", "pip"]
    for pkg in PIP_PACKAGES:
        if _pip_installed(pkg):
            info(f"  ✓ {pkg} already installed")
            continue
        info(f"pip install {pkg} …")
        try:
            run(pip_cmd + ["install", "--break-system-packages", pkg], check=False)
        except Exception as exc:
            warn(f"pip install failed for {pkg}: {exc}")

# ---------------------------------------------------------------------------
# System packages
# ---------------------------------------------------------------------------
APT_PACKAGES = [
    "hackrf", "ubertooth", "stlink-tools", "proxmark3",
    "libusb-1.0-0-dev", "libusb-dev",
    "git", "python3-pip", "python3-dev",
    "gcc-arm-none-eabi",   # build Sniffle firmware for CC1352P-4 (PLATFORM=CC1352P_4)
    "openocd",             # open-source XDS110 flasher for the TI LaunchPads
    "tshark", "wireshark-common",  # BLE capture (nRF Sniffer extcap) + pcap tooling
    "crackle",             # BLE legacy pairing PIN/TK cracker (Kali/Debian package)
    "libpcap-dev",         # crackle build dependency (git fallback)
]
DNF_PACKAGES = [
    "hackrf", "ubertooth", "stlink", "libusb-devel",
    "git", "python3-pip", "python3-devel",
    "arm-none-eabi-gcc-cs", "arm-none-eabi-newlib",  # CC1352P-4 Sniffle build
    "openocd",
    "wireshark-cli", "libpcap-devel",  # BLE capture + crackle build (git fallback)
]
ZYPPER_PACKAGES = [
    "hackrf", "ubertooth", "libusb-1_0-devel",
    "git", "python3-pip", "python3-devel",
    "cross-arm-none-eabi-gcc13", "cross-arm-none-eabi-newlib-devel",  # CC1352P-4 build
    "openocd",
    "wireshark", "libpcap-devel",  # BLE capture + crackle build (git fallback)
]
BREW_PACKAGES  = ["hackrf", "ubertooth", "stlink", "proxmark3", "libusb", "open-ocd",
                  "libpcap"]  # libpcap: crackle build dependency
BREW_CASKS     = ["segger-jlink", "gcc-arm-embedded",  # gcc-arm-embedded = arm-none-eabi-gcc
                  "wireshark"]  # BLE capture GUI + tshark (nRF Sniffer extcap)


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
    """The TI LaunchPads (CC1352P-4 / CC26X2R1) need TI UniFlash to flash — OpenOCD
    cannot drive their XDS110 cJTAG. Quiver now AUTO-INSTALLS UniFlash on demand."""
    banner("TI UniFlash — auto-installed by Quiver on first CC1352P-4 / CC26X2R1 flash")
    info("These LaunchPads flash over the onboard XDS110 using 2-pin cJTAG, which")
    info("only TI UniFlash's 'dslite' handles correctly (OpenOCD cannot).")
    info("  • Quiver downloads + installs UniFlash unattended the first time you flash")
    info(f"    a TI board (to /opt/ti/uniflash_*), then generates the target config and")
    info("    runs dslite for you — no TI account needed for the direct-download build.")
    info("  • Nothing to do here at install time; it happens on demand at flash time.")
    info("Firmware itself is auto-downloaded (prebuilt Sniffle hex). The TI SimpleLink")
    info("SDK is only needed to BUILD Sniffle from source (advanced).")

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

    # crackle — BLE legacy pairing PIN/TK cracker. Packaged on Kali/Debian (apt),
    # but build from source everywhere else so the nRF52840 pairing-crack flow
    # works regardless of distro. Non-fatal if the toolchain/libpcap is missing.
    if not shutil.which("crackle"):
        crackle_dest = "/opt/crackle"
        git_clone_or_update("https://github.com/mikeryan/crackle", crackle_dest)
        info("Building crackle …")
        b = run(["make", "-C", crackle_dest], check=False)
        built = os.path.join(crackle_dest, "crackle")
        if getattr(b, "returncode", 1) == 0 and os.path.isfile(built):
            run(["cp", built, "/usr/local/bin/crackle"], check=False)
            info("crackle built and installed to /usr/local/bin/crackle")
        else:
            warn("crackle build failed (libpcap-dev/toolchain missing?) — "
                 "repo left at /opt/crackle to build later.")
    else:
        info("crackle already present — skipping build.")

    # WHAD — BLE attack/MITM host framework (whad-team; drives the ButteRFly-
    # flashed nRF52840). Deliberately NOT installed into this shared interpreter:
    # WHAD is a Linux-side tool used by the nRF52840 BLE MITM workflow, and pulling
    # a large dependency set into the Flask interpreter risks breaking Quiver (cf.
    # the nrfutil/click incident). Install it on the operating host with:
    #     pip install whad         # host tools: wsniff, wanalyze, winstall
    #     winstall --flash butterfly   # flash whad-team ButteRFly to the DK
    info("WHAD (BLE MITM framework) is NOT auto-installed into Quiver's interpreter.")
    info("  On the sniffing host run:  pip install whad  &&  winstall --flash butterfly")

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
