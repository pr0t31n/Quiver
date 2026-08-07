#!/usr/bin/env python3
"""
Shared utilities for Quiver tool management scripts.
"""

import json
import os
import sys
import time
import platform
import subprocess
import socket
import re
import textwrap
from pathlib import Path
from typing import Optional

try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False


# ── PATH augmentation ─────────────────────────────────────────────────────────
# Quiver often runs as a root launchd/systemd service, whose PATH is minimal
# (/usr/bin:/bin:/usr/sbin:/sbin) and excludes Homebrew / local install dirs.
# Tools installed there (arm-none-eabi-gcc, dslite, brew, openocd, …) are then
# invisible to `which` and to child processes like `make`. Append the standard
# local tool dirs so they are discoverable for this process and everything it
# spawns. Append (not prepend) so system tools keep priority.
def _augment_path() -> None:
    extra = [
        "/opt/homebrew/bin", "/opt/homebrew/sbin",   # Apple-Silicon Homebrew
        "/usr/local/bin", "/usr/local/sbin",          # Intel Homebrew / local
        "/opt/ti/uniflash/dslite",                    # common TI UniFlash dir
    ]
    cur = os.environ.get("PATH", "").split(os.pathsep)
    added = [d for d in extra if os.path.isdir(d) and d not in cur]
    if added:
        os.environ["PATH"] = os.pathsep.join(cur + added)


_augment_path()


# ── Web mode flag ─────────────────────────────────────────────────────────────
# When QUIVER_WEB_MODE=1 the script is driven by the Flask app over stdin/stdout.
# Log functions emit  LOG:{json}   lines.
# Interactive functions emit  PROMPT:{json}  then block reading one JSON line.

WEB_MODE: bool = os.environ.get("QUIVER_WEB_MODE", "") == "1"

# ── Sudo credential store ──────────────────────────────────────────────────────
# Populated by require_sudo(); consumed by sudo_run() / run_streaming_sudo().

_SUDO_PASS: Optional[str] = None


def _web_log(level: str, text: str):
    print(f"LOG:{json.dumps({'level': level, 'text': text})}", flush=True)


def _web_prompt(payload: dict) -> str:
    """Emit a PROMPT line and block until the Flask app writes back a JSON answer."""
    print(f"PROMPT:{json.dumps(payload)}", flush=True)
    raw = sys.stdin.readline()
    try:
        return json.loads(raw.strip()).get("value", "")
    except Exception:
        return raw.strip()


# ── Terminal colours ──────────────────────────────────────────────────────────

RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[31m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
WHITE  = "\033[37m"


def c(text: str, colour: str) -> str:
    return f"{colour}{text}{RESET}"


def ok(msg: str):
    if WEB_MODE:
        _web_log("ok", msg)
    else:
        print(f"  {c('✔', GREEN)}  {msg}")


def warn(msg: str):
    if WEB_MODE:
        _web_log("warn", msg)
    else:
        print(f"  {c('!', YELLOW)}  {msg}")


def err(msg: str):
    if WEB_MODE:
        _web_log("err", msg)
    else:
        print(f"  {c('✘', RED)}  {msg}", file=sys.stderr)


def info(msg: str):
    if WEB_MODE:
        _web_log("info", msg)
    else:
        print(f"  {c('·', CYAN)}  {msg}")


def heading(msg: str):
    if WEB_MODE:
        _web_log("heading", msg)
    else:
        bar = "─" * (len(msg) + 4)
        print(f"\n{c(bar, BOLD)}")
        print(f"{c('  ' + msg, BOLD)}")
        print(f"{c(bar, BOLD)}\n")


def print_banner(tool_name: str, description: str):
    if WEB_MODE:
        _web_log("banner", f"{tool_name} — {description}")
    else:
        width = 60
        border = "═" * width
        print(f"\n{c(border, CYAN)}")
        print(f"{c('  QUIVER', BOLD)}")
        print(f"  {c(tool_name, YELLOW)}")
        print(f"  {description}")
        print(f"{c(border, CYAN)}\n")


# ── User interaction ──────────────────────────────────────────────────────────

def confirm(prompt_text: str, default: bool = True) -> bool:
    if WEB_MODE:
        ans = _web_prompt({"type": "confirm", "question": prompt_text, "default": default})
        return ans.lower() in ("y", "yes", "true", "1") if ans else default
    hint = "[Y/n]" if default else "[y/N]"
    while True:
        resp = input(f"  {prompt_text} {hint} ").strip().lower()
        if resp in ("", "y", "yes"):
            return True if (resp in ("y", "yes") or default) else False
        if resp in ("n", "no"):
            return False
        print("  Please answer y or n.")


_PASSWORD_KEYWORDS = ("password", "passwd", "passphrase", "secret", "pass")


def _is_password_prompt(msg: str) -> bool:
    """Return True if the prompt message is asking for a password."""
    lower = msg.lower()
    return any(kw in lower for kw in _PASSWORD_KEYWORDS)


def prompt(msg: str, default: str = "") -> str:
    if WEB_MODE:
        ptype = "password" if _is_password_prompt(msg) else "text"
        ans = _web_prompt({"type": ptype, "question": msg, "default": default})
        return ans if ans else default
    # Terminal mode: use getpass for passwords so the input is not echoed
    if _is_password_prompt(msg):
        import getpass
        hint = f" [{default}]" if default else ""
        try:
            val = getpass.getpass(f"  {msg}{hint}: ")
        except (EOFError, KeyboardInterrupt):
            val = ""
        return val if val else default
    hint = f" [{default}]" if default else ""
    val = input(f"  {msg}{hint}: ").strip()
    return val if val else default


def prompt_password(question: str) -> str:
    """Prompt for a password — masked in both web UI and terminal."""
    if WEB_MODE:
        return _web_prompt({"type": "password", "question": question})
    import getpass
    try:
        return getpass.getpass(f"  {question}: ")
    except (EOFError, KeyboardInterrupt):
        print()
        return ""


def pause(msg: str = "Press ENTER to continue…"):
    if WEB_MODE:
        _web_prompt({"type": "pause", "question": msg})
        return
    input(f"\n  {c(msg, YELLOW)}\n")


def wait_start(text: str):
    """Show waiting modal in web mode; print instructions in terminal mode."""
    if WEB_MODE:
        _web_log("wait_start", text)
    else:
        print(text)


def wait_status(text: str):
    """Update waiting modal status line (web) or emit info line (terminal)."""
    if WEB_MODE:
        _web_log("wait_status", text)
    else:
        info(text)


def wait_done(text: str = ""):
    """Close waiting modal on success (web) or log ok (terminal)."""
    if WEB_MODE:
        _web_log("wait_done", text or "Done")
    elif text:
        ok(text)


def wait_timeout(text: str = ""):
    """Close waiting modal on timeout (web) or log warn (terminal)."""
    if WEB_MODE:
        _web_log("wait_timeout", text or "Timed out")
    elif text:
        warn(text)


def numbered_menu(title: str, options: list[str]) -> int:
    """Display a numbered menu; returns 0-based index of chosen option."""
    if WEB_MODE:
        ans = _web_prompt({"type": "menu", "question": title, "options": options})
        try:
            return int(ans)
        except Exception:
            return 0
    print(f"\n  {c(title, BOLD)}")
    for i, opt in enumerate(options, 1):
        print(f"    {c(str(i), CYAN)}.  {opt}")
    while True:
        raw = input(f"\n  Select [1-{len(options)}]: ").strip()
        if raw.isdigit():
            n = int(raw)
            if 1 <= n <= len(options):
                return n - 1
        print(f"  Invalid choice; enter a number between 1 and {len(options)}.")


# ── Platform helpers ──────────────────────────────────────────────────────────

def get_os() -> str:
    """Return 'macos', 'linux', or 'windows'."""
    s = platform.system().lower()
    if s == "darwin":
        return "macos"
    if s == "linux":
        return "linux"
    return "windows"


def get_os_flavor() -> str:
    """
    Return a more specific OS flavor: 'kali', 'debian', 'ubuntu', 'arch',
    'fedora', 'macos', 'linux', or 'windows'.
    """
    if platform.system().lower() == "darwin":
        return "macos"
    if platform.system().lower() != "linux":
        return "windows"
    try:
        with open("/etc/os-release") as f:
            content = f.read().lower()
        if "kali" in content:
            return "kali"
        if "debian" in content:
            return "debian"
        if "ubuntu" in content:
            return "ubuntu"
        if "arch" in content:
            return "arch"
        if "fedora" in content or "rhel" in content or "centos" in content:
            return "fedora"
    except FileNotFoundError:
        pass
    return "linux"


def run(cmd: str, capture: bool = True, check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd, shell=True, capture_output=capture,
        text=True, check=check
    )


def run_output(cmd: str) -> str:
    result = run(cmd, capture=True)
    return result.stdout.strip() if result.returncode == 0 else ""


# ── Sudo helpers ───────────────────────────────────────────────────────────────

def _set_sudo_pass(pwd: str) -> None:
    global _SUDO_PASS
    _SUDO_PASS = pwd


def require_sudo() -> None:
    """
    Ensure this process has or can obtain root/sudo privileges.

    • Already root (uid 0): returns immediately.
    • Web mode non-root: prompts for the sudo password via the masked modal,
      validates it with ``sudo -S -k true``, then stores it for subsequent
      sudo_run() / run_streaming_sudo() calls.
    • Terminal mode non-root: checks if credentials are cached (``sudo -n``),
      then prompts via getpass if needed.

    Exits the process with code 1 if sudo cannot be obtained after 3 attempts.
    """
    if os.name != "posix":
        return  # Windows — skip privilege checks
    if os.getuid() == 0:
        return  # Already root

    if WEB_MODE:
        info("Root privileges required. Enter the sudo password to continue.")
        for attempt in range(3):
            pwd = prompt_password(f"sudo password (attempt {attempt + 1}/3)")
            if not pwd:
                err("No sudo password provided.")
                sys.exit(1)
            result = subprocess.run(
                ["sudo", "-S", "-k", "true"],
                input=pwd + "\n",
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                _set_sudo_pass(pwd)
                ok("Sudo authentication successful.")
                return
            err(f"Incorrect sudo password (attempt {attempt + 1}/3).")
        err("Sudo authentication failed after 3 attempts. Exiting.")
        sys.exit(1)
    else:
        # Check if credentials are already cached
        if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode == 0:
            return
        import getpass
        for attempt in range(3):
            try:
                pwd = getpass.getpass(f"  [sudo] password (attempt {attempt + 1}/3): ")
            except (EOFError, KeyboardInterrupt):
                print()
                err("Sudo prompt cancelled.")
                sys.exit(1)
            result = subprocess.run(
                ["sudo", "-S", "-k", "true"],
                input=pwd + "\n",
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                _set_sudo_pass(pwd)
                ok("Sudo authentication successful.")
                return
            err(f"Incorrect password (attempt {attempt + 1}/3).")
        err("Sudo authentication failed. Exiting.")
        sys.exit(1)


def sudo_run(cmd: str, capture: bool = True) -> subprocess.CompletedProcess:
    """
    Run a shell command string with sudo.
    Uses stored sudo password (via ``sudo -S``) if available; falls back to
    plain ``sudo`` (TTY-cached credentials) when not root.
    """
    if os.name != "posix" or os.getuid() == 0:
        return run(cmd, capture=capture)
    if _SUDO_PASS:
        return subprocess.run(
            ["sudo", "-S", "bash", "-c", cmd],
            input=_SUDO_PASS + "\n",
            capture_output=capture,
            text=True,
        )
    return run(f"sudo bash -c {repr(cmd)}", capture=capture)


def sudo_output(cmd: str) -> str:
    """Run a shell command with sudo; return stripped stdout or ''."""
    r = sudo_run(cmd)
    return r.stdout.strip() if r.returncode == 0 else ""


def run_streaming_sudo(cmd: list, on_line, timeout: int = 300) -> int:
    """
    Like run_streaming() but prepends sudo and feeds the stored password via
    stdin (``sudo -S``).  Falls back to run_streaming() when already root.
    """
    if os.name != "posix" or os.getuid() == 0:
        return run_streaming(cmd, on_line, timeout)
    full_cmd = ["sudo", "-S"] + cmd
    inp = (_SUDO_PASS + "\n") if _SUDO_PASS else None
    proc = subprocess.Popen(
        full_cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    if inp:
        try:
            proc.stdin.write(inp)
            proc.stdin.flush()
        except BrokenPipeError:
            pass
    proc.stdin.close()
    try:
        for line in proc.stdout:
            stripped = line.rstrip()
            if stripped and not stripped.startswith("[sudo]"):
                on_line(stripped)
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
    return proc.returncode


# ── USB device detection ──────────────────────────────────────────────────────

def detect_usb_device(vid: str, pid: Optional[str] = None) -> bool:
    """
    Check if a USB device with the given VID (and optionally PID) is attached.
    vid/pid: hex strings like '0BDA' or '8152' (case-insensitive, no 0x prefix).
    """
    os_name = get_os()
    vid = vid.upper().replace("0X", "")
    if pid:
        pid = pid.upper().replace("0X", "")

    if os_name == "macos":
        out = run_output("system_profiler SPUSBDataType 2>/dev/null")
        # system_profiler prints "Vendor ID: 0xXXXX" and "Product ID: 0xXXXX"
        vid_pattern = rf"Vendor ID:\s+0x{vid}"
        if not re.search(vid_pattern, out, re.IGNORECASE):
            return False
        if pid:
            pid_pattern = rf"Product ID:\s+0x{pid}"
            # We need to check they appear together in the same USB device block
            # Approximate: look for the pid after the vid within 500 chars
            match = re.search(vid_pattern, out, re.IGNORECASE)
            if match:
                segment = out[match.start():match.start() + 800]
                if not re.search(pid_pattern, segment, re.IGNORECASE):
                    return False
        return True

    elif os_name == "linux":
        out = run_output("lsusb 2>/dev/null")
        if pid:
            pattern = rf"{vid}:{pid}"
        else:
            pattern = rf"{vid}:"
        return bool(re.search(pattern, out, re.IGNORECASE))

    else:
        warn("USB detection not implemented on Windows; check manually.")
        return False


def find_usb_serial(vid: str, pid: str) -> Optional[str]:
    """
    Find the /dev/tty* device for a USB serial adapter.
    Returns device path or None.
    """
    os_name = get_os()
    if os_name == "macos":
        import glob
        # Try common patterns
        for pat in ["/dev/tty.usbserial-*", "/dev/tty.SLAB_USBtoUART*", "/dev/tty.usbmodem*"]:
            matches = glob.glob(pat)
            if matches:
                return matches[0]
    elif os_name == "linux":
        import glob
        for pat in ["/dev/ttyUSB*", "/dev/ttyACM*"]:
            matches = glob.glob(pat)
            if matches:
                return matches[0]
    return None


def find_mounted_drive(label: str) -> Optional[Path]:
    """Find a mounted drive by volume label. Returns mount path or None."""
    os_name = get_os()
    if os_name == "macos":
        p = Path(f"/Volumes/{label}")
        if p.exists():
            return p
        # Try case-insensitive
        try:
            for entry in Path("/Volumes").iterdir():
                if entry.name.upper() == label.upper():
                    return entry
        except Exception:
            pass
    elif os_name == "linux":
        # Check /media/user/<label> or /run/media/user/<label>
        user = os.environ.get("USER", "")
        for base in [f"/media/{user}", f"/run/media/{user}", "/media"]:
            p = Path(base) / label
            if p.exists():
                return p
    return None


# ── Network utilities ─────────────────────────────────────────────────────────

def ping(host: str, count: int = 1, timeout: int = 2) -> bool:
    """Return True if host responds to ping."""
    os_name = get_os()
    if os_name in ("macos", "linux"):
        cmd = f"ping -c {count} -W {timeout * 1000 if os_name == 'linux' else timeout} {host}"
    else:
        cmd = f"ping -n {count} -w {timeout * 1000} {host}"
    result = run(cmd)
    return result.returncode == 0


def wait_for_ping(host: str, timeout: int = 120, interval: int = 5) -> bool:
    """Wait until host responds to ping (up to timeout seconds)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if ping(host):
            return True
        time.sleep(interval)
    return False


def get_internet_interface() -> Optional[str]:
    """Return the name of the primary internet-facing network interface."""
    os_name = get_os()
    if os_name == "macos":
        out = run_output("route -n get default 2>/dev/null")
        m = re.search(r"interface:\s+(\S+)", out)
        return m.group(1) if m else None
    elif os_name == "linux":
        out = run_output("ip route show default 2>/dev/null")
        m = re.search(r"dev\s+(\S+)", out)
        return m.group(1) if m else None
    return None


def get_interface_for_ip(target_ip: str) -> Optional[str]:
    """Find the local interface that would route to target_ip."""
    os_name = get_os()
    if os_name == "macos":
        out = run_output(f"route -n get {target_ip} 2>/dev/null")
        m = re.search(r"interface:\s+(\S+)", out)
        return m.group(1) if m else None
    elif os_name == "linux":
        out = run_output(f"ip route get {target_ip} 2>/dev/null")
        m = re.search(r"dev\s+(\S+)", out)
        return m.group(1) if m else None
    return None


def assign_static_ip_macos(iface: str, ip: str, mask: str = "255.255.255.0"):
    """Assign a static IP to a macOS network interface."""
    run(f"sudo networksetup -setmanual '{iface}' {ip} {mask}", capture=False)


def assign_dhcp_macos(iface: str):
    """Restore DHCP on a macOS network interface."""
    run(f"sudo networksetup -setdhcp '{iface}'", capture=False)


def get_macos_service_for_iface(iface: str) -> Optional[str]:
    """Get the NetworkSetup service name for a given interface (e.g. en3)."""
    out = run_output("networksetup -listallhardwareports")
    # Output format: Hardware Port: ...\n Device: en3\n ...
    blocks = re.split(r"\n(?=Hardware Port)", out)
    for block in blocks:
        if re.search(rf"Device:\s+{re.escape(iface)}", block):
            m = re.search(r"Hardware Port:\s+(.+)", block)
            if m:
                return m.group(1).strip()
    return None


# ── Internet Connection Sharing ───────────────────────────────────────────────

_ICS_RULES_FILE = Path("/tmp/quiver_ics_rules.bak")


def enable_ics_linux(internet_if: str, device_if: str):
    """Enable NAT internet sharing from internet_if to device_if."""
    info(f"Enabling IP forwarding and NAT: {internet_if} → {device_if}")
    cmds = [
        "sudo sysctl -w net.ipv4.ip_forward=1",
        f"sudo iptables -t nat -A POSTROUTING -o {internet_if} -j MASQUERADE",
        f"sudo iptables -A FORWARD -i {device_if} -o {internet_if} -j ACCEPT",
        f"sudo iptables -A FORWARD -i {internet_if} -o {device_if} -m state --state ESTABLISHED,RELATED -j ACCEPT",
    ]
    for cmd in cmds:
        r = run(cmd)
        if r.returncode != 0:
            warn(f"Command returned error: {cmd}")
    # Save current iptables for cleanup
    run(f"sudo iptables-save > {_ICS_RULES_FILE}")


def disable_ics_linux():
    """Remove NAT rules saved during enable_ics_linux."""
    if _ICS_RULES_FILE.exists():
        info("Reverting iptables rules…")
        run(f"sudo iptables-restore < {_ICS_RULES_FILE}")
        _ICS_RULES_FILE.unlink(missing_ok=True)
    run("sudo sysctl -w net.ipv4.ip_forward=0")


def enable_ics_macos(device_service: str) -> bool:
    """
    Enable Internet Sharing on macOS via pfctl NAT.
    Returns True on success.
    """
    info("Configuring macOS Internet Sharing via PF NAT…")

    internet_if = get_internet_interface()
    info(f"Internet-facing interface: {internet_if or '(not detected)'}")
    if not internet_if:
        warn("Cannot determine internet interface — run 'route -n get default' to diagnose")
        return False

    # Look for the device interface using the correct BB subnet IP
    device_if = get_interface_for_ip("172.16.64.1")
    info(f"BB host interface (route to 172.16.64.1): {device_if or '(not found)'}")

    if not device_if:
        warn("No interface routes to 172.16.64.1 — PF NAT cannot be auto-configured")
        info("Manual steps to enable Internet Sharing on macOS:")
        print("    1. Open System Settings → General → Sharing")
        print("    2. Enable 'Internet Sharing'")
        print(f"   3. Share from: {internet_if}")
        print(f"   4. To computers using: {device_service or 'RNDIS/Ethernet Gadget'}")
        pause("Once Internet Sharing is enabled, press ENTER to continue…")
        return True

    info(f"Writing PF rules: {device_if} → {internet_if}")
    pf_rules = (
        f"nat on {internet_if} from {device_if}:network to any -> ({internet_if})\n"
        f"pass in  quick on {device_if}\n"
        f"pass out quick on {internet_if}\n"
    )
    pf_file = Path("/tmp/quiver_pf.conf")
    pf_file.write_text(pf_rules)

    r_fwd = run("sudo sysctl -w net.inet.ip.forwarding=1 2>&1")
    info(f"IP forwarding: {(r_fwd.stdout + r_fwd.stderr).strip() or 'ok'}")

    run("sudo pfctl -d 2>/dev/null")  # disable first to avoid duplicate rules
    r_pf = run(f"sudo pfctl -e -f {pf_file} 2>&1")
    pf_out = (r_pf.stdout + r_pf.stderr).strip()
    info(f"pfctl -e -f: rc={r_pf.returncode} output={pf_out or '(none)'}")

    if r_pf.returncode == 0 or "pf enabled" in pf_out.lower():
        ok(f"macOS PF NAT active: {device_if} → {internet_if}")
        return True

    warn(f"pfctl returned rc={r_pf.returncode}: {pf_out[:200]}")
    return False


def disable_ics_macos():
    """Remove PF NAT rules set by enable_ics_macos."""
    pf_file = Path("/tmp/quiver_pf.conf")
    if pf_file.exists():
        info("Removing PF NAT rules…")
        run("sudo pfctl -F nat")
        run("sudo pfctl -d 2>/dev/null")
        pf_file.unlink(missing_ok=True)
    run("sudo sysctl -w net.inet.ip.forwarding=0")


def enable_ics(device_ip: str, device_service: str = "") -> bool:
    """OS-agnostic ICS setup."""
    os_name = get_os()
    internet_if = get_internet_interface()
    if not internet_if:
        warn("Could not determine internet interface. Manual ICS setup required.")
        return False
    device_if = get_interface_for_ip(device_ip)
    if os_name == "linux":
        if not device_if:
            warn("Cannot find interface for device. Make sure it's connected.")
            return False
        enable_ics_linux(internet_if, device_if)
        return True
    elif os_name == "macos":
        return enable_ics_macos(device_service)
    else:
        warn("Windows ICS not automated. Configure manually:")
        print("  Control Panel → Network → right-click Wi-Fi → Properties → Sharing")
        return False


def disable_ics():
    """OS-agnostic ICS teardown."""
    os_name = get_os()
    if os_name == "linux":
        disable_ics_linux()
    elif os_name == "macos":
        disable_ics_macos()


# ── SSH known_hosts helpers ───────────────────────────────────────────────────

def clear_ssh_known_hosts(host: str) -> bool:
    """
    Remove SSH known_hosts entries for *host*.
    Fixes "REMOTE HOST IDENTIFICATION HAS CHANGED" after firmware updates.
    """
    info(f"Clearing SSH known_hosts for {host}…")
    r = run(f"ssh-keygen -R {host} 2>&1")
    out = (r.stdout + r.stderr).strip()
    if r.returncode == 0 or "not found" in out.lower():
        ok(f"known_hosts cleared for {host}")
        return True
    warn(f"ssh-keygen -R {host}: {out[:200]}")
    return False


# ── Kernel module helpers (Linux) ─────────────────────────────────────────────

def check_kernel_module(module: str) -> bool:
    """Return True if kernel module is loaded (Linux only; always True on other OS)."""
    if get_os() != "linux":
        return True
    out = run_output("lsmod 2>/dev/null")
    return bool(re.search(rf"^{re.escape(module)}\b", out, re.MULTILINE))


def load_kernel_module(module: str) -> bool:
    """Load a kernel module via modprobe. Returns True on success."""
    if get_os() != "linux":
        return True
    info(f"Loading kernel module '{module}'…")
    r = run(f"sudo modprobe {module} 2>&1")
    out = (r.stdout + r.stderr).strip()
    if r.returncode == 0:
        ok(f"Module '{module}' loaded.")
        return True
    warn(f"modprobe {module}: {out[:200]}")
    return False


# ── Interface / link helpers ──────────────────────────────────────────────────

def check_interface_link(iface: str) -> bool:
    """Return True if the interface has an active Ethernet carrier."""
    os_name = get_os()
    if os_name == "linux":
        carrier = run_output(f"cat /sys/class/net/{iface}/carrier 2>/dev/null").strip()
        return carrier == "1"
    elif os_name == "macos":
        out = run_output(f"ifconfig {iface} 2>/dev/null")
        return "status: active" in out.lower()
    return False


def set_interface_promisc(iface: str, enable: bool = True) -> bool:
    """Enable or disable promiscuous mode on a network interface."""
    os_name = get_os()
    action = "Enabling" if enable else "Disabling"
    info(f"{action} promiscuous mode on {iface}…")
    if os_name == "linux":
        r = run(f"sudo ip link set {iface} {'promisc on' if enable else 'promisc off'} 2>&1")
        if r.returncode == 0:
            ok(f"Promiscuous mode {'on' if enable else 'off'} on {iface}.")
            return True
        warn(f"ip link promisc failed: {(r.stdout + r.stderr).strip()[:200]}")
        return False
    elif os_name == "macos":
        flag = "promisc" if enable else "-promisc"
        r = run(f"sudo ifconfig {iface} {flag} 2>&1")
        if r.returncode == 0:
            ok(f"Promiscuous mode {'on' if enable else 'off'} on {iface}.")
            return True
        warn(f"ifconfig {flag} failed: {(r.stdout + r.stderr).strip()[:200]}")
        return False
    else:
        warn("Promiscuous mode must be set manually on Windows (adapter properties → configure → advanced).")
        return False


def get_filesystem_type(path: str) -> str:
    """Return the filesystem type of the volume at path, uppercase (e.g. 'FAT32', 'EXFAT', 'NTFS')."""
    os_name = get_os()
    if os_name == "macos":
        out = run_output(f"diskutil info '{path}' 2>/dev/null")
        m = re.search(r"File System Personality:\s+(\S+)", out) or \
            re.search(r"Type \(Bundle\):\s+(\S+)", out)
        return m.group(1).upper() if m else ""
    elif os_name == "linux":
        out = run_output(f"df -T '{path}' 2>/dev/null | tail -1")
        parts = out.split()
        if len(parts) >= 2:
            return parts[1].upper()
        # Fallback via stat
        out2 = run_output(f"stat -f -c '%T' '{path}' 2>/dev/null")
        return out2.strip().upper() if out2.strip() else ""
    return ""


# ── SSH helpers ───────────────────────────────────────────────────────────────

class SSHClient:
    """Thin wrapper around paramiko (or subprocess ssh) for remote commands."""

    def __init__(self, host: str, user: str, password: str, port: int = 22):
        self.host = host
        self.user = user
        self.password = password
        self.port = port
        self._client: Optional["paramiko.SSHClient"] = None

    def connect(self, timeout: int = 30) -> bool:
        if not HAS_PARAMIKO:
            warn("paramiko not installed; run: pip install paramiko")
            return False
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                self.host, port=self.port,
                username=self.user, password=self.password,
                timeout=timeout,
                banner_timeout=timeout,
                auth_timeout=timeout,
                look_for_keys=False,
                allow_agent=False,
            )
            self._client = client
            return True
        except Exception as e:
            err(f"SSH connect failed: {e}")
            return False

    def run(self, cmd: str, timeout: int = 120) -> tuple[int, str, str]:
        """Run command; return (returncode, stdout, stderr)."""
        if not self._client:
            raise RuntimeError("Not connected")
        stdin, stdout, stderr = self._client.exec_command(cmd, timeout=timeout)
        exit_code = stdout.channel.recv_exit_status()
        return exit_code, stdout.read().decode(), stderr.read().decode()

    def upload(self, local: str, remote: str) -> bool:
        """Upload a file via SFTP."""
        if not self._client:
            return False
        try:
            sftp = self._client.open_sftp()
            sftp.put(local, remote)
            sftp.close()
            return True
        except Exception as e:
            err(f"SFTP upload failed: {e}")
            return False

    def download(self, remote: str, local: str) -> bool:
        if not self._client:
            return False
        try:
            sftp = self._client.open_sftp()
            sftp.get(remote, local)
            sftp.close()
            return True
        except Exception as e:
            err(f"SFTP download failed: {e}")
            return False

    def close(self):
        if self._client:
            self._client.close()
            self._client = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def wait_for_ssh(host: str, user: str, password: str, port: int = 22,
                 timeout: int = 120, interval: int = 5) -> Optional[SSHClient]:
    """Poll until SSH is up; return an open SSHClient or None on timeout."""
    if not HAS_PARAMIKO:
        warn("Install paramiko first:  pip install -r requirements.txt")
        return None
    deadline = time.time() + timeout
    info(f"Waiting for SSH on {host}:{port}…")
    while time.time() < deadline:
        client = SSHClient(host, user, password, port)
        if client.connect(timeout=5):
            return client
        time.sleep(interval)
    return None


# ── Serial console ────────────────────────────────────────────────────────────

try:
    import serial as _serial
    HAS_SERIAL = True
except ImportError:
    HAS_SERIAL = False


class SerialConsole:
    """
    Thin wrapper around pyserial for interacting with an embedded Linux shell
    (e.g. Bash Bunny arming-mode serial console at 115200 baud).

    Usage:
        with SerialConsole("/dev/tty.usbmodem1234") as con:
            print(con.run("ip addr show usb0"))
    """

    # Matches a typical root shell prompt: root@bunny:~# or just #/$ at EOL
    _PROMPT_RE = re.compile(
        rb"(?:root@[^:]*:[^\r\n]*[#\$]|[#\$])\s*$", re.MULTILINE
    )
    _LOGIN_RE   = re.compile(rb"login:\s*$", re.IGNORECASE)
    _PASSWD_RE  = re.compile(rb"[Pp]assword:\s*$")

    def __init__(self, port: str, baud: int = 115200, timeout: float = 0.3):
        self.port    = port
        self.baud    = baud
        self.timeout = timeout
        self._ser    = None

    # ── connection ─────────────────────────────────────────────────────────

    def connect(self, login: str = "root", password: str = "hak5bunny") -> bool:
        if not HAS_SERIAL:
            warn("pyserial not installed. Run: pip install pyserial")
            return False
        try:
            self._ser = _serial.Serial(
                port=self.port, baudrate=self.baud, timeout=self.timeout,
                bytesize=8, parity="N", stopbits=1, xonxoff=False,
                rtscts=False, dsrdtr=False,
            )
        except Exception as e:
            err(f"Cannot open serial port {self.port}: {e}")
            return False

        # Prod the console with a CR to elicit a prompt or login challenge
        self._ser.write(b"\r\n")
        time.sleep(0.6)
        banner = self._read_raw(timeout=4)

        # Handle login prompt if present
        if self._LOGIN_RE.search(banner):
            self._ser.write((login + "\r\n").encode())
            time.sleep(0.5)
            resp = self._read_raw(timeout=4)
            if self._PASSWD_RE.search(resp):
                self._ser.write((password + "\r\n").encode())
                time.sleep(0.5)
                self._read_raw(timeout=4)  # consume the post-login banner

        # One more CR to get a clean prompt
        self._ser.write(b"\r\n")
        time.sleep(0.3)
        self._read_raw(timeout=2)
        return True

    # ── raw I/O ────────────────────────────────────────────────────────────

    def _read_raw(self, timeout: float = 10.0) -> bytes:
        """Read until a shell prompt appears or timeout expires."""
        buf = b""
        deadline = time.time() + timeout
        while time.time() < deadline:
            chunk = self._ser.read(512)
            if chunk:
                buf += chunk
                # Check the tail of the buffer for a prompt
                tail = buf[-128:]
                if self._PROMPT_RE.search(tail):
                    break
            else:
                time.sleep(0.05)
        return buf

    # ── public API ─────────────────────────────────────────────────────────

    def run(self, cmd: str, timeout: float = 30.0) -> str:
        """
        Send *cmd* to the shell, wait for the next prompt, and return the
        output with the echoed command and trailing prompt stripped.
        """
        if self._ser is None:
            raise RuntimeError("SerialConsole: not connected")
        self._ser.reset_input_buffer()
        self._ser.write((cmd.strip() + "\r\n").encode())
        time.sleep(0.15)
        raw = self._read_raw(timeout=timeout)

        # Decode and clean up
        text = raw.decode("utf-8", errors="replace")
        lines = text.replace("\r\n", "\n").replace("\r", "\n").splitlines()

        cleaned = []
        echo_done = False
        for line in lines:
            stripped = line.strip()
            # Skip the echoed command line
            if not echo_done and cmd.strip() in stripped:
                echo_done = True
                continue
            # Skip the trailing prompt line
            if self._PROMPT_RE.search(line.encode()):
                continue
            cleaned.append(line)

        return "\n".join(cleaned).strip()

    def write_raw(self, data: bytes):
        """Send raw bytes (no newline added)."""
        if self._ser:
            self._ser.write(data)

    def close(self):
        if self._ser and self._ser.is_open:
            self._ser.close()
        self._ser = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


# ── Firmware helpers ──────────────────────────────────────────────────────────

def get_openwrt_version(ssh: SSHClient) -> str:
    """Read OpenWRT release version via SSH."""
    rc, out, _ = ssh.run("cat /etc/openwrt_release 2>/dev/null || cat /etc/os-release")
    for line in out.splitlines():
        if "DISTRIB_RELEASE" in line or "VERSION_ID" in line:
            return line.split("=", 1)[-1].strip().strip('"')
    return "unknown"


def openwrt_sysupgrade(ssh: SSHClient, remote_bin: str, keep_config: bool = False):
    """
    Run sysupgrade on an OpenWRT device.
    keep_config=False passes -n (no config preservation).
    NOTE: SSH session will drop; caller must wait and reconnect.
    """
    flag = "" if keep_config else "-n"
    info(f"Running: sysupgrade {flag} {remote_bin}  (device will reboot)")
    ssh.run(f"sysupgrade {flag} {remote_bin} &", timeout=5)


# ── Payload validation ────────────────────────────────────────────────────────

def check_bash_syntax(path: str) -> list[str]:
    """Run bash -n on a file; return list of error lines."""
    r = run(f"bash -n {path} 2>&1")
    if r.returncode == 0:
        return []
    return r.stderr.strip().splitlines() if r.stderr.strip() else r.stdout.strip().splitlines()


def extract_required_commands(script_path: str, known_builtins: set) -> list[str]:
    """
    Heuristic: scan a shell script for commands that are not builtins,
    keywords, or known shell constructs. Returns list of likely external commands.
    """
    commands = set()
    skip_words = {
        "if", "then", "else", "fi", "for", "do", "done", "while", "case", "esac",
        "function", "return", "local", "export", "echo", "printf", "read", "exit",
        "source", ".", "set", "unset", "shift", "trap", "true", "false", "test",
        "[", "[[", "]]", "sleep", "kill", "wait", "cd", "pwd", "mkdir", "rm",
        "cat", "ls", "cp", "mv", "ln", "chmod", "chown", "grep", "sed", "awk",
        "sort", "uniq", "wc", "head", "tail", "tee", "tr", "cut", "date",
        "basename", "dirname", "find", "xargs", "env", "which", "type",
        "sync", "halt", "reboot", "init",
    }
    skip_words |= known_builtins

    try:
        content = Path(script_path).read_text()
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Grab first token of each pipeline stage
            for part in re.split(r"[|;&]", line):
                part = part.strip()
                # Strip variable assignments and redirections
                part = re.sub(r"^\s*\w+=\S+\s*", "", part)
                part = re.sub(r"\s*\d?[<>]+\S*", "", part)
                tokens = part.split()
                if tokens:
                    cmd = tokens[0].lstrip("$({\\")
                    if cmd and cmd not in skip_words and re.match(r"^[a-zA-Z_][a-zA-Z0-9_-]*$", cmd):
                        commands.add(cmd)
    except Exception:
        pass
    return sorted(commands)


def check_packages_openwrt(ssh: SSHClient, commands: list[str]) -> dict[str, bool]:
    """
    Check if given command names are available on an OpenWRT device.
    Returns {command: is_available}.
    """
    availability = {}
    for cmd in commands:
        rc, _, _ = ssh.run(f"which {cmd} 2>/dev/null || command -v {cmd} 2>/dev/null")
        availability[cmd] = (rc == 0)
    return availability


def install_openwrt_package(ssh: SSHClient, package: str) -> bool:
    """Install a package via opkg."""
    info(f"  opkg update && opkg install {package}")
    rc, out, err_out = ssh.run("opkg update 2>&1", timeout=120)
    if rc != 0:
        warn(f"opkg update warning: {err_out[:200]}")
    rc2, out2, err2 = ssh.run(f"opkg install {package} 2>&1", timeout=120)
    if rc2 == 0:
        ok(f"Installed {package}")
        return True
    else:
        err(f"Failed to install {package}: {err2[:200]}")
        return False


def check_packages_debian(ssh: SSHClient, commands: list[str]) -> dict[str, bool]:
    """Check if commands are available on a Debian-based device."""
    availability = {}
    for cmd in commands:
        rc, _, _ = ssh.run(f"which {cmd} 2>/dev/null")
        availability[cmd] = (rc == 0)
    return availability


def install_debian_package(ssh: SSHClient, package: str) -> bool:
    rc, _, err_out = ssh.run(
        f"apt-get install -y {package} 2>&1", timeout=180
    )
    if rc == 0:
        ok(f"Installed {package}")
        return True
    else:
        err(f"Failed to install {package}: {err_out[:200]}")
        return False


# ── Device detection loop ─────────────────────────────────────────────────────

def detection_loop(detect_fn, mode_instructions: str,
                   reset_instructions: str,
                   max_attempts: int = 3,
                   poll_interval: int = 5,
                   poll_timeout: int = 30) -> bool:
    """
    Generic detection loop.
    1. Try once immediately.
    2. If not found, show mode instructions and retry.
    3. After max_attempts, show reset instructions and offer to abort.
    Returns True if device was eventually detected, False otherwise.
    """
    heading("Step 2 — Device Detection")

    for attempt in range(1, max_attempts + 1):
        info(f"Scanning for device (attempt {attempt}/{max_attempts})…")
        deadline = time.time() + poll_timeout
        found = False
        while time.time() < deadline:
            if detect_fn():
                found = True
                break
            time.sleep(poll_interval)

        if found:
            ok("Device detected!")
            return True

        if attempt < max_attempts:
            heading(f"Step 3 — Device Not Found (attempt {attempt})")
            print(textwrap.indent(textwrap.dedent(mode_instructions).strip(), "  "))
            if not confirm("\nTry again?", default=True):
                break
        else:
            heading("Step 5 — Factory Reset Instructions")
            print(textwrap.indent(textwrap.dedent(reset_instructions).strip(), "  "))
            pause("After following the reset steps, press ENTER to scan once more…")
            if detect_fn():
                ok("Device detected after reset procedure!")
                return True

    heading("Step 6 — Manual Test / Replacement")
    err("Device could not be detected after multiple attempts.")
    print("\n  Recommendations:")
    print("    • Try a different USB port or cable")
    print("    • Test on a different computer")
    print("    • Check the device documentation or community forums")
    print("    • If the device is unresponsive, consider hardware replacement")
    return False


# ── Enhanced USB detection (pyserial + pyusb) ─────────────────────────────────

def find_serial_port_by_vidpid(vid_pids: list) -> Optional[str]:
    """
    Find a serial port by a list of (vid_int, pid_int_or_None) tuples.
    Uses serial.tools.list_ports for precise matching.
    Returns the device path (e.g. /dev/ttyACM0) or None.
    """
    if not HAS_SERIAL:
        warn("pyserial not installed — cannot scan USB serial ports.")
        return None
    import serial.tools.list_ports as _lp
    for port in _lp.comports():
        for vid, pid in vid_pids:
            if port.vid == vid and (pid is None or port.pid == pid):
                return port.device
    return None


def detect_usb_libusb(vid: int, pid: int) -> bool:
    """
    Detect a libusb-only device (no serial port) using pyusb.
    vid/pid: integer values (e.g. 0x1D50, 0x6089).
    Returns True if found.
    """
    try:
        import usb.core  # type: ignore
        dev = usb.core.find(idVendor=vid, idProduct=pid)
        return dev is not None
    except ImportError:
        # Fall back to system tools if pyusb not installed
        return detect_usb_device(f"{vid:04X}", f"{pid:04X}")
    except Exception:
        return False


def detect_usb_libusb_any(vid_pids: list) -> bool:
    """Check if any device in the vid_pids list [(vid, pid), ...] is connected."""
    for vid, pid in vid_pids:
        if detect_usb_libusb(vid, pid):
            return True
    return False


# ── Package / tool bootstrapping ──────────────────────────────────────────────

def _apt_installed(pkg: str) -> bool:
    """Return True if pkg is listed as 'ii' (fully installed) by dpkg."""
    r = subprocess.run(["dpkg", "-l", pkg], capture_output=True, text=True)
    return r.returncode == 0 and f"\nii  {pkg}" in r.stdout


def ensure_apt_packages(packages: list) -> bool:
    """
    Ensure apt packages are installed (Debian / Kali / Ubuntu).
    packages: list of apt package name strings.
    Returns True if all were already present or successfully installed.
    On macOS or non-apt systems this is a no-op that returns False.
    """
    import shutil
    flavor = get_os_flavor()
    if flavor == "macos":
        return False  # caller should use ensure_brew_packages instead
    if not shutil.which("apt-get"):
        warn("apt-get not found; skipping apt package installation.")
        return False

    missing = [p for p in packages if not _apt_installed(p)]
    if not missing:
        return True

    info(f"Installing via apt: {' '.join(missing)}")
    rc = run_streaming_sudo(
        ["apt-get", "install", "-y", "--no-install-recommends"] + missing,
        on_line=lambda l: info(f"  apt: {l}"),
        timeout=300,
    )
    if rc == 0:
        ok(f"apt packages installed: {', '.join(missing)}")
        return True
    err(f"apt install failed (exit {rc}). Try manually:")
    err(f"  sudo apt-get install -y {' '.join(missing)}")
    return False


def ensure_brew_packages(packages: list) -> bool:
    """
    Ensure Homebrew packages are installed (macOS only).
    packages: list of brew formula names.
    """
    import shutil
    if get_os_flavor() != "macos":
        return False
    if not shutil.which("brew"):
        warn("Homebrew not found. Install from https://brew.sh")
        return False

    missing = []
    for pkg in packages:
        r = subprocess.run(["brew", "list", "--formula", pkg],
                           capture_output=True, text=True)
        if r.returncode != 0:
            missing.append(pkg)

    if not missing:
        return True

    info(f"Installing via brew: {' '.join(missing)}")
    rc = run_streaming(
        ["brew", "install"] + missing,
        on_line=lambda l: info(f"  brew: {l}"),
        timeout=300,
    )
    if rc == 0:
        ok(f"brew packages installed: {', '.join(missing)}")
        return True
    err(f"brew install failed. Try manually: brew install {' '.join(missing)}")
    return False


def ensure_openocd() -> str:
    """Return the path to an `openocd` binary, auto-installing it if missing.

    OpenOCD is the open-source flasher for TI XDS110 LaunchPads (CC13xx/CC26xx)
    and, unlike TI UniFlash, needs no TI login — so it can be installed as part
    of a flash workflow. Returns the path, or '' if it could not be provided.
    """
    import shutil
    path = shutil.which("openocd")
    if path:
        return path
    flavor = get_os_flavor()
    info("openocd not found — attempting to install it (open-source XDS110 flasher)…")
    if flavor == "macos":
        ensure_brew_packages(["open-ocd"])       # brew formula is 'open-ocd'
    elif flavor in ("debian", "kali", "ubuntu", "raspbian"):
        ensure_apt_packages(["openocd"])
    else:
        # dnf/zypper/others: best-effort, non-fatal
        for mgr in (["dnf", "install", "-y", "openocd"],
                    ["zypper", "--non-interactive", "install", "openocd"]):
            if shutil.which(mgr[0]):
                run(" ".join(mgr))
                break
    return shutil.which("openocd") or ""
    """
    Ensure Python packages are installed via pip.
    packages: list of (import_name, pip_install_spec) tuples.
    E.g.: [("serial", "pyserial"), ("esptool", "esptool>=4.7")]

    On Debian/Kali/Ubuntu the ``--break-system-packages`` flag is used so that
    pip can install into the system Python without PEP-668 complaints.
    Returns True if all packages are available after installation.
    """
    import importlib
    missing_specs = []
    for import_name, pip_spec in packages:
        try:
            importlib.import_module(import_name)
        except ImportError:
            missing_specs.append((import_name, pip_spec))

    if not missing_specs:
        return True

    flavor = get_os_flavor()
    bsp = "--break-system-packages" if flavor in ("kali", "debian", "ubuntu", "linux") else ""

    info(f"Installing missing Python packages via pip: {', '.join(s for _, s in missing_specs)}")
    all_ok = True
    for import_name, pip_spec in missing_specs:
        cmd = f'{sys.executable} -m pip install "{pip_spec}"'
        if bsp:
            cmd += f" {bsp}"
        cmd += " 2>&1"
        info(f"  {cmd}")
        r = run(cmd, capture=True)
        if r.returncode == 0:
            ok(f"  Installed: {pip_spec}")
        else:
            err(f"  Failed to install {pip_spec}: {(r.stdout + r.stderr)[:300]}")
            all_ok = False
    return all_ok


def ensure_system_tool(tool_name: str, install_hint: str,
                       apt_pkg: str = None, brew_pkg: str = None) -> bool:
    """
    Return True if tool_name is in PATH.
    If not found, attempt automatic installation:
      - apt_pkg:  install via apt on Debian/Kali/Ubuntu
      - brew_pkg: install via brew on macOS
    Falls back to printing install_hint if automatic install fails or is unavailable.
    """
    import shutil
    if shutil.which(tool_name):
        return True

    flavor = get_os_flavor()
    if apt_pkg and flavor in ("kali", "debian", "ubuntu", "linux"):
        info(f"'{tool_name}' not found — installing via apt ({apt_pkg})…")
        if ensure_apt_packages([apt_pkg]) and shutil.which(tool_name):
            return True
    elif brew_pkg and flavor == "macos":
        info(f"'{tool_name}' not found — installing via brew ({brew_pkg})…")
        if ensure_brew_packages([brew_pkg]) and shutil.which(tool_name):
            return True

    warn(f"'{tool_name}' not found in PATH.")
    info(f"Install: {install_hint}")
    return False


# ── Web-aware device detection loop ──────────────────────────────────────────

def web_detect_loop(detect_fn, tool_name: str, instructions: str,
                    timeout: int = 1800, interval: float = 3.0) -> bool:
    """
    Detection loop that integrates with the web waiting modal.
    In web mode: emits wait_start (shows modal), polls detect_fn, emits wait_done/timeout.
    In terminal mode: prints instructions, polls, prints status.
    Returns True if device detected, False on timeout.
    """
    if WEB_MODE:
        wait_start(instructions)
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                if detect_fn():
                    wait_done(f"{tool_name} detected")
                    return True
            except Exception:
                pass
            remaining = int(deadline - time.time())
            wait_status(f"Waiting for {tool_name}… ({remaining}s remaining)")
            time.sleep(interval)
        wait_timeout(f"{tool_name} not detected after {timeout}s")
        return False
    else:
        heading(f"Connecting — {tool_name}")
        print(textwrap.indent(textwrap.dedent(instructions).strip(), "  "))
        deadline = time.time() + timeout
        while time.time() < deadline:
            info(f"Scanning for {tool_name}…")
            try:
                if detect_fn():
                    ok(f"{tool_name} detected!")
                    return True
            except Exception:
                pass
            time.sleep(interval)
        warn(f"{tool_name} not found after {timeout}s.")
        return False


# ── Pre-selected payload helper ───────────────────────────────────────────────

def get_selected_payload() -> str:
    """
    Return the payload path pre-selected in the Quiver UI (set via the
    QUIVER_SELECTED_PAYLOAD environment variable by the Flask app) or an
    empty string if none was selected.
    """
    return os.environ.get("QUIVER_SELECTED_PAYLOAD", "")


# ── Connection verification with interactive retry ────────────────────────────

def verify_device_connection(detect_fn, tool_name: str, instructions: str,
                              max_retries: int = 3) -> bool:
    """
    Verify that a device is connected and accessible before proceeding.

    1. Checks immediately — returns True right away if the device is found.
    2. If not found, shows the connection instructions inside a pause popup
       (web mode) or prints them to the terminal, then waits for the user to
       click Continue / press Enter.
    3. Re-checks after each Continue.  Repeats up to *max_retries* times.
    4. Returns False and logs an error if the device is still not found after
       all retries.

    Instructions should describe: how to put the device in the correct mode,
    what LEDs or indicators to watch for, and when the device is ready.
    """
    if detect_fn():
        return True

    for attempt in range(1, max_retries + 1):
        err(f"{tool_name} not detected (attempt {attempt} of {max_retries}).")
        msg = (
            f"\u26a0\ufe0f  {tool_name} \u2014 Device Not Detected\n"
            f"Attempt {attempt} of {max_retries}\n\n"
            f"{instructions}\n\n"
            f"Connect the device and click Continue when it is ready."
        )
        pause(msg)
        if detect_fn():
            ok(f"{tool_name} detected.")
            return True

    err(
        f"Device not detected after {max_retries} attempt(s). "
        "Verify the device is connected in the correct mode and try again."
    )
    return False


def run_streaming(cmd: list, on_line, timeout: int = 300) -> int:
    """
    Run a subprocess, calling on_line(text) for each stdout/stderr line.
    Returns the exit code.
    """
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    try:
        for line in proc.stdout:
            on_line(line.rstrip())
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
    return proc.returncode


# ── Firmware version helpers ───────────────────────────────────────────────────

def progress(pct: int, text: str = "", step: str = "") -> None:
    """
    Emit a progress event for WebSocket progress bars.

    pct  — integer 0-100 representing percentage complete
    text — human-readable description of current operation
    step — optional short step label (e.g., "Erasing", "Flashing", "Verifying")

    In web mode this emits a LOG JSON with level=progress.
    In terminal mode it prints a simple ASCII progress bar.
    """
    pct = max(0, min(100, int(pct)))
    if _WEB_MODE:
        import json as _json
        print(f"LOG:{_json.dumps({'level':'progress','pct':pct,'text':text,'step':step})}",
              flush=True)
    else:
        bar_len  = 30
        filled   = int(bar_len * pct / 100)
        bar      = "█" * filled + "░" * (bar_len - filled)
        label    = f" {step}: " if step else " "
        sys.stdout.write(f"\r[{bar}] {pct:3d}%{label}{text}")
        sys.stdout.flush()
        if pct >= 100:
            print()   # newline on completion


def get_firmware_dir(tool_id: str = "") -> Path:
    """
    Return the path to the firmware directory for a tool.
    firmware/ lives alongside the tool scripts, at the same level as payloads/.
    """
    script_dir = Path(__file__).parent
    base = script_dir / "firmware"
    if tool_id:
        return base / tool_id
    return base


def check_latest_github_release(owner: str, repo: str,
                                 timeout: int = 8) -> tuple:
    """
    Query the GitHub API for the latest release of owner/repo.

    Returns (tag_name: str, release_url: str) on success, or ("", "") on
    failure (network error, rate-limit, 404, etc.).  Failures are logged as
    warnings and never raise.

    Uses 'requests' if available, falls back to urllib so we do not require
    an extra dependency just for a version check.
    """
    api_url = f"https://api.github.com/repos/{owner}/{repo}/releases/latest"
    headers = {"Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": "2022-11-28"}
    # Honour GITHUB_TOKEN if set (avoids 60-req/hr unauthenticated limit)
    token = os.environ.get("GITHUB_TOKEN", "")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        try:
            import requests as _req
            resp = _req.get(api_url, headers=headers, timeout=timeout)
            if resp.status_code == 200:
                data = resp.json()
                return data.get("tag_name", ""), data.get("html_url", "")
            if resp.status_code == 403:
                warn("GitHub API rate limit reached. Set GITHUB_TOKEN env var for higher limits.")
            elif resp.status_code == 404:
                warn(f"GitHub repo not found: {owner}/{repo}")
            else:
                warn(f"GitHub API returned HTTP {resp.status_code} for {owner}/{repo}")
            return "", ""
        except ImportError:
            pass  # fall through to urllib

        import urllib.request as _urlreq
        import urllib.error as _urlerr
        import json as _json
        req = _urlreq.Request(api_url, headers=headers)
        with _urlreq.urlopen(req, timeout=timeout) as resp:
            data = _json.loads(resp.read())
            return data.get("tag_name", ""), data.get("html_url", "")

    except Exception as e:
        warn(f"Could not check latest release for {owner}/{repo}: {e}")
        return "", ""


def compare_versions(v1: str, v2: str) -> int:
    """
    Compare two version strings (e.g. 'v1.2.3' vs '1.3.0').

    Returns:
      -1  if v1 < v2  (v1 is older)
       0  if v1 == v2
      +1  if v1 > v2  (v1 is newer)

    Non-numeric suffixes (alpha, beta, rc) are handled gracefully.
    Strips leading 'v' or 'V'.
    """
    import re as _re

    def _normalise(v: str) -> list:
        v = v.strip().lstrip("vV")
        # Keep only the numeric dotted part; discard '-rc1', '-alpha', etc.
        v = _re.split(r"[-+]", v)[0]
        parts = []
        for p in v.split("."):
            try:
                parts.append(int(p))
            except ValueError:
                parts.append(0)
        return parts

    a, b = _normalise(v1), _normalise(v2)
    # Pad to equal length
    length = max(len(a), len(b))
    a += [0] * (length - len(a))
    b += [0] * (length - len(b))
    if a < b:
        return -1
    if a > b:
        return 1
    return 0


def announce_firmware_update(tool_name: str, current: str, latest: str,
                              release_url: str = "") -> bool:
    """
    Log a firmware update notice and prompt the user.

    Returns True if the user wants to update now, False to skip.
    Always returns False (skip) if current == latest or either is empty.
    """
    if not current or not latest:
        return False
    cmp = compare_versions(current, latest)
    if cmp == 0:
        ok(f"{tool_name} firmware is up to date: {current}")
        return False
    if cmp > 0:
        info(f"{tool_name} firmware {current} is newer than latest release {latest}.")
        return False
    # cmp == -1: current is older
    warn(f"{tool_name} firmware update available!")
    warn(f"  Installed : {current}")
    warn(f"  Latest    : {latest}")
    if release_url:
        info(f"  Release   : {release_url}")
    return confirm("Update firmware now?", default=True)


def download_firmware(url: str, dest: Path, tool_name: str = "",
                      timeout: int = 120) -> bool:
    """
    Download a file from *url* to *dest*.

    Tries requests (streaming) first, falls back to urllib, then curl/wget.
    Shows progress info() lines.  Returns True on success.
    """
    tool_name = tool_name or dest.name
    info(f"Downloading {dest.name} from {url} …")
    dest.parent.mkdir(parents=True, exist_ok=True)

    # ── Try requests ──────────────────────────────────────────────────────────
    try:
        import requests as _req
        with _req.get(url, stream=True, timeout=timeout) as r:
            r.raise_for_status()
            total = int(r.headers.get("content-length", 0))
            downloaded = 0
            with open(dest, "wb") as f:
                for chunk in r.iter_content(chunk_size=65536):
                    f.write(chunk)
                    downloaded += len(chunk)
            size_kb = downloaded // 1024
            ok(f"Downloaded {dest.name} ({size_kb} KB)")
            return True
    except ImportError:
        pass  # fall through
    except Exception as e:
        warn(f"requests download failed: {e}")

    # ── Try urllib ────────────────────────────────────────────────────────────
    try:
        import urllib.request as _urlreq
        _urlreq.urlretrieve(url, str(dest))
        ok(f"Downloaded {dest.name} ({dest.stat().st_size // 1024} KB)")
        return True
    except Exception as e:
        warn(f"urllib download failed: {e}")

    # ── Try curl / wget ───────────────────────────────────────────────────────
    for cli, args in [("curl", ["-fL", "-o", str(dest), url]),
                      ("wget", ["-q", "-O", str(dest), url])]:
        if shutil.which(cli):
            r = subprocess.run([cli] + args, capture_output=True)
            if r.returncode == 0 and dest.exists():
                ok(f"Downloaded {dest.name} via {cli} ({dest.stat().st_size // 1024} KB)")
                return True

    err(f"Failed to download {url}")
    info(f"Manual download: curl -fL -o {dest} '{url}'")
    return False


def get_github_release_asset_url(owner: str, repo: str, tag: str,
                                  asset_pattern: str) -> str:
    """
    Find the download URL of a release asset matching *asset_pattern* (regex)
    in the given GitHub release tag.  Returns '' on failure.
    """
    import re as _re
    api_url = (f"https://api.github.com/repos/{owner}/{repo}/releases/tags/{tag}"
               if tag else
               f"https://api.github.com/repos/{owner}/{repo}/releases/latest")
    headers = {"Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": "2022-11-28"}
    token = os.environ.get("GITHUB_TOKEN", "")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        try:
            import requests as _req
            resp = _req.get(api_url, headers=headers, timeout=8)
            resp.raise_for_status()
            data = resp.json()
        except ImportError:
            import urllib.request as _urlreq
            import json as _json
            req = _urlreq.Request(api_url, headers=headers)
            with _urlreq.urlopen(req, timeout=8) as r:
                data = _json.loads(r.read())
        for asset in data.get("assets", []):
            if _re.search(asset_pattern, asset.get("name", ""), _re.IGNORECASE):
                return asset.get("browser_download_url", "")
    except Exception as e:
        warn(f"Could not query release assets for {owner}/{repo}: {e}")
    return ""
