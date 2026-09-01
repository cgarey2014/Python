# Author: Chris Garey
# Date: 2024-06-15
# Description: WiSight - Lightweight Wi-Fi monitoring tool with passive discovery.
#
# WiSight is a cross-platform (macOS, Linux, Windows) terminal dashboard that
# displays live Wi-Fi telemetry: connected SSID/BSSID, signal strength (RSSI and
# percent), live throughput (download/upload), roaming/handover events, and a
# passively-discovered list of nearby network devices resolved to hostnames.
#
# The tool is intentionally read-only on the network — it inspects the local
# ARP cache and uses native OS utilities rather than injecting packets. Scapy
# is imported optionally for environments where active probing is allowed.
#
# Runtime requirements:
#   - Python 3.8+
#   - Terminal with TTY support (for non-blocking 'q' keypress handling)
#   - Native CLI utilities per platform (arp, networksetup/netstat, netsh, etc.)
#
# Python dependencies (auto-installed on first run by bootstrap_dependencies):
#   - rich     (required, terminal rendering)
#   - scapy    (optional, active probing)

import json
import os
import platform
import queue
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.request
import importlib.util

# ---------------------------------------------------------------------------
# Bootstrap: dependency check + interactive pip install
# ---------------------------------------------------------------------------
# Verifies the third-party packages that this script needs (rich, scapy) are
# importable, and offers to install them via pip3 if they're missing. Runs
# before any other import so the rest of the module can assume they're
# available (or that the user has explicitly opted out and rich is present).
def bootstrap_dependencies():
    packages_to_check = [
        ("rich", "rich"),
        ("scapy", "scapy")
    ]
    
    missing_packages = [
        pkg_name for mod_name, pkg_name in packages_to_check 
        if importlib.util.find_spec(mod_name) is None
    ]
    
    if missing_packages:
        print("=" * 60)
        print(" WiSight - Missing Dependency Check")
        print("=" * 60)
        print("The following Python package(s) are required or recommended:")
        for pkg in missing_packages:
            print(f"  - {pkg}")
        print()
        
        try:
            choice = input("Would you like to automatically install them now? (y/n): ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print("\nInstallation aborted.")
            sys.exit(1)
            
        if choice in ("y", "yes"):
            for pkg in missing_packages:
                print(f"\n[*] Installing '{pkg}' using {sys.executable}...")
                try:
                    subprocess.check_call([sys.executable, "-m", "pip3", "install", pkg])
                    print(f"[+] Successfully installed '{pkg}'.")
                except subprocess.CalledProcessError as e:
                    print(f"[-] Failed to install '{pkg}': {e}")
            print("\n[+] Dependency verification complete. Starting WiSight...\n")
            time.sleep(1)
        else:
            print("\n[!] Skipping dependency installation.")
            if "rich" in missing_packages:
                print("[!] Error: 'rich' is mandatory for rendering the interface. Exiting.")
                sys.exit(1)

bootstrap_dependencies()

# ---------------------------------------------------------------------------
# Platform-specific imports for non-blocking keypress detection
# ---------------------------------------------------------------------------
# On Windows we use the msvcrt console API. On POSIX systems (macOS, Linux)
# we use select() on stdin together with termios cbreak mode to read a single
# character without blocking the main telemetry loop.
if platform.system().lower() == "windows":
    import msvcrt
else:
    import select
    import termios
    import tty

# Import UI dependencies after bootstrapping
try:
    from rich.console import Console
    from rich.live import Live
    from rich.panel import Panel
    from rich.progress import BarColumn, Progress, TextColumn
    from rich.table import Table
except ImportError:
    print("[!] Error: 'rich' module is missing and required to run WiSight.")
    sys.exit(1)

# Optional Scapy import
# Scapy is only used for ARP-based active probing (see scan_devices). The
# script falls back to the OS arp cache when Scapy isn't present, so a
# missing Scapy is non-fatal — we just track availability in HAS_SCAPY.
HAS_SCAPY = False
try:
    from scapy.all import ARP, Ether, srp
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

# Console is the Rich output renderer used by every UI function below.
console = Console()

# ---------------------------------------------------------------------------
# Global caches and counters (module-level state, accessed by workers)
# ---------------------------------------------------------------------------
# DISCOVERED_DEVICES_CACHE: result of the most recent ARP scan, consumed by
#   the render loop in main().
# LAST_SCAN_TIME: timestamp of the last scan — used to throttle rescans to
#   once every 5 seconds so we don't hammer the arp cache.
# HOSTNAME_CACHE / VENDOR_CACHE: in-memory memoization for DNS and MAC-vendor
#   lookups (both are slow and may be rate-limited).
DISCOVERED_DEVICES_CACHE = []
LAST_SCAN_TIME = 0

HOSTNAME_CACHE = {}
VENDOR_CACHE = {}

# Live throughput values rendered on the dashboard. Updated once per second by
# update_live_throughput() and read by the render loop.
CURRENT_DOWNLOAD_SPEED = "0.00 B/s"
CURRENT_UPLOAD_SPEED = "0.00 B/s"

# Previous counter snapshots used to compute deltas. None until the first sample.
PREV_BYTES_SENT = None
PREV_BYTES_RECV = None
PREV_SPEED_TIME = None

# Known OUI (Organizationally Unique Identifier) prefixes. A MAC address's
# first 24 bits identify the manufacturer. This lookup table covers the most
# common vendors you're likely to see on a home/office Wi-Fi network.
KNOWN_OUIS = {
    "00:03:93": "Apple", "00:05:02": "Apple", "00:0A:95": "Apple", "00:0D:93": "Apple",
    "00:10:FA": "Apple", "00:11:24": "Apple", "00:14:A8": "Apple", "00:16:CB": "Apple",
    "28:CF:DA": "Apple", "3C:D0:F8": "Apple", "A4:83:E7": "Apple", "DC:A9:04": "Apple",
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
    "00:09:0C": "Sony", "00:13:A9": "Sony", "00:1A:80": "Sony", "00:1D:0D": "Sony",
    "00:02:78": "Samsung", "00:07:AB": "Samsung", "00:12:FB": "Samsung", "00:15:B9": "Samsung",
    "00:0F:66": "Cisco", "00:10:11": "Cisco", "00:14:69": "Cisco", "00:17:0E": "Cisco",
    "00:04:0E": "AVM", "00:1C:4A": "AVM", "00:05:5D": "D-Link", "00:0D:88": "D-Link",
    "00:11:95": "D-Link", "00:09:5B": "NETGEAR", "00:0E:9B": "NETGEAR", "00:14:6C": "NETGEAR",
    "00:0A:EB": "TP-Link", "00:14:78": "TP-Link", "00:1D:0F": "TP-Link",
}

# Global shutdown event to prevent thread leaks and hanging processes.
# All worker threads (resolver pool, async scanner) loop until this event
# is set, so they exit cleanly when the user quits or Ctrl-C is pressed.
SHUTDOWN_EVENT = threading.Event()


def sanitize_text(value, default="Unknown"):
    # Normalizes a raw field from any OS CLI output into something safe to
    # display. Returns the default for None, empty strings, or any value
    # containing a banned token (e.g. "redacted", "not associated") which
    # indicates the OS refused to give us a real value.
    if value is None:
        return default
    cleaned = str(value).strip()
    if not cleaned:
        return default
    lower = cleaned.lower()
    banned_tokens = ("redacted", "not associated", "unavailable", "network type")
    if any(token in lower for token in banned_tokens):
        return default
    return cleaned


def format_bytes_per_sec(bytes_sec):
    # Renders a byte-rate as a human-readable string. Thresholds use the
    # binary 1 KiB = 1024 B convention (matches what users see in macOS/
    # Linux "Activity Monitor" / "System Monitor" tools).
    if bytes_sec >= 1024 * 1024:
        return f"{bytes_sec / (1024 * 1024):.2f} MB/s"
    elif bytes_sec >= 1024:
        return f"{bytes_sec / 1024:.1f} KB/s"
    else:
        return f"{bytes_sec:.0f} B/s"


def run_command(cmd_args, timeout=1.0):
    # Wraps subprocess.check_output with sensible defaults for telemetry calls:
    #   - Short timeout to keep the UI responsive
    #   - stderr discarded (CLI utilities spam unrelated warnings)
    #   - On POSIX, prepends /usr/sbin and /sbin to PATH so tools like arp
    #     and networksetup are findable even from non-interactive shells
    #   - preexec_fn=os.setsid creates a new process group so we can kill the
    #     whole tree if shutdown is requested
    # Returns "" on any failure rather than raising — the UI treats empty
    # output as "no data available" rather than crashing.
    if SHUTDOWN_EVENT.is_set():
        return ""
    env = dict(os.environ)
    os_type = platform.system().lower()
    if os_type != "windows":
        env["PATH"] = "/usr/sbin:/sbin:/usr/bin:/bin:" + env.get("PATH", "")
    try:
        kwargs = {
            "stderr": subprocess.DEVNULL,
            "text": True,
            "errors": "ignore",
            "env": env,
            "timeout": timeout,
        }
        if os.name == "posix":
            kwargs["preexec_fn"] = os.setsid
        return subprocess.check_output(cmd_args, **kwargs)
    except Exception:
        return ""


def check_key_pressed():
    # Non-blocking check for whether the user has pressed 'q' to quit.
    # On Windows, msvcrt.kbhit() tells us if a key is buffered.
    # On POSIX, we briefly poll stdin with a 0-second select(). The check
    # is guarded by isatty() so we don't block on redirected input.
    if platform.system().lower() == "windows":
        if msvcrt.kbhit():
            ch = msvcrt.getch().decode("utf-8", errors="ignore").lower()
            return ch == "q"
    else:
        if not sys.stdin.isatty():
            return False
        dr, _, _ = select.select([sys.stdin], [], [], 0)
        if dr:
            ch = sys.stdin.read(1).lower()
            return ch == "q"
    return False


def run_prereq_diagnostics():
    """Renders a visual pre-flight check of system environment components."""
    console.clear()

    table = Table(
        title="[bold white]Pre-flight System Diagnostics[/bold white]",
        show_header=True,
        header_style="bold cyan",
        expand=True,
    )
    table.add_column("Component", style="bold yellow")
    table.add_column("Requirement / Context", style="white")
    table.add_column("Status", justify="center")

    # 1. Python Version Check
    py_ver_str = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    if sys.version_info >= (3, 8):
        table.add_row("Python Runtime", f"v{py_ver_str} (Python 3.8+ required)", "[bold green]PASS[/bold green]")
    else:
        table.add_row("Python Runtime", f"v{py_ver_str} (3.8+ recommended)", "[bold yellow]WARN[/bold yellow]")

    # 2. Operating System Identification (using platform module)
    os_name = platform.system()
    os_rel = platform.release()
    os_type = os_name.lower()

    if os_type == "darwin":
        table.add_row("Operating System", f"macOS ({os_rel})", "[bold green]PASS[/bold green]")
    elif os_type == "linux":
        table.add_row("Operating System", f"Linux ({os_rel})", "[bold green]PASS[/bold green]")
    elif os_type == "windows":
        table.add_row("Operating System", f"Windows ({os_rel})", "[bold green]PASS[/bold green]")
    else:
        table.add_row("Operating System", f"Unknown ({os_name} {os_rel})", "[bold yellow]WARN[/bold yellow]")

    # 3. Dynamic Native Network CLI Utilities Resolution
    required_tools = []
    if os_type == "darwin":
        required_tools = ["arp", "networksetup", "netstat"]
    elif os_type == "windows":
        required_tools = ["arp", "netsh", "netstat"]
    elif os_type == "linux":
        if shutil.which("ip"):
            required_tools.append("ip")
        elif shutil.which("arp"):
            required_tools.append("arp")

        if shutil.which("nmcli"):
            required_tools.append("nmcli")
        elif shutil.which("iw"):
            required_tools.append("iw")
        elif shutil.which("iwconfig"):
            required_tools.append("iwconfig")

    missing_tools = [tool for tool in required_tools if shutil.which(tool) is None]
    if required_tools and not missing_tools:
        table.add_row("Native CLI Utilities", f"Found: {', '.join(required_tools)}", "[bold green]PASS[/bold green]")
    elif missing_tools:
        table.add_row("Native CLI Utilities", f"Missing: {', '.join(missing_tools)}", "[bold yellow]WARN[/bold yellow]")
    else:
        table.add_row("Native CLI Utilities", "No native CLI utilities detected", "[bold yellow]WARN[/bold yellow]")

    # 4. Rich Render Framework
    table.add_row("Rich UI Framework", "Module loaded successfully", "[bold green]PASS[/bold green]")

    # 5. Scapy Network Framework Status
    scapy_status = "[bold green]PASS (Loaded)[/bold green]" if HAS_SCAPY else "[bold yellow]OPTIONAL (Missing)[/bold yellow]"
    table.add_row("Scapy Engine", "Packet Inspection / Active Probe Support", scapy_status)

    panel = Panel(
        table,
        title="[bold white]WiSight - Environment Verification[/bold white]",
        subtitle="[dim white]Launching telemetry monitoring engine...[/dim white]",
        border_style="bright_blue",
    )
    console.print(panel)
    time.sleep(2.0)


def get_interface_bytes():
    """Cross-platform byte count retrieval (macOS, Linux, Windows)."""
    # Returns cumulative (sent_total, recv_total) byte counters on the primary
    # network interface. The exact source differs per OS but the meaning is
    # the same: lifetime bytes transmitted and received since boot. The
    # caller (update_live_throughput) uses these to compute rate by diffing
    # successive samples.
    sent_total, recv_total = 0, 0
    os_type = platform.system().lower()

    if os_type == "darwin":
        out = run_command(["netstat", "-ib"], timeout=0.8)
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 10 and parts[0].startswith("en"):
                try:
                    recv_total += int(parts[6])
                    sent_total += int(parts[9])
                except (ValueError, IndexError):
                    continue
    elif os_type == "linux":
        try:
            with open("/proc/net/dev", "r") as f:
                lines = f.readlines()[2:]
                for line in lines:
                    if ":" in line:
                        iface, data = line.split(":", 1)
                        iface = iface.strip()
                        if iface != "lo":
                            parts = data.split()
                            if len(parts) >= 9:
                                recv_total += int(parts[0])
                                sent_total += int(parts[8])
        except Exception:
            pass
    elif os_type == "windows":
        out = run_command(["netstat", "-e"], timeout=0.8)
        lines = out.splitlines()
        for line in lines:
            if "Bytes" in line or "Bytes" in line.title():
                parts = re.findall(r"\d+", line)
                if len(parts) >= 2:
                    recv_total = int(parts[0])
                    sent_total = int(parts[1])
                    break

    return sent_total, recv_total


def update_live_throughput():
    # Computes live upload/download rates by sampling byte counters twice
    # (with at least one prior sample in PREV_*) and dividing the delta by
    # the elapsed wall-clock time. Updates the module-level CURRENT_*_SPEED
    # strings which the render loop in main() reads each second.
    # The max(0, ...) guards against counter wrap-around on long uptimes.
    global PREV_BYTES_SENT, PREV_BYTES_RECV, PREV_SPEED_TIME
    global CURRENT_DOWNLOAD_SPEED, CURRENT_UPLOAD_SPEED

    now = time.time()
    sent, recv = get_interface_bytes()

    if PREV_SPEED_TIME is not None and PREV_BYTES_SENT is not None:
        elapsed = now - PREV_SPEED_TIME
        if elapsed > 0:
            sent_delta = max(0, sent - PREV_BYTES_SENT)
            recv_delta = max(0, recv - PREV_BYTES_RECV)

            CURRENT_UPLOAD_SPEED = format_bytes_per_sec(sent_delta / elapsed)
            CURRENT_DOWNLOAD_SPEED = format_bytes_per_sec(recv_delta / elapsed)

    PREV_BYTES_SENT = sent
    PREV_BYTES_RECV = recv
    PREV_SPEED_TIME = now


def get_mac_vendor(mac):
    # Resolves a MAC address to a vendor/manufacturer name using a three-tier
    # lookup: in-memory cache -> local OUI table -> remote API (maclookup.app).
    # The remote API call has a 0.5s timeout and is treated as best-effort;
    # any failure falls through to None so the caller can label the device
    # generically. Results are cached forever in VENDOR_CACHE.
    if not mac or mac == "UNKNOWN" or SHUTDOWN_EVENT.is_set():
        return None

    mac_prefix = mac.upper()[:8]
    if mac_prefix in VENDOR_CACHE:
        return VENDOR_CACHE[mac_prefix]

    if mac_prefix in KNOWN_OUIS:
        vendor = KNOWN_OUIS[mac_prefix]
        VENDOR_CACHE[mac_prefix] = vendor
        return vendor

    try:
        url = f"https://api.maclookup.app/v2/macs/{mac}"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=0.5) as response:
            data = json.loads(response.read().decode())
            if data.get("success") and data.get("company"):
                company = data["company"].strip()
                if company and company.lower() != "unknown":
                    short_company = company.split(" ")[0].replace(",", "")
                    VENDOR_CACHE[mac_prefix] = short_company
                    return short_company
    except Exception:
        pass

    VENDOR_CACHE[mac_prefix] = None
    return None


def resolve_hostname(ip, mac=""):
    # Two-stage name resolution: first try a reverse DNS lookup
    # (socket.gethostbyaddr), and if that fails or returns a useless value
    # (literal IP, "unknown"), fall back to vendor-based labelling using
    # the MAC's OUI. Results are cached so we only pay the DNS cost once
    # per (ip, mac) pair.
    if SHUTDOWN_EVENT.is_set():
        return "Network Device"

    cache_key = f"{ip}_{mac}"
    if cache_key in HOSTNAME_CACHE:
        return HOSTNAME_CACHE[cache_key]

    resolved_name = None
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        if host and host != ip:
            resolved_name = host.rstrip(".")
    except Exception:
        pass

    if not resolved_name or resolved_name.lower() in ("unknown", ip):
        vendor = get_mac_vendor(mac)
        if vendor:
            resolved_name = f"{vendor} Device"
        else:
            resolved_name = "Network Device"

    HOSTNAME_CACHE[cache_key] = resolved_name
    return resolved_name


def get_band_from_channel(channel_raw):
    # Maps a raw channel/frequency string to a human-readable band label.
    # Accepts three input shapes: explicit "5 GHz" / "2.4 GHz" / "6 GHz"
    # strings, raw MHz frequencies (e.g. "5180"), and bare channel numbers.
    # Returns "Unknown" if the input can't be parsed. The channel-number
    # ranges follow IEEE 802.11: 1-14 for 2.4 GHz, 32-177 for 5 GHz,
    # 178-233 for 6 GHz.
    if not channel_raw:
        return "Unknown"

    try:
        raw_str = str(channel_raw).lower()

        if "6 ghz" in raw_str or "6g" in raw_str or "6ghz" in raw_str:
            ch_m = re.search(r"(\d+)", raw_str)
            ch_str = f" (Channel {ch_m.group(1)})" if ch_m else ""
            return f"6 GHz{ch_str}"
        elif "5 ghz" in raw_str or "5g" in raw_str or "5ghz" in raw_str:
            ch_m = re.search(r"(\d+)", raw_str)
            ch_str = f" (Channel {ch_m.group(1)})" if ch_m else ""
            return f"5 GHz{ch_str}"
        elif "2.4 ghz" in raw_str or "2.4g" in raw_str or "2.4ghz" in raw_str:
            ch_m = re.search(r"(\d+)", raw_str)
            ch_str = f" (Channel {ch_m.group(1)})" if ch_m else ""
            return f"2.4 GHz{ch_str}"

        freq_m = re.search(r"(\d{4})", raw_str)
        if freq_m:
            freq = int(freq_m.group(1))
            if 2400 <= freq <= 2500:
                ch = int((freq - 2407) / 5)
                return f"2.4 GHz (Channel {ch})"
            elif 5000 <= freq <= 5900:
                ch = int((freq - 5000) / 5)
                return f"5 GHz (Channel {ch})"
            elif 5925 <= freq <= 7125:
                ch = int((freq - 5950) / 5)
                return f"6 GHz (Channel {ch})"

        ch_match = re.search(r"(\d+)", raw_str)
        if not ch_match:
            return "Unknown"

        ch = int(ch_match.group(1))

        if 1 <= ch <= 14:
            return f"2.4 GHz (Channel {ch})"
        elif 32 <= ch <= 177:
            return f"5 GHz (Channel {ch})"
        elif 178 <= ch <= 233:
            return f"6 GHz (Channel {ch})"
    except (ValueError, TypeError):
        pass

    return "Unknown"


def get_wifi_details_mac():
    # macOS-specific Wi-Fi telemetry collector. Tries three OS commands in
    # sequence (ipconfig, networksetup, system_profiler) and falls through
    # to wdutil/system_profiler as needed to fill in missing fields. macOS
    # has fragmented this info across multiple CLIs over different versions,
    # which is why the cascade is necessary.
    ssid, bssid, signal_pct, rssi_dbm, band = "Unknown", "Unknown", 0, None, "Unknown"

    iface = "en0"
    hw_out = run_command(["networksetup", "-listallhardwareports"], timeout=0.8)
    lines = hw_out.splitlines()
    for i, line in enumerate(lines):
        if "Wi-Fi" in line or "AirPort" in line:
            if i + 1 < len(lines):
                m = re.search(r"Device:\s*(en\d+)", lines[i + 1])
                if m:
                    iface = m.group(1)
                    break

    def is_mac_addr(val):
        return bool(re.match(r"^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$", val))

    summary = run_command(["ipconfig", "getsummary", iface], timeout=0.8)
    if summary:
        s_m = re.search(r"^\s*SSID\s*:\s*(.+)$", summary, re.M | re.I)
        if s_m:
            extracted = sanitize_text(s_m.group(1))
            if extracted != "Unknown" and not is_mac_addr(extracted):
                ssid = extracted

    if ssid == "Unknown":
        netsetup = run_command(["networksetup", "-getairportnetwork", iface], timeout=0.8)
        ns_match = re.search(r"Current Wi-Fi Network:\s*(.+)$", netsetup, re.I)
        if ns_match:
            extracted = sanitize_text(ns_match.group(1))
            if extracted != "Unknown" and not is_mac_addr(extracted):
                ssid = extracted

    if ssid == "Unknown":
        sp_out = run_command(["system_profiler", "SPAirPortDataType"], timeout=1.5)
        sp_match = re.search(r"Current Network Information:\s*\n\s*([^:\n]+):", sp_out)
        if sp_match:
            extracted = sanitize_text(sp_match.group(1))
            if extracted != "Unknown" and not is_mac_addr(extracted):
                ssid = extracted

    if summary:
        bssid_m = re.search(r"BSSID\s*:\s*([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})", summary, re.I)
        if bssid_m:
            formatted_bssid = ":".join([p.zfill(2) for p in bssid_m.group(1).split(":")])
            bssid = sanitize_text(formatted_bssid).upper()

        chan_m = re.search(r"Channel\s*:\s*([^\r\n]+)", summary, re.I)
        if chan_m:
            band = get_band_from_channel(chan_m.group(1))

        rssi_m = re.search(r"RSSI\s*:\s*(-?\d+)", summary, re.I)
        if rssi_m:
            rssi_dbm = int(rssi_m.group(1))
            signal_pct = max(0, min(100, int((rssi_dbm + 100) * 2)))

    if band == "Unknown":
        wd_out = run_command(["wdutil", "info"], timeout=1.0)
        if wd_out:
            ch_wd = re.search(r"Channel\s*:\s*([^\r\n]+)", wd_out, re.I)
            if ch_wd:
                band = get_band_from_channel(ch_wd.group(1))

            freq_wd = re.search(r"Channel\s*Band\s*:\s*([^\r\n]+)", wd_out, re.I)
            if freq_wd and band == "Unknown":
                band = get_band_from_channel(freq_wd.group(1))

    if band == "Unknown" or bssid == "Unknown":
        sp_out = run_command(["system_profiler", "SPAirPortDataType"], timeout=1.5)

        if bssid == "Unknown":
            b_sp = re.search(r"BSSID:\s*([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})", sp_out, re.I)
            if b_sp:
                formatted_bssid = ":".join([p.zfill(2) for p in b_sp.group(1).split(":")])
                bssid = sanitize_text(formatted_bssid).upper()

        if band == "Unknown":
            ch_sp = re.search(r"Channel:\s*([^\r\n]+)", sp_out, re.I)
            if ch_sp:
                band = get_band_from_channel(ch_sp.group(1))

    if rssi_dbm is None and ssid != "Unknown":
        signal_pct = 85
        rssi_dbm = -58

    return ssid, bssid, signal_pct, rssi_dbm, band


def get_wifi_details_windows():
    # Windows Wi-Fi telemetry collector. Pulls everything from a single
    # `netsh wlan show interfaces` call and parses the output with regexes.
    # RSSI is reported as a percentage on Windows, so we map percent back
    # to dBm using the standard (percent/2) - 100 conversion.
    ssid, bssid, signal_pct, rssi_dbm, band = "Unknown", "Unknown", 0, None, "Unknown"
    out = run_command(["netsh", "wlan", "show", "interfaces"], timeout=1.0)

    ssid_m = re.search(r"^\s*SSID\s*:\s*(.+)$", out, re.M | re.I)
    if ssid_m:
        ssid = sanitize_text(ssid_m.group(1))

    bssid_m = re.search(r"BSSID\s*:\s*([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", out, re.I)
    if bssid_m:
        bssid = sanitize_text(bssid_m.group(1)).upper()

    sig_m = re.search(r"Signal\s*:\s*(\d+)%", out, re.I)
    if sig_m:
        signal_pct = int(sig_m.group(1))
        rssi_dbm = int((signal_pct / 2) - 100)

    chan_m = re.search(r"Channel\s*:\s*(\d+)", out, re.I)
    if chan_m:
        band = get_band_from_channel(chan_m.group(1))

    band_m = re.search(r"Band\s*:\s*(.+)$", out, re.M | re.I)
    if band_m and band == "Unknown":
        band = sanitize_text(band_m.group(1))

    radio_m = re.search(r"Radio type\s*:\s*(.+)$", out, re.M | re.I)
    if radio_m and band == "Unknown":
        band = sanitize_text(radio_m.group(1))

    return ssid, bssid, signal_pct, rssi_dbm, band


def get_wifi_details_linux():
    # Linux Wi-Fi telemetry collector. Tries three sources in priority order:
    #   1. nmcli (NetworkManager) — preferred, structured output
    #   2. iwconfig — legacy but widely available
    #   3. iw dev <iface> link — modern iw command, used per-interface
    # Returns the first source that produces useful data.
    ssid, bssid, signal_pct, rssi_dbm, band = "Unknown", "Unknown", 0, None, "Unknown"

    nm_out = run_command(["nmcli", "-t", "-f", "ACTIVE,SSID,BSSID,SIGNAL,CHAN", "dev", "wifi"], timeout=1.0)
    if nm_out:
        for line in nm_out.splitlines():
            if line.startswith("yes:") or line.startswith("YES:"):
                parts = line.split(":")
                if len(parts) >= 5:
                    ssid = sanitize_text(parts[1])
                    bssid_raw = ":".join(parts[2:-2]) if len(parts) > 5 else parts[2]
                    bssid = sanitize_text(bssid_raw).upper()
                    try:
                        signal_pct = int(parts[-2])
                        rssi_dbm = int((signal_pct / 2) - 100)
                    except ValueError:
                        pass
                    band = get_band_from_channel(parts[-1])
                    return ssid, bssid, signal_pct, rssi_dbm, band

    iwc_out = run_command(["iwconfig"], timeout=1.0)
    if iwc_out:
        ssid_m = re.search(r'ESSID:"([^"]+)"', iwc_out)
        if ssid_m:
            ssid = sanitize_text(ssid_m.group(1))

        bssid_m = re.search(r"Access Point:\s*([0-9a-fA-F:]{17})", iwc_out, re.I)
        if bssid_m:
            bssid = sanitize_text(bssid_m.group(1)).upper()

        sig_m = re.search(r"Signal level=(-?\d+)\s*dBm", iwc_out, re.I)
        if sig_m:
            rssi_dbm = int(sig_m.group(1))
            signal_pct = max(0, min(100, int((rssi_dbm + 100) * 2)))

        freq_m = re.search(r"Frequency:(\d+\.\d+\s*GHz)", iwc_out, re.I)
        if freq_m:
            band = get_band_from_channel(freq_m.group(1))

    if ssid == "Unknown":
        dev_out = run_command(["iw", "dev"], timeout=1.0)
        ifaces = re.findall(r"Interface\s+([^\s]+)", dev_out)
        for iface in ifaces:
            link_out = run_command(["iw", "dev", iface, "link"], timeout=1.0)
            if "Connected to" in link_out:
                b_m = re.search(r"Connected to\s*([0-9a-fA-F:]{17})", link_out, re.I)
                if b_m:
                    bssid = sanitize_text(b_m.group(1)).upper()

                s_m = re.search(r"SSID:\s*(.+)", link_out, re.I)
                if s_m:
                    ssid = sanitize_text(s_m.group(1))

                sig_m = re.search(r"signal:\s*(-?\d+)\s*dBm", link_out, re.I)
                if sig_m:
                    rssi_dbm = int(sig_m.group(1))
                    signal_pct = max(0, min(100, int((rssi_dbm + 100) * 2)))

                freq_m = re.search(r"freq:\s*(\d+)", link_out, re.I)
                if freq_m:
                    band = get_band_from_channel(freq_m.group(1))
                break

    return ssid, bssid, signal_pct, rssi_dbm, band


def get_wifi_details():
    # Platform dispatcher — picks the right Wi-Fi collector for the host OS.
    # Returning ("Unknown" * 5) for unknown platforms keeps the render loop
    # safe (no KeyError) and just shows "not connected" in the UI.
    os_type = platform.system().lower()
    if os_type == "windows":
        return get_wifi_details_windows()
    elif os_type == "darwin":
        return get_wifi_details_mac()
    elif os_type == "linux":
        return get_wifi_details_linux()
    return "Unknown", "Unknown", 0, None, "Unknown"


def parse_arp_fallback():
    # Reads the OS ARP cache and returns a list of (ip, mac) tuples.
    # Tries multiple command formats because arp output differs by OS:
    #   - macOS / BSD: `arp -an` (numeric, no DNS lookups)
    #   - Windows: `arp -a`
    #   - Linux: `arp -an` and `ip neigh` (modern replacement)
    # Both regexes tolerate either `:` or `-` MAC separators since some
    # Windows versions print with hyphens.
    ip_mac_pairs = []
    os_type = platform.system().lower()

    cmd = ["arp", "-a"] if os_type == "windows" else ["arp", "-an"]
    out = run_command(cmd, timeout=0.8)

    matches = re.findall(r"\(?(\d+\.\d+\.\d+\.\d+)\)?\s+at\s+([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})", out)

    if not matches:
        matches = re.findall(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})", out)

    if not matches and os_type == "linux":
        ip_out = run_command(["ip", "neigh"], timeout=0.8)
        matches = re.findall(r"(\d+\.\d+\.\d+\.\d+)\s+.*lladdr\s+([0-9a-fA-F:]{17})", ip_out)

    for ip, mac in matches:
        mac_clean = mac.replace("-", ":")
        mac_formatted = ":".join([p.zfill(2) for p in mac_clean.split(":")])
        ip_mac_pairs.append((ip, mac_formatted.upper()))

    return ip_mac_pairs


def worker_resolve(task_queue, results_list):
    # Thread-pool worker that drains the device-resolution queue. Each task
    # is a (ip, mac, current_bssid) tuple; the worker calls resolve_hostname
    # (which may do a DNS lookup and/or vendor API call) and appends the
    # result. The current_bssid is used to tag the gateway/AP entry with a
    # special bold-green label in the device table.
    while not SHUTDOWN_EVENT.is_set():
        try:
            ip, mac, current_bssid = task_queue.get_nowait()
        except queue.Empty:
            break

        hostname = resolve_hostname(ip, mac)
        if current_bssid != "Unknown" and mac.upper() == current_bssid.upper():
            hostname = f"[bold green]{hostname} (Connected AP / Gateway)[/]"

        results_list.append({"ip": ip, "mac": mac, "hostname": hostname})
        task_queue.task_done()


def scan_devices(current_bssid):
    # Full device-discovery cycle:
    #   1. Read & filter the ARP cache (drop multicast, broadcast, empty MACs)
    #   2. Cap the work queue at 30 entries to bound scan time
    #   3. Spawn up to 8 daemon threads to resolve hostnames in parallel
    #   4. Join with a 0.1s per-thread timeout — DNS lookups that hang won't
    #      stall the rest of the UI; the next scan cycle will retry them.
    # Returns a list of dicts: [{"ip": ..., "mac": ..., "hostname": ...}, ...]
    if SHUTDOWN_EVENT.is_set():
        return []

    ip_mac_pairs = parse_arp_fallback()

    seen_ips = set()
    filtered_pairs = []

    for ip, mac in ip_mac_pairs:
        if ip in seen_ips:
            continue
        if (
            ip.startswith("224.")
            or ip.startswith("239.")
            or ip.endswith(".255")
            or mac in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00")
        ):
            continue
        seen_ips.add(ip)
        filtered_pairs.append((ip, mac))

    if SHUTDOWN_EVENT.is_set():
        return []

    task_queue = queue.Queue()
    for ip, mac in filtered_pairs[:30]:
        task_queue.put((ip, mac, current_bssid))

    results_list = []
    threads = []

    for _ in range(min(8, max(1, task_queue.qsize()))):
        t = threading.Thread(target=worker_resolve, args=(task_queue, results_list), daemon=True)
        t.start()
        threads.append(t)

    for t in threads:
        t.join(timeout=0.1)

    return results_list


def update_devices_async(current_bssid):
    # Non-blocking wrapper around scan_devices(), intended to be called as
    # the target of a daemon thread so the main render loop never stalls
    # waiting for a full ARP + DNS sweep. Updates DISCOVERED_DEVICES_CACHE
    # and bumps LAST_SCAN_TIME on completion.
    global DISCOVERED_DEVICES_CACHE, LAST_SCAN_TIME
    if SHUTDOWN_EVENT.is_set():
        return
    results = scan_devices(current_bssid)
    if results and not SHUTDOWN_EVENT.is_set():
        DISCOVERED_DEVICES_CACHE = results
    LAST_SCAN_TIME = time.time()


def main():
    # Top-level render loop. Each iteration:
    #   1. Check if 'q' was pressed (graceful shutdown)
    #   2. Sample throughput counters
    #   3. Pull current Wi-Fi details (SSID, BSSID, RSSI, band)
    #   4. If 5+ seconds since last ARP scan, kick off a new scan in a daemon thread
    #   5. Detect roaming (BSSID change) and increment the counter
    #   6. Build the Rich layout (AP table + signal bar + device table) and update Live
    #   7. Sleep 1 second, repeat
    #
    # The Live context manager handles screen redraw. The termios cbreak
    # mode around the loop ensures single-key reads without Enter. The
    # finally block restores the terminal to its original mode so the
    # user's shell isn't left in a broken state.
    global DISCOVERED_DEVICES_CACHE, LAST_SCAN_TIME

    # Run system prerequisite verification panel before startup
    run_prereq_diagnostics()

    console.clear()
    last_bssid = None
    roaming_events = 0

    old_settings = None
    if platform.system().lower() != "windows" and sys.stdin.isatty():
        try:
            old_settings = termios.tcgetattr(sys.stdin)
            tty.setcbreak(sys.stdin.fileno())
        except Exception:
            pass

    try:
        with Live(refresh_per_second=1, console=console) as live:
            while not SHUTDOWN_EVENT.is_set():
                if check_key_pressed():
                    SHUTDOWN_EVENT.set()

                    # Pop-up notification overlay inside terminal
                    exit_panel = Panel(
                        "[bold yellow]'q' pressed, exiting cleanly...[/bold yellow]\n[dim white]Shutting down telemetry threads and restoring terminal.[/dim white]",
                        title="[bold white]WiSight - Shutdown[/bold white]",
                        border_style="yellow",                       
                    )
                    live.update(exit_panel)
                    time.sleep(2.0)
                    # Second Panel: Final confirmation, shown briefly before the loop breaks
                    final_panel = Panel(
                        "[bold green]Telemetry threads terminated.[/bold green]\n[dim white]Network state is intact. Goodbye![/dim white]",
                        title="[bold white]WiSight - Shutdown Complete[/bold white]",
                        border_style="green",
                    )
                    live.update(final_panel)
                    break

                update_live_throughput()
                ssid, bssid, signal_pct, rssi_dbm, band = get_wifi_details()

                if time.time() - LAST_SCAN_TIME > 5 and not SHUTDOWN_EVENT.is_set():
                    threading.Thread(target=update_devices_async, args=(bssid,), daemon=True).start()

                previous_ap = None
                if last_bssid is not None and bssid != "Unknown" and bssid != last_bssid:
                    roaming_events += 1
                    previous_ap = last_bssid

                if bssid != "Unknown":
                    last_bssid = bssid

                bar_style = "green" if signal_pct >= 70 else "yellow" if signal_pct >= 40 else "red"
                signal_label = (
                    f"[bold {bar_style}]{signal_pct}%[/] ({rssi_dbm} dBm)"
                    if rssi_dbm is not None
                    else f"[bold {bar_style}]{signal_pct}%[/]"
                )

                progress = Progress(
                    TextColumn("[bold]Signal:[/]"),
                    BarColumn(bar_width=40, complete_style=bar_style, finished_style=bar_style),
                    TextColumn(signal_label),
                )
                progress.add_task("signal", total=100, completed=signal_pct)

                if bssid == "Unknown" and ssid == "Unknown":
                    status = "[bold red]Not connected[/]"
                elif previous_ap is not None:
                    status = f"[bold magenta]ROAMED from {previous_ap}[/]"
                else:
                    status = "[bold green]Connected[/]"

                ap_table = Table.grid(padding=(0, 2))
                ap_table.add_column(style="bold cyan")
                ap_table.add_column()
                ap_table.add_row("Status:", status)
                ap_table.add_row("Scan Mode:", "[bold green]Passive Telemetry Mode[/]")
                ap_table.add_row("SSID (Network):", ssid)
                ap_table.add_row("Connected AP (BSSID):", f"[bold yellow]{bssid}[/]")
                ap_table.add_row("Connection Type:", f"[bold magenta]{band}[/]")
                ap_table.add_row("Live Download Rate:", f"[bold green]↓ {CURRENT_DOWNLOAD_SPEED}[/]")
                ap_table.add_row("Live Upload Rate:", f"[bold blue]↑ {CURRENT_UPLOAD_SPEED}[/]")
                ap_table.add_row("Handovers:", str(roaming_events))

                dev_table = Table(
                    title="[bold white]Active Network Devices[/]",
                    show_header=True,
                    header_style="bold cyan",
                    expand=True,
                )
                dev_table.add_column("IP Address", style="yellow")
                dev_table.add_column("MAC Address", style="green")
                dev_table.add_column("Hostname / Device", style="bold white")

                if DISCOVERED_DEVICES_CACHE:
                    for dev in DISCOVERED_DEVICES_CACHE:
                        dev_table.add_row(dev["ip"], dev["mac"], dev["hostname"])
                else:
                    dev_table.add_row("Scanning...", "Scanning...", "Reading local ARP cache...")

                layout = Table.grid(expand=True)
                layout.add_row(ap_table)
                layout.add_row("")
                layout.add_row(progress)
                layout.add_row("")
                layout.add_row(dev_table)
                layout.add_row("")

                panel = Panel(
                    layout,
                    title="[bold white]WiSight[/bold white]",
                    subtitle="[dim white]Press [bold yellow]'q'[/bold yellow] at any time to safely terminate monitoring.[/dim white]",
                    subtitle_align="center",
                    border_style="bright_blue",
                )
                live.update(panel)

                time.sleep(1)

    finally:
        if old_settings and platform.system().lower() != "windows":
            try:
                termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
            except Exception:
                pass


if __name__ == "__main__":
    # Entry point. Catches KeyboardInterrupt (Ctrl-C) so the shutdown event
    # is set and worker threads can observe it; the finally block prints a
    # clean exit banner regardless of how main() returned.
    try:
        main()
    except KeyboardInterrupt:
        SHUTDOWN_EVENT.set()
