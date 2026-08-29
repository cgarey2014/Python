# Author: Chris Garey
# Date: 2024-06-15
# Description: WiSight - A cross-platform Wi-Fi monitoring tool that displays real-time connection details and scans for devices on the local network.

# import necessary modules
import json
import os
import re
import socket
import subprocess
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TextColumn
from rich.table import Table

# Optional Scapy import for raw socket access when running under sudo
HAS_SCAPY = False
try:
    from scapy.all import ARP, Ether, srp
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

# Initialize Rich console for output
console = Console()

# Global variables for caching discovered devices and scan timing
DISCOVERED_DEVICES_CACHE = []
LAST_SCAN_TIME = 0

HOSTNAME_CACHE = {}
VENDOR_CACHE = {}

# Known Organizationally Unique Identifiers (OUIs) for MAC address vendor lookup
KNOWN_OUIS = {
    "00:03:93": "Apple", "00:05:02": "Apple", "00:0A:95": "Apple", "00:0D:93": "Apple",
    "00:10:FA": "Apple", "00:11:24": "Apple", "00:14:A8": "Apple", "00:16:CB": "Apple",
    "28:CF:DA": "Apple", "3C:D0:F8": "Apple", "A4:83:E7": "Apple", "DC:A9:04": "Apple",
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
    "00:09:0C": "Sony", "00:13:A9": "Sony", "00:1A:80": "Sony", "00:1D:0D": "Sony",
    "00:02:78": "Samsung", "00:07:AB": "Samsung", "00:12:FB": "Samsung", "00:15:B9": "Samsung",
    "00:0F:66": "Cisco", "00:10:11": "Cisco", "00:14:69": "Cisco", "00:17:0E": "Cisco",
    "00:04:0E": "AVM (Fritz!Box)", "00:1C:4A": "AVM (Fritz!Box)",
    "00:05:5D": "D-Link", "00:0D:88": "D-Link", "00:11:95": "D-Link",
    "00:09:5B": "NETGEAR", "00:0E:9B": "NETGEAR", "00:14:6C": "NETGEAR",
    "00:0A:EB": "TP-Link", "00:14:78": "TP-Link", "00:1D:0F": "TP-Link",
}

# Function to sanitize text values, replacing empty or banned values with a default
def sanitize_text(value, default="Unknown"):
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

# Function to get the vendor name from a MAC address using known OUIs or an external API
def get_mac_vendor(mac):
    if not mac or mac == "UNKNOWN":
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
        with urllib.request.urlopen(req, timeout=0.8) as response:
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

# Function to resolve the hostname for a given IP address, with caching and fallback methods
def resolve_hostname(ip, mac=""):
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

    if not resolved_name:
        try:
            cmd = ["nslookup", ip]
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True, errors="ignore", timeout=0.5)
            match = re.search(r"name\s*=\s*(.+)$", out, re.MULTILINE | re.IGNORECASE)
            if match:
                resolved_name = match.group(1).strip().rstrip(".")
        except Exception:
            pass

    if resolved_name:
        resolved_name = re.sub(r"\.(lan|home|localdomain|local)$", "", resolved_name, flags=re.I)

    if not resolved_name or resolved_name.lower() in ("unknown", ip):
        vendor = get_mac_vendor(mac)
        if vendor:
            resolved_name = f"{vendor} Device"
        else:
            resolved_name = "Network Device"

    HOSTNAME_CACHE[cache_key] = resolved_name
    return resolved_name

# Function to run system commands with proper environment setup
def run_command(cmd_args):
    """Executes system commands with explicit search path handling for sudo."""
    env = dict(os.environ)
    env["PATH"] = "/usr/sbin:/sbin:/usr/bin:/bin:" + env.get("PATH", "")
    try:
        return subprocess.check_output(
            cmd_args, stderr=subprocess.DEVNULL, text=True, errors="ignore", env=env
        )
    except Exception:
        return ""

# Function to get Wi-Fi details on macOS using multiple methods
def get_wifi_details_mac():
    ssid, bssid, signal_pct, rssi_dbm, band = "Unknown", "Unknown", 0, None, "Unknown"
    combined_output = ""

    # 1. Try ipconfig getsummary en0
    summary = run_command(["/usr/sbin/ipconfig", "getsummary", "en0"])
    if not summary:
        summary = run_command(["ipconfig", "getsummary", "en0"])

    combined_output += summary

    bssid_match = re.search(r"BSSID\s*:\s*([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", summary, re.I)
    if bssid_match:
        bssid = sanitize_text(bssid_match.group(1)).upper()

    ssid_matches = re.findall(r"^\s*SSID\s*:\s*(.+)$", summary, re.MULTILINE | re.I)
    for match in ssid_matches:
        cleaned = sanitize_text(match)
        if cleaned != "Unknown":
            ssid = cleaned
            break

    # 2. Try airport tool
    airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
    if os.path.exists(airport_path):
        airport_out = run_command([airport_path, "-I"])
        combined_output += airport_out

        if ssid == "Unknown":
            s_match = re.search(r"^\s*SSID\s*:\s*(.+)$", airport_out, re.M | re.I)
            if s_match:
                ssid = sanitize_text(s_match.group(1))

        if bssid == "Unknown":
            b_match = re.search(r"BSSID\s*:\s*([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", airport_out, re.I)
            if b_match:
                bssid = sanitize_text(b_match.group(1)).upper()

        rssi_match = re.search(r"agrCtlRSSI\s*:\s*(-?\d+)", airport_out)
        if rssi_match:
            rssi_dbm = int(rssi_match.group(1))

    # 3. Fallback for RSSI via wdutil
    if rssi_dbm is None:
        wd_out = run_command(["wdutil", "info"])
        combined_output += wd_out
        rssi_match = re.search(r"RSSI\s*:\s*(-?\d+)", wd_out)
        if rssi_match:
            rssi_dbm = int(rssi_match.group(1))

    # 4. Fallback for SSID via networksetup
    if ssid == "Unknown":
        netsetup_out = run_command(["networksetup", "-getairportnetwork", "en0"])
        ns_match = re.search(r"Current Wi-Fi Network:\s*(.+)$", netsetup_out, re.I)
        if ns_match:
            ssid = sanitize_text(ns_match.group(1))

    # Calculate signal percentage
    if rssi_dbm is not None:
        signal_pct = max(0, min(100, int((rssi_dbm + 100) * (100 / 70))))

    # Frequency Band Detection
    if re.search(r"6\s*GHz|59\d{2}\s*MHz|6\d{3}\s*MHz", combined_output, re.I):
        band = "6 GHz"
    elif re.search(r"5\s*GHz|5\d{3}\s*MHz", combined_output, re.I):
        band = "5 GHz"
    elif re.search(r"2\.4\s*GHz|24\d{2}\s*MHz", combined_output, re.I):
        band = "2.4 GHz"
    else:
        channel_match = re.search(r"channel\s*:\s*(\d+)", combined_output, re.IGNORECASE)
        if channel_match:
            ch = int(channel_match.group(1))
            if 1 <= ch <= 14:
                band = "2.4 GHz"
            elif 32 <= ch <= 177:
                band = "5 GHz"
            elif 178 <= ch <= 233:
                band = "6 GHz"

    return ssid, bssid, signal_pct, rssi_dbm, band

# Function to get Wi-Fi details on Windows using netsh command
def get_wifi_details_windows():
    ssid, bssid, signal_pct, rssi_dbm, band = "Unknown", "Unknown", 0, None, "Unknown"
    out = run_command(["netsh", "wlan", "show", "interfaces"])

    ssid_m = re.search(r"^\s*SSID\s*:\s*(.+)$", out, re.M)
    if ssid_m:
        ssid = sanitize_text(ssid_m.group(1))

    bssid_m = re.search(r"BSSID\s*:\s*([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", out)
    if bssid_m:
        bssid = sanitize_text(bssid_m.group(1)).upper()

    sig_m = re.search(r"Signal\s*:\s*(\d+)%", out)
    if sig_m:
        signal_pct = int(sig_m.group(1))
        rssi_dbm = int((signal_pct / 2) - 100)

    chan_m = re.search(r"Channel\s*:\s*(\d+)", out)
    if chan_m:
        ch = int(chan_m.group(1))
        if 1 <= ch <= 14:
            band = "2.4 GHz"
        elif 32 <= ch <= 177:
            band = "5 GHz"
        elif 178 <= ch <= 233:
            band = "6 GHz"

    return ssid, bssid, signal_pct, rssi_dbm, band

# Function to get Wi-Fi details on Linux using nmcli command
def get_wifi_details_linux():
    ssid, bssid, signal_pct, rssi_dbm, band = "Unknown", "Unknown", 0, None, "Unknown"
    out = run_command(["nmcli", "-t", "-f", "ACTIVE,SSID,BSSID,SIGNAL,FREQ", "dev", "wifi"])

    for line in out.splitlines():
        if line.startswith("yes:"):
            parts = line.split(":")
            if len(parts) >= 5:
                ssid = sanitize_text(parts[1])
                bssid = sanitize_text(":".join(parts[2:-2])).upper()
                signal_pct = int(parts[-2]) if parts[-2].isdigit() else 0
                rssi_dbm = int((signal_pct / 2) - 100)
                freq_m = re.search(r"(\d+)", parts[-1])
                if freq_m:
                    freq = int(freq_m.group(1))
                    if 2400 <= freq <= 2500:
                        band = "2.4 GHz"
                    elif 4900 <= freq <= 5899:
                        band = "5 GHz"
                    elif 5925 <= freq <= 7125:
                        band = "6 GHz"
            break

    return ssid, bssid, signal_pct, rssi_dbm, band

# Function to get Wi-Fi details based on the operating system
def get_wifi_details():
    if os.name == "nt":
        return get_wifi_details_windows()
    elif os.name == "posix":
        if os.path.exists("/System/Library/PrivateFrameworks/Apple80211.framework"):
            return get_wifi_details_mac()
        return get_wifi_details_linux()
    return "Unknown", "Unknown", 0, None, "Unknown"

# Function to determine the local IP subnet for ARP scanning
def get_local_ip_subnet():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        parts = ip.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    except Exception:
        return None

# Function to perform a raw ARP scan using Scapy when running under sudo
def raw_arp_scan_sudo():
    subnet = get_local_ip_subnet()
    if not subnet or not HAS_SCAPY:
        return []

    devices = []
    try:
        arp_req = ARP(pdst=subnet)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp_req
        answered, _ = srp(packet, timeout=1.5, verbose=False)

        for sent, received in answered:
            ip = received.psrc
            mac = received.hwsrc.upper()
            devices.append((ip, mac))
    except Exception:
        pass

    return devices

# Function to parse ARP table output as a fallback method for device discovery
def parse_arp_fallback():
    ip_mac_pairs = []
    if os.name == "nt":
        out = run_command(["arp", "-a"])
        matches = re.findall(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})", out)
        for ip, mac in matches:
            ip_mac_pairs.append((ip, mac.replace("-", ":").upper()))
    else:
        out = run_command(["arp", "-an"])
        matches = re.findall(r"(\d+\.\d+\.\d+\.\d+).*?\s([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})", out)
        for ip, mac in matches:
            mac_formatted = ":".join([p.zfill(2) for p in mac.split(":")])
            ip_mac_pairs.append((ip, mac_formatted.upper()))

    return ip_mac_pairs

# Function to scan for devices on the local network, filtering out duplicates and invalid entries
def scan_devices(current_bssid):
    ip_mac_pairs = raw_arp_scan_sudo() if HAS_SCAPY else []
    if not ip_mac_pairs:
        ip_mac_pairs = parse_arp_fallback()

    devices = []
    seen_ips = set()
    filtered_pairs = []

    for ip, mac in ip_mac_pairs:
        if ip in seen_ips:
            continue
        if ip.startswith("224.") or ip.startswith("239.") or ip.endswith(".255") or mac in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"):
            continue
        seen_ips.add(ip)
        filtered_pairs.append((ip, mac))

    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = {executor.submit(resolve_hostname, ip, mac): (ip, mac) for ip, mac in filtered_pairs[:20]}
        for future in futures:
            ip, mac = futures[future]
            hostname = future.result()

            if current_bssid != "Unknown" and mac.upper() == current_bssid.upper():
                hostname = f"[bold green]{hostname} (Connected AP / Gateway)[/]"

            devices.append({"ip": ip, "mac": mac, "hostname": hostname})

    return devices

# Function to update the discovered devices cache asynchronously
def update_devices_async(current_bssid):
    global DISCOVERED_DEVICES_CACHE, LAST_SCAN_TIME
    results = scan_devices(current_bssid)
    if results:
        DISCOVERED_DEVICES_CACHE = results
    LAST_SCAN_TIME = time.time()

# Main function to run the Wi-Fi monitoring tool with real-time updates
def main():
    global DISCOVERED_DEVICES_CACHE, LAST_SCAN_TIME
    console.clear()
    last_bssid = None
    roaming_events = 0

    with Live(refresh_per_second=1, console=console) as live:
        while True:
            ssid, bssid, signal_pct, rssi_dbm, band = get_wifi_details()

            if time.time() - LAST_SCAN_TIME > 8:
                threading.Thread(target=update_devices_async, args=(bssid,), daemon=True).start()

            previous_ap = None
            if last_bssid is not None and bssid != "Unknown" and bssid != last_bssid:
                roaming_events += 1
                previous_ap = last_bssid

            if bssid != "Unknown":
                last_bssid = bssid
            else:
                last_bssid = None

            bar_style = "green" if signal_pct >= 70 else "yellow" if signal_pct >= 40 else "red"
            signal_label = f"[bold {bar_style}]{signal_pct}%[/] ({rssi_dbm} dBm)" if rssi_dbm is not None else f"[bold {bar_style}]{signal_pct}%[/] (N/A)"

            progress = Progress(
                TextColumn("[bold]Signal:[/]"),
                BarColumn(bar_width=40, complete_style=bar_style, finished_style=bar_style),
                TextColumn(signal_label),
            )
            progress.add_task("signal", total=100, completed=signal_pct)

            if bssid == "Unknown" or ssid == "Unknown":
                status = "[bold red]Not connected[/]"
            elif previous_ap is not None:
                status = f"[bold magenta]ROAMED from {previous_ap}[/]"
            else:
                status = "[bold green]Connected[/]"

            mode_str = "[bold green]RAW ARP (SUDO Active)[/]" if HAS_SCAPY else "[bold yellow]Standard ARP Mode[/]"

            ap_table = Table.grid(padding=(0, 2))
            ap_table.add_column(style="bold cyan")
            ap_table.add_column()
            ap_table.add_row("Status:", status)
            ap_table.add_row("Scan Mode:", mode_str)
            ap_table.add_row("SSID (Network):", ssid)
            ap_table.add_row("Connected AP (BSSID):", f"[bold yellow]{bssid}[/]")
            ap_table.add_row("Connection Type:", f"[bold magenta]{band}[/]")
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
                dev_table.add_row("Scanning...", "Scanning...", "Executing raw Layer-2 ARP broadcast sweep...")

            layout = Table.grid(expand=True)
            layout.add_row(ap_table)
            layout.add_row("")
            layout.add_row(progress)
            layout.add_row("")
            layout.add_row(dev_table)

            panel = Panel(
                layout,
                title="[bold white]WiSight[/]",
                border_style="bright_blue",
            )
            live.update(panel)

            time.sleep(1)

# Entry point for the script, handling keyboard interrupts gracefully
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold red]Monitoring stopped.[/]")