#!/usr/bin/env python3
"""lanradar — one-file LAN radar: find out who is on your network.

Run it with no arguments and it finds your local subnet, sweeps it
(ARP table + ICMP ping sweep) and prints every live device with MAC
address and vendor (OUI) — optionally hostname, open ports and a
gateway marker.

  lanradar                                  # auto-detect local subnet
  lanradar 192.168.1.0/24                   # explicit CIDR
  lanradar 192.168.1.1-50 --rdns            # range + hostnames
  lanradar 192.168.1.0/24 --ports 22,80,443 # also check common ports
  lanradar --watch --interval 30            # alert on new/gone devices
  lanradar --state /var/lib/lanradar.json   # cron-friendly inventory

Watch mode keeps sweeping and prints a timestamped event whenever a
device joins (NEW) or leaves (GONE) the scanned range.

Responsible use: only scan networks you own or are explicitly
authorized to test.

Requires: Python 3.9+ (rich optional, for pretty tables)
"""
from __future__ import annotations

import argparse
import concurrent.futures
import csv
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence, Tuple

VERSION = "0.1.0"
USER_AGENT = "lanradar/%s" % VERSION

# --------------------------------------------------------------------------
# built-in OUI table (high-confidence prefixes only — use --oui full for
# the complete IEEE database)
# --------------------------------------------------------------------------

MINI_OUI: Dict[str, str] = {
    # virtual machines / hypervisors
    "00:50:56": "VMware",
    "08:00:27": "VMware",
    "00:0c:29": "Cisco (virtual)",
    "00:15:5d": "Microsoft (Hyper-V)",
    "52:54:00": "QEMU/KVM (virtual)",
    # Intel
    "00:1b:1c": "Intel",
    "00:1e:64": "Intel",
    "00:1f:29": "Intel",
    "00:22:15": "Intel",
    "00:24:d7": "Intel",
    "00:26:62": "Intel",
    "00:27:10": "Intel",
    "00:28:7b": "Intel",
    "00:60:2f": "Intel",
    "00:a0:d1": "Intel",
    "00:c2:c6": "Intel",
    "00:c6:4b": "Intel",
    "00:d8:61": "Intel",
    "3c:5a:b4": "Intel",
    "44:85:00": "Intel",
    "b8:59:9f": "Intel",
    "c4:54:44": "Intel",
    # Apple
    "00:1b:63": "Apple",
    "00:1d:4f": "Apple",
    "00:1f:52": "Apple",
    "00:23:24": "Apple",
    "00:26:bb": "Apple",
    "00:28:31": "Apple",
    "00:2c:76": "Apple",
    "00:42:a4": "Apple",
    "00:60:0d": "Apple",
    "00:a0:c9": "Apple",
    "a4:83:e7": "Apple",
    "ac:87:a3": "Apple",
    "c0:18:85": "Apple",
    "d0:5f:48": "Apple",
    "f8:1e:df": "Apple",
    # server boards / embedded
    "00:14:22": "Dell",
    "b8:27:eb": "Raspberry Pi Trading",
    "dc:a6:32": "Raspberry Pi Foundation",
    "24:a4:cc": "Ubiquiti (UniFi)",
    "00:17:f2": "Canon",
    "50:c7:bf": "TP-Link",
}

OUI_CACHE_DIR = os.path.join(
    os.environ.get("XDG_CACHE_HOME", os.path.expanduser("~/.cache")), "lanradar")
OUI_CACHE_FILE = os.path.join(OUI_CACHE_DIR, "oui.txt")
OII_URL = "https://standards-oui.ieee.org/oui/oui.txt"

PORT_NAMES: Dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 123: "ntp", 135: "msrpc", 139: "netbios", 143: "imap",
    161: "snmp", 389: "ldap", 443: "https", 445: "smb", 465: "smtps",
    587: "submission", 636: "ldaps", 993: "imaps", 995: "pop3s", 1433: "mssql",
    1521: "oracle", 1723: "pppoe", 1883: "mqtt", 2049: "nfs", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 5900: "vnc", 5984: "couchdb", 6379: "redis",
    8080: "http-alt", 8443: "https-alt", 9100: "prometheus", 9200: "elasticsearch",
}


# --------------------------------------------------------------------------
# data model
# --------------------------------------------------------------------------

@dataclass
class Device:
    ip: str
    mac: str = ""
    vendor: str = ""
    hostname: str = ""
    ports: List[int] = field(default_factory=list)
    alive: bool = False
    source: str = ""          # arp / icmp / ports
    gateway: bool = False
    first_seen: str = ""
    last_seen: str = ""
    event: str = ""           # "" | "new" | "gone"


# --------------------------------------------------------------------------
# target parsing
# --------------------------------------------------------------------------

def _expand_spec(spec: str) -> List[ipaddress.IPv4Address]:
    spec = spec.strip()
    if not spec:
        raise ValueError("empty target")
    if "/" in spec:
        net = ipaddress.ip_network(spec, strict=False)
        if net.num_addresses == 2:          # /31
            return [net.network_address, net.broadcast_address]
        if net.prefixlen >= 31:
            return [net.network_address]
        return list(net.hosts())
    if "-" in spec:
        lo_s, _, hi_s = spec.partition("-")
        lo_s, hi_s = lo_s.strip(), hi_s.strip()
        lo_i = ipaddress.IPv4Address(lo_s)
        if hi_s.count(".") < 3:             # shorthand: 192.168.1.10-50
            base, _, _last = lo_s.rpartition(".")
            if not base or not hi_s.isdigit():
                raise ValueError("bad range: %s" % spec)
            hi_i = ipaddress.IPv4Address("%s.%s" % (base, hi_s))
        else:
            hi_i = ipaddress.IPv4Address(hi_s)
        if hi_i < lo_i:
            raise ValueError("bad range: %s" % spec)
        if (int(hi_i) - int(lo_i)) > 65536:
            raise ValueError("range too large (max 65536 hosts): %s" % spec)
        return [ipaddress.IPv4Address(int(lo_i) + i)
                for i in range(int(hi_i) - int(lo_i) + 1)]
    return [ipaddress.IPv4Address(spec)]


def parse_targets(specs: Sequence[str]) -> List[ipaddress.IPv4Address]:
    """Expand CIDR / range / single-IP specs into a sorted, unique IP list."""
    out: Dict[int, ipaddress.IPv4Address] = {}
    for spec in specs:
        for ip in _expand_spec(spec):
            out[int(ip)] = ip
    return sorted(out.values(), key=int)


# --------------------------------------------------------------------------
# local subnet auto-detection
# --------------------------------------------------------------------------

def _outgoing_ip() -> Optional[str]:
    """Best-effort local IP: UDP 'connect' sends no packets."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1.0)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return None


def detect_local_subnet() -> Optional[Tuple[str, List[ipaddress.IPv4Address]]]:
    """Guess (subnet string, host list) for this machine's LAN."""
    outgoing = _outgoing_ip()
    if outgoing is None:
        return None
    system = platform.system()
    prefix: Optional[int] = None
    try:
        if system == "Linux" and shutil.which("ip"):
            out = subprocess.run(["ip", "-4", "-o", "addr", "show", "up"],
                                 capture_output=True, text=True, timeout=3).stdout
            for line in out.splitlines():
                m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", line)
                if m and m.group(1) == outgoing:
                    prefix = int(m.group(2))
                    break
        elif system == "Darwin":
            out = subprocess.run(["ifconfig"], capture_output=True, text=True,
                                 timeout=3).stdout
            for line in out.splitlines():
                m = re.match(r"\s*inet (\d+\.\d+\.\d+\.\d+) netmask (0x[0-9a-f]+)",
                             line)
                if m and m.group(1) == outgoing:
                    prefix = bin(int(m.group(2), 16)).count("1")
                    break
        elif system == "Windows":
            out = subprocess.run("ipconfig", capture_output=True, text=True,
                                 timeout=5, shell=True).stdout
            pairs: List[Tuple[str, str]] = []
            cur: Optional[str] = None
            for line in out.splitlines():
                m = re.search(r"IPv4[^:]*:\s*(\d+\.\d+\.\d+\.\d+)", line)
                if m:
                    cur = m.group(1)
                    continue
                m = re.search(r"Subnet Mask[^:]*:\s*(\d+\.\d+\.\d+\.\d+)", line)
                if m and cur:
                    pairs.append((cur, m.group(1)))
                    cur = None
            for cand_ip, mask in pairs:
                if cand_ip == outgoing:
                    prefix = sum(bin(int(o)).count("1") for o in mask.split("."))
                    break
            if prefix is None and pairs:
                prefix = sum(bin(int(o)).count("1")
                             for o in pairs[0][1].split("."))
    except (OSError, subprocess.SubprocessError):
        prefix = None
    if prefix is None or prefix > 28:
        prefix = 24
    net = ipaddress.ip_network(outgoing + "/" + str(prefix), strict=False)
    return str(net), list(net.hosts())


def detect_gateway() -> Optional[str]:
    system = platform.system()
    try:
        if system == "Linux" and shutil.which("ip"):
            out = subprocess.run(["ip", "-4", "route", "show", "default"],
                                 capture_output=True, text=True, timeout=3).stdout
            m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
            if m:
                return m.group(1)
        elif system == "Darwin" and shutil.which("route"):
            out = subprocess.run(["route", "-n", "get", "default"],
                                 capture_output=True, text=True, timeout=3).stdout
            m = re.search(r"gateway:\s*(\d+\.\d+\.\d+\.\d+)", out)
            if m:
                return m.group(1)
        elif system == "Windows":
            out = subprocess.run("ipconfig", capture_output=True, text=True,
                                 timeout=5, shell=True).stdout
            m = re.search(r"Default Gateway[^:]*:\s*(\d+\.\d+\.\d+\.\d+)", out)
            if m:
                return m.group(1)
    except (OSError, subprocess.SubprocessError):
        pass
    return None


# --------------------------------------------------------------------------
# ARP table
# --------------------------------------------------------------------------

_MAC_RE = r"([0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2})"


def _norm_mac(mac: str) -> str:
    return mac.replace("-", ":").lower()


def read_arp_table() -> Dict[str, str]:
    """ip -> mac from the OS ARP/neighbor cache (best effort)."""
    table: Dict[str, str] = {}
    system = platform.system()
    try:
        if system == "Linux" and shutil.which("ip"):
            out = subprocess.run(["ip", "-4", "neigh", "show"],
                                 capture_output=True, text=True, timeout=3).stdout
            for line in out.splitlines():
                m = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+dev\s+\S+\s+lladdr\s+" + _MAC_RE,
                             line, re.IGNORECASE)
                if m:
                    table[m.group(1)] = _norm_mac(m.group(2))
        elif system == "Darwin":
            out = subprocess.run(["arp", "-a"], capture_output=True, text=True,
                                 timeout=3).stdout
            for line in out.splitlines():
                m = re.match(r"^\s*(?:\S+\s+)?\(?"
                             r"(\d+\.\d+\.\d+\.\d+)\)?\s+at\s+" + _MAC_RE, line,
                             re.IGNORECASE)
                if m:
                    table[m.group(1)] = _norm_mac(m.group(2))
        elif system == "Windows":
            out = subprocess.run("arp -a", capture_output=True, text=True,
                                 timeout=5, shell=True).stdout
            for line in out.splitlines():
                m = re.match(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f]{2}(?:-[0-9a-f]{2}){5})",
                             line, re.IGNORECASE)
                if m:
                    table[m.group(1)] = _norm_mac(m.group(2))
    except (OSError, subprocess.SubprocessError):
        pass
    return table


# --------------------------------------------------------------------------
# ICMP sweep
# --------------------------------------------------------------------------

def ping_alive(ip: str, count: int, timeout: float) -> bool:
    exe = shutil.which("ping")
    if exe is None:
        return False
    wait_s = max(1, int(timeout))
    if platform.system() == "Windows":
        cmd = [exe, "-n", str(count), "-w", str(int(timeout * 1000)), ip]
    else:
        cmd = [exe, "-c", str(count), "-W", str(wait_s), ip]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=count * wait_s + 5)
    except (OSError, subprocess.SubprocessError):
        return False
    if proc.returncode == 0:
        return True
    blob = ((proc.stdout or b"") + (proc.stderr or b"")).decode("utf-8", "ignore").lower()
    return "1 received" in blob


# --------------------------------------------------------------------------
# TCP port check
# --------------------------------------------------------------------------

def check_ports(ip: str, ports: Sequence[int], timeout: float) -> List[int]:
    open_ports: List[int] = []
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout):
                open_ports.append(port)
        except OSError:
            continue
    return open_ports


# --------------------------------------------------------------------------
# rDNS
# --------------------------------------------------------------------------

def lookup_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""


# --------------------------------------------------------------------------
# OUI
# --------------------------------------------------------------------------

def vendor_for(mac: str, oui: Dict[str, str]) -> str:
    if not mac or len(mac) < 8:
        return ""
    return oui.get(mac[:8].replace("-", ":"), "")


def _parse_oui_file(text: str) -> Dict[str, str]:
    """Parse the official IEEE OUI file: 'AA-BB-CC\\t    Vendor'."""
    out: Dict[str, str] = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t", 1)
        if len(parts) != 2:
            continue
        prefix = parts[0].strip().lower()
        vendor = parts[1].strip()
        if re.fullmatch(r"[0-9a-f]{2}(-[0-9a-f]{2}){2}", prefix):
            out[prefix.replace("-", ":")] = vendor
    return out


def load_oui(mode: str) -> Tuple[Dict[str, str], str]:
    """Return (oui dict, note). mode: mini | full | /path/to/file."""
    if mode == "mini":
        return dict(MINI_OUI), "built-in OUI table (mini)"
    if mode == "full":
        try:
            if os.path.exists(OUI_CACHE_FILE):
                with open(OUI_CACHE_FILE, "r", encoding="utf-8") as fh:
                    return _parse_oui_file(fh.read()), "IEEE OUI db (cached)"
        except OSError:
            pass
        try:
            import urllib.request
            req = urllib.request.Request(OII_URL, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=15) as resp:
                text = resp.read().decode("utf-8", "ignore")
            os.makedirs(OUI_CACHE_DIR, exist_ok=True)
            with open(OUI_CACHE_FILE, "w", encoding="utf-8") as fh:
                fh.write(text)
            return _parse_oui_file(text), "IEEE OUI db (downloaded)"
        except Exception:
            return dict(MINI_OUI), "OUI download failed — fell back to mini table"
    try:
        with open(mode, "r", encoding="utf-8") as fh:
            return _parse_oui_file(fh.read()), "custom OUI file: %s" % mode
    except OSError as e:
        return dict(MINI_OUI), "cannot read OUI file (%s) — fell back to mini" % e


# --------------------------------------------------------------------------
# state file
# --------------------------------------------------------------------------

def load_state(path: str) -> Dict[str, Dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        devices = data.get("devices", data)
        return devices if isinstance(devices, dict) else {}
    except (OSError, ValueError):
        return {}


def save_state(path: str, devices: Sequence[Device]) -> None:
    payload = {
        "tool": "lanradar",
        "version": VERSION,
        "updated": datetime.now().astimezone().isoformat(timespec="seconds"),
        "devices": {
            d.ip: {
                "mac": d.mac,
                "vendor": d.vendor,
                "hostname": d.hostname,
                "ports": d.ports,
                "gateway": d.gateway,
                "first_seen": d.first_seen,
                "last_seen": d.last_seen,
            }
            for d in devices if d.alive
        },
    }
    try:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
    except OSError:
        pass


def diff_events(devices: Sequence[Device],
                prev: Dict[str, Dict[str, Any]]) -> None:
    """Mark each device with event='new'/'gone' relative to prev (in place).
    'gone' entries are returned as synthetic Device rows."""
    for d in devices:
        if d.ip not in prev:
            d.event = "new"
        prev.pop(d.ip, None)
    for ip, info in prev.items():
        gone = Device(ip=ip, alive=False, event="gone",
                      mac=info.get("mac", ""), vendor=info.get("vendor", ""),
                      hostname=info.get("hostname", ""))
        devices.append(gone)  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# sweep
# --------------------------------------------------------------------------

def run_sweep(ips: Sequence[ipaddress.IPv4Address], args: argparse.Namespace,
              oui: Dict[str, str], prev: Dict[str, Dict[str, Any]],
              gateway: Optional[str],
              do_diff: bool = False) -> Tuple[List[Device], Dict[str, int]]:
    t0 = time.perf_counter()
    now = datetime.now().astimezone().isoformat(timespec="seconds")
    arp: Dict[str, str] = {} if args.no_arp else read_arp_table()
    icmp: Dict[str, bool] = {}
    if not args.no_icmp:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
            futs = {pool.submit(ping_alive, str(ip), args.ping_count, args.timeout): ip
                    for ip in ips}
            for fut in concurrent.futures.as_completed(futs):
                ip = futs[fut]
                try:
                    icmp[str(ip)] = fut.result()
                except Exception:
                    icmp[str(ip)] = False
    ports_found: Dict[str, List[int]] = {}
    if args.ports:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
            futs = {pool.submit(check_ports, str(ip), args.ports, args.port_timeout): ip
                    for ip in ips}
            for fut in concurrent.futures.as_completed(futs):
                ip = futs[fut]
                try:
                    ports_found[str(ip)] = fut.result()
                except Exception:
                    ports_found[str(ip)] = []

    devices: Dict[str, Device] = {}
    for ip in ips:
        s = str(ip)
        mac = arp.get(s, "")
        open_ports = ports_found.get(s, [])
        alive = bool(icmp.get(s)) or bool(mac) or bool(open_ports)
        if not alive:
            continue
        d = Device(ip=s, mac=mac, alive=True,
                   source="+".join(x for x, ok in (("icmp", icmp.get(s)),
                                                     ("arp", bool(mac)),
                                                     ("ports", bool(open_ports))) if ok),
                   ports=sorted(open_ports))
        d.vendor = vendor_for(mac, oui)
        if args.rdns:
            d.hostname = lookup_hostname(s)
        if gateway and s == gateway:
            d.gateway = True
        d.last_seen = now
        devices[s] = d

    dev_list: List[Device] = list(devices.values())
    for d in dev_list:
        info = prev.get(d.ip)
        if info and info.get("first_seen"):
            d.first_seen = info["first_seen"]
        else:
            d.first_seen = now
    if do_diff:
        diff_events(dev_list, prev)

    elapsed = time.perf_counter() - t0
    stats = {
        "probed": len(ips),
        "arp_entries": len(arp),
        "icmp_up": sum(1 for v in icmp.values() if v),
        "with_ports": sum(1 for v in ports_found.values() if v),
        "elapsed": round(elapsed, 2),
    }
    return sorted(dev_list, key=lambda d: int(ipaddress.ip_address(d.ip))), stats


# --------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------

try:
    from rich import box
    from rich.console import Console
    from rich.table import Table
    from rich.text import Text
    _RICH = True
except ImportError:  # pragma: no cover
    _RICH = False


def _port_str(ports: Sequence[int]) -> str:
    if not ports:
        return ""
    parts = []
    for p in ports[:6]:
        name = PORT_NAMES.get(p)
        parts.append("%d%s" % (p, "/" + name if name else ""))
    if len(ports) > 6:
        parts.append("+%d" % (len(ports) - 6))
    return ", ".join(parts)


def render(devices: Sequence[Device], stats: Dict[str, int], args: argparse.Namespace,
           subnet: str, oui_note: str, round_no: Optional[int] = None) -> None:
    console = Console()
    if round_no is not None:
        when = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        console.print("[bold]Round %d[/bold] · %s · %s" % (round_no, when, subnet))
    for d in devices:
        if d.event:
            icon, color = ("＋", "green") if d.event == "new" else ("－", "red")
            console.print("[%s]%s[/] [%s]%s[/]  %s%s" % (
                color, icon, color, d.event.upper(), d.ip,
                "  (%s)" % d.vendor if d.vendor else ""))
    rows = [d for d in devices if d.alive or (d.event == "gone" and not args.quiet)]
    if args.quiet:
        rows = [d for d in devices if d.event]
    if not rows:
        console.print("[dim]no live devices found in %s[/]" % subnet)
        return
    table = Table(box=box.SIMPLE_HEAD, header_style="bold", pad_edge=False)
    table.add_column("IP", style="bold cyan", no_wrap=True)
    table.add_column("MAC", no_wrap=True)
    table.add_column("Vendor", max_width=24)
    table.add_column("Hostname", max_width=28)
    table.add_column("Ports", max_width=40)
    table.add_column("Role", no_wrap=True)
    for d in rows:
        ip_style = "dim" if d.event == "gone" else "bold cyan"
        table.add_row(
            Text(d.ip, style=ip_style),
            d.mac or "–",
            d.vendor or ("?" if d.mac else "–"),
            d.hostname or "–",
            _port_str(d.ports) or "–",
            "[yellow]gateway[/]" if d.gateway else "",
        )
    console.print(table)
    live = [d for d in devices if d.alive]
    vendors: Dict[str, int] = {}
    for d in live:
        key = d.vendor or "unknown"
        vendors[key] = vendors.get(key, 0) + 1
    top = sorted(vendors.items(), key=lambda kv: -kv[1])[:5]
    console.print(
        "%d live device(s) in [bold]%s[/] · %d addresses probed in %.1f s · "
        "arp cache %d · top vendors: %s · %s" % (
            len(live), subnet, stats["probed"], stats["elapsed"],
            stats["arp_entries"],
            ", ".join("%s×%d" % (k, v) for k, v in top) or "–",
            oui_note))


def to_rows(devices: Sequence[Device]) -> List[List[str]]:
    return [[d.ip, d.mac, d.vendor, d.hostname, ";".join(str(p) for p in d.ports),
             "gateway" if d.gateway else "", d.event] for d in devices]


def to_json(devices: Sequence[Device], subnet: str, stats: Dict[str, int],
            round_no: int = 1) -> Dict[str, Any]:
    return {
        "tool": "lanradar",
        "version": VERSION,
        "round": round_no,
        "timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
        "subnet": subnet,
        "stats": stats,
        "devices": [
            {
                "ip": d.ip, "mac": d.mac, "vendor": d.vendor,
                "hostname": d.hostname, "ports": d.ports, "alive": d.alive,
                "gateway": d.gateway, "first_seen": d.first_seen,
                "last_seen": d.last_seen, "event": d.event,
            }
            for d in devices
        ],
    }


# --------------------------------------------------------------------------
# watch mode
# --------------------------------------------------------------------------

def run_watch(subnet: str, ips: List[ipaddress.IPv4Address], args: argparse.Namespace,
              oui: Dict[str, str], oui_note: str) -> int:
    console = Console()
    gateway = detect_gateway()
    prev: Dict[str, Dict[str, Any]] = (load_state(args.state) if args.state else {})
    round_no = 0
    try:
        while True:
            round_no += 1
            if sys.stdout.isatty():
                console.clear()
            devices, stats = run_sweep(ips, args, oui, prev, gateway, do_diff=True)
            prev = {d.ip: {"mac": d.mac, "vendor": d.vendor,
                           "hostname": d.hostname}
                    for d in devices if d.alive}
            if args.state:
                save_state(args.state, devices)
            if args.json:
                print(json.dumps(to_json(devices, subnet, stats, round_no)))
            elif args.csv:
                _print_csv(devices)
            else:
                render(devices, stats, args, subnet, oui_note, round_no=round_no)
            if args.rounds and round_no >= args.rounds:
                break
            time.sleep(args.interval)
    except KeyboardInterrupt:
        console.print("\n[dim]stopped after %d round(s)[/dim]" % round_no)
    return 0


def _print_csv(devices: Sequence[Device]) -> None:
    w = csv.writer(sys.stdout, lineterminator="\n")
    w.writerow(["ip", "mac", "vendor", "hostname", "ports", "role", "event"])
    for row in to_rows(devices):
        w.writerow(row)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

_EPILOG = """\
examples:
  lanradar                                  auto-detect local subnet
  lanradar 192.168.1.0/24                   sweep an explicit CIDR
  lanradar 192.168.1.1-50 --rdns            range + hostnames
  lanradar 192.168.1.0/24 --ports 22,80,443,445,3389
  lanradar --watch --interval 30            alert on new/gone devices
  lanradar --state /var/lib/lanradar.json -q   cron-friendly inventory diff
  lanradar 10.0.0.0/8 --oui full --json

target formats:  192.168.1.0/24   192.168.1.1-50   192.168.1.10
exit codes:      0 sweep completed, 2 bad usage

responsible use: only scan networks you own or are authorized to test.
"""


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="lanradar",
        description="One-file LAN radar: discover live devices (IP, MAC, vendor) "
                    "on a network — with watch mode for new/leave events.",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("targets", nargs="*", metavar="TARGET",
                   help="CIDR, range or IP (default: auto-detect local subnet)")
    p.add_argument("-t", "--timeout", type=float, default=1.5, metavar="SEC",
                   help="per-host ping timeout (default: 1.5)")
    p.add_argument("-n", "--ping-count", type=int, default=1, metavar="N",
                   help="ICMP probes per host (default: 1)")
    p.add_argument("-w", "--workers", type=int, default=64, metavar="N",
                   help="parallel workers (default: 64)")
    p.add_argument("--ports", default="", metavar="LIST",
                   help="TCP ports to check on every address, e.g. '22,80,443' (off by default)")
    p.add_argument("--port-timeout", type=float, default=0.5, metavar="SEC",
                   help="per-port connect timeout (default: 0.5)")
    p.add_argument("--rdns", action="store_true",
                   help="resolve hostnames via reverse DNS (slower)")
    p.add_argument("--oui", default="mini", metavar="MODE",
                   help="OUI source: mini (built-in) | full (download IEEE db, cached) | /path/to/oui.txt (default: mini)")
    p.add_argument("--no-icmp", action="store_true", help="skip the ping sweep")
    p.add_argument("--no-arp", action="store_true", help="skip reading the ARP cache")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="only show new/gone events (for cron/watch logs)")
    p.add_argument("-j", "--json", action="store_true", help="JSON output")
    p.add_argument("-c", "--csv", action="store_true", help="CSV output")
    p.add_argument("--watch", action="store_true", help="keep sweeping in a loop")
    p.add_argument("--interval", type=float, default=30.0, metavar="SEC",
                   help="seconds between rounds in watch mode (default: 30)")
    p.add_argument("--rounds", type=int, default=0, metavar="N",
                   help="stop after N rounds in watch mode (default: forever)")
    p.add_argument("--state", default="", metavar="FILE",
                   help="JSON state file: track first/last seen + new/gone between runs")
    p.add_argument("--version", action="version", version="%(prog)s " + VERSION)
    return p


_VALUE_OPTS = {
    "-t", "--timeout", "-n", "--ping-count", "-w", "--workers",
    "--ports", "--port-timeout", "--oui", "--interval", "--rounds", "--state",
}


def _prepare_argv(argv: Sequence[str]) -> List[str]:
    """Collect target tokens at the end of argv (argparse can't interleave
    a ``nargs='*'`` positional with options mid-command)."""
    rest: List[str] = []
    targets: List[str] = []
    skip_value = False
    after_ddash = False
    for tok in argv:
        if after_ddash:
            targets.append(tok)
            continue
        if skip_value:
            rest.append(tok)
            skip_value = False
            continue
        if tok == "--":
            after_ddash = True
            continue
        if tok in _VALUE_OPTS:
            rest.append(tok)
            skip_value = True
            continue
        if tok.startswith("--") and "=" in tok:
            rest.append(tok)
            continue
        if tok.startswith("-") and len(tok) > 1:
            rest.append(tok)
            continue
        targets.append(tok)
    return rest + targets


def main(argv: Optional[Sequence[str]] = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    parser = _build_parser()
    args = parser.parse_args(_prepare_argv(list(argv)))

    try:
        if args.ports:
            args.ports = [int(x) for x in re.split(r"[,\s]+", args.ports) if x]
            for x in args.ports:
                if not 1 <= x <= 65535:
                    raise ValueError
        else:
            args.ports = []
        if args.targets:
            ips = parse_targets(args.targets)
            subnet = ", ".join(args.targets)
        else:
            found = detect_local_subnet()
            if not found:
                parser.error("could not auto-detect the local subnet — "
                             "pass a CIDR, e.g. 192.168.1.0/24")
            subnet, ips = found
    except ValueError as e:
        parser.error(str(e))
    if not ips:
        parser.error("no addresses to probe")
    if not _RICH and not (args.json or args.csv):
        print("lanradar: the 'rich' package is required for table output. "
              "Run: pip install rich   (or use --json/--csv)", file=sys.stderr)
        return 2

    oui, oui_note = load_oui(args.oui)
    if args.watch:
        return run_watch(subnet, ips, args, oui, oui_note)

    prev = load_state(args.state) if args.state else {}
    gateway = detect_gateway()
    devices, stats = run_sweep(ips, args, oui, prev, gateway,
                               do_diff=bool(args.state))
    if args.state:
        save_state(args.state, devices)
    if args.json:
        print(json.dumps(to_json(devices, subnet, stats), indent=2))
    elif args.csv:
        _print_csv(devices)
    else:
        render(devices, stats, args, subnet, oui_note)
    return 0


if __name__ == "__main__":
    sys.exit(main())
