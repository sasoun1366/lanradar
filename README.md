<div align="center">

# lanradar

**One-file LAN radar** — run it, and find out what devices are on your network:
IP, MAC, vendor, hostname, open ports. Plus a watch mode that alerts when a
device **joins or leaves**.

[![tests](https://github.com/sasoun1366/lanradar/actions/workflows/test.yml/badge.svg)](https://github.com/sasoun1366/lanradar/actions/workflows/test.yml)
[![python](https://img.shields.io/badge/python-3.9%2B-3776ab?logo=python&logoColor=white)](https://www.python.org/)
[![license](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![size](https://img.shields.io/badge/size-1%20file-ff69b4)](lanradar.py)
[![Telegram](https://img.shields.io/badge/Telegram-%40luyavaai-26A5E4?logo=telegram&logoColor=white)](https://t.me/luyavaai)

> ⚖️ **Responsible use:** only scan networks you own or are explicitly
> authorized to test. Unauthorized scanning is illegal in most jurisdictions.

</div>

---

```
$ lanradar 192.168.1.0/24 --rdns
IP           MAC                  Vendor                   Hostname         Ports                    Role
────────────────────────────────────────────────────────────────────────────────────────────────────────────────
192.168.1.1  aa:bb:cc:dd:ee:01    TP-Link                  –                80/http, 443/https       gateway
192.168.1.5  b8:27:eb:12:34:56    Raspberry Pi Trading     pi-cluster       22/ssh, 8080/http-alt
192.168.1.10 aa:bb:cc:dd:ee:0a    Apple                    macbook-nima     22/ssh
192.168.1.23 00:50:56:9a:bc:de    VMware                   esxi01           22/ssh, 443/https, 9100/prometheus
192.168.1.42 44:85:00:11:22:33    Intel                    printer          80/http, 631
192.168.1.77 52:54:00:ab:cd:ef    QEMU/KVM (virtual)       k8s-node-2       22/ssh, 6443
5 live device(s) in 192.168.1.0/24 · 254 addresses probed in 2.3 s · arp cache 41 · top vendors: Apple×2, Intel×1, …
```
*(typical output — example)*

## Why one file?

* **Zero required dependencies.** Runs on any Python 3.9+ (`rich` optional, only for pretty tables — `--json`/`--csv` work without it).
* **No config, no daemon.** One command, one answer.
* **Portable.** Linux, macOS, Windows — uses the OS ARP/neighbor cache and the system `ping`.
* **Scriptable.** JSON & CSV output, state file with first/last-seen, watch mode with new/gone events — drops into cron, CI and other tools.

## How it finds devices

| engine | what it does |
|--------|--------------|
| **ARP cache** | reads the OS neighbor table (`ip neigh` / `arp -a`) — instant MAC + vendor |
| **ICMP sweep** | parallel ping sweep (`-c 1`) for hosts that don't respond to ARP |
| **TCP probe** *(opt-in)* | `--ports 22,80,443,…` checks common ports on every address — catches silent servers |
| **rDNS** *(opt-in)* | `--rdns` resolves hostnames |
| **OUI lookup** | MAC prefix → vendor: built-in mini table, or the full IEEE database (`--oui full`, downloaded once & cached) |

## Install

```bash
# works directly, no install needed
python lanradar.py

# or install as a package
pip install .
lanradar
```

`pip install rich` is optional and only improves the table output.

## Quick start

```bash
# no arguments: auto-detects your local subnet and sweeps it
lanradar

# explicit subnet / range / single host
lanradar 192.168.1.0/24
lanradar 192.168.1.1-50
lanradar 10.0.0.42

# hostnames + common ports
lanradar 192.168.1.0/24 --rdns --ports 22,80,443,445,3389
```

Target formats: `192.168.1.0/24`, `192.168.1.1-50` (shorthand for the last
octet), `192.168.1.1-192.168.1.50`, or a single IP. Multiple targets accepted.

## Watch mode — "who just joined the network?"

```bash
lanradar 192.168.1.0/24 --watch --interval 30
```

Re-sweeps every 30 s and prints a timestamped event only when something
changes:

```
[14:03:12] ＋ NEW  192.168.1.140  (Apple)
[14:05:12] ＋ NEW  192.168.1.141  (TP-Link)
[14:37:12] － GONE 192.168.1.5   (Raspberry Pi Trading)
```

With `--json` or `--csv`, each round emits one document/row — pipe it into
your log pipeline.

## Cron-friendly inventory

`--state FILE` remembers every device (first/last seen) between runs and marks
`new`/`gone` against the previous run:

```cron
*/1 * * * * /usr/local/bin/lanradar 192.168.1.0/24 --state /var/lib/lanradar.json -q >> /var/log/lanradar.log 2>&1
```

Every run rewrites the state file (plain JSON), so you can also query it with
`jq` or load it into any CMDB/CM.

## Output formats

```bash
lanradar 192.168.1.0/24 --json | jq '.devices[] | select(.ports | length > 0)'
lanradar 192.168.1.0/24 --csv    > inventory.csv
```

CSV columns: `ip, mac, vendor, hostname, ports, role, event`.

## Useful flags

| flag | meaning |
|------|---------|
| `-t SEC` | per-host ping timeout (default 1.5 s) |
| `-n N` | ICMP probes per host (default 1) |
| `-w N` | parallel workers (default 64) |
| `--ports LIST` | TCP ports to check on every address (off by default) |
| `--port-timeout SEC` | per-port connect timeout (default 0.5 s) |
| `--rdns` | resolve hostnames via reverse DNS (slower) |
| `--oui MODE` | `mini` (built-in) · `full` (download IEEE db, cached) · `/path/to/oui.txt` |
| `--no-icmp` / `--no-arp` | disable an engine |
| `-q` | only show new/gone events |
| `-j` / `-c` | JSON / CSV output |
| `--watch`, `--interval SEC`, `--rounds N` | continuous monitoring |
| `--state FILE` | JSON state file for cross-run diffing |

## Exit codes

| code | meaning |
|------|---------|
| `0` | sweep completed (regardless of how many hosts were found) |
| `2` | bad usage |

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest -q          # offline unit tests, no network needed
```

CI runs on Python 3.9–3.13, and pushing a `v*` tag publishes a GitHub release
automatically.

## Notes & limitations

* The ICMP engine uses the **system `ping`**. In unprivileged containers it may
  be blocked — ARP cache + `--ports` still work, and the sweep degrades
  gracefully.
* ARP cache only contains devices the host has recently talked to; the ping
  sweep refreshes entries on most OSes.
* Reverse DNS is best-effort and often missing on corporate LANs.
* Ranges are capped at 65536 addresses per spec; CIDR up to /8 is fine.

## Stay updated

New releases are announced on Telegram: **[@luyavaai](https://t.me/luyavaai)** — version
notes, upgrade advice and practical MikroTik / network notes go there first.

<!-- support:start -->
## Support the project

**lanradar** is built and maintained in my own time, and it stays free to use
and free to fork. If it saved you an outage — or just an afternoon — you can help
fund the next round of test hardware and the time to add more vendors:

**USDT (TRC20)**

```text
TMEyd1JZqdCjjKTc4zG2fhjzAYFKXCUWnA
```

This is the only address I publish for these projects. Anything else claiming to be
me is not mine.
<!-- support:end -->

## License

[MIT](LICENSE)
