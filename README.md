# NetMonitor v2

**A multi-threaded, ARP-based LAN monitoring tool with device fingerprinting and lightweight IDS-style alerting — built in Python with Scapy.**

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-brightgreen)

---

## Overview

NetMonitor v2 discovers every device on your local network, fingerprints what it likely is (vendor + OS family), and raises real-time alerts on suspicious activity — new/unknown devices joining, ARP spoofing (MITM signature), and abnormal traffic spikes. It runs entirely from the terminal with no external services or paid APIs.

```
[*] Running active ARP scan on 192.168.1.0/24 ...
[*] Active scan found 12 device(s)
[*] Starting capture (Ctrl+C to stop)...

NetMonitor v2 — LAN Monitoring
  devices: 12   refresh #4   14:32:07
----------------------------------------------------------------------
IP              MAC                Vendor                  OS guess                    Pkts    Bytes
----------------------------------------------------------------------
 192.168.1.1    AA:BB:CC:11:22:33  Cisco Systems           Network device (TTL~255)      420    58210
*192.168.1.42   B8:27:EB:AA:11:22  Raspberry Pi Foundation Linux/Android/macOS (TTL~64)   88     9440
----------------------------------------------------------------------
(* = newly discovered this session)   Ctrl+C to stop
```

## Features

- 🔍 **ARP-based discovery** — active subnet sweep on startup + continuous passive observation
- 🧬 **Device fingerprinting** — MAC vendor (OUI) lookup + TTL-based OS family guessing
- 🚨 **IDS-style alerting** — new device detection, ARP spoofing / cache-poisoning detection, per-device traffic-spike detection
- ⚡ **Multi-threaded pipeline** — capture, processing, and rendering run on separate threads so nothing blocks packet capture
- 📤 **Export** — JSON, CSV, or TXT reports of the full session
- 🖥️ **Zero external dependencies** beyond Scapy — no cloud APIs, no paid services

## Architecture

```
CaptureThread (scapy.sniff)
        │  parsed frames
        ▼
     Queue
        │
        ▼
ProcessingThread ──▶ Fingerprinting ──▶ DeviceTable (thread-safe, RLock)
        │                                      │
        ▼                                      ▼
   IDS Engine                                CLI Dashboard
   (alerts)                                  (live redraw)
```

| Module | Responsibility |
|---|---|
| `capture.py` | Threaded Scapy sniffer; pushes parsed frames to a queue |
| `discovery.py` | Active ARP subnet scan (`srp`) + passive ARP observation |
| `device_table.py` | Thread-safe shared device registry |
| `fingerprint.py` | MAC vendor (OUI) + TTL-based OS guessing |
| `ids_alerts.py` | Rule engine: new device / ARP spoof / traffic spike |
| `exporter.py` | JSON / CSV / TXT report generation |
| `cli.py` | argparse entry point, live dashboard, alert output |

## Installation

```bash
git clone https://github.com/vikash-11/netmonitor-v2.git
cd netmonitor-v2
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Scapy requires libpcap (Linux: usually preinstalled or `apt install libpcap-dev`; Windows: install [Npcap](https://npcap.com/) first).

## Usage

Raw packet capture requires elevated privileges:

```bash
sudo venv/bin/python3 main.py --cidr 192.168.1.0/24
```

Passive-only monitoring (no active scan):

```bash
sudo venv/bin/python3 main.py
```

Export a report on exit:

```bash
sudo venv/bin/python3 main.py --cidr 192.168.1.0/24 --export report.json --export-format json
```

### CLI options

| Flag | Description |
|---|---|
| `-i, --iface` | Network interface to sniff on |
| `-c, --cidr` | CIDR range for the initial active ARP scan (e.g. `192.168.1.0/24`) |
| `--refresh` | Dashboard redraw interval in seconds (default: 2.0) |
| `--traffic-window` | IDS rolling window in seconds for spike detection |
| `--traffic-threshold` | Packet count within the window that triggers an alert |
| `--export` | Path to write a report to on exit |
| `--export-format` | `json`, `csv`, or `txt` |
| `--no-dashboard` | Disable the live table; only print alerts |

## How Fingerprinting Works

- **Vendor**: the first 3 bytes of a MAC address (the OUI) are matched against a bundled manufacturer table.
- **OS guess**: observed IP TTL is bucketed to the nearest common OS default (Windows ≈128, Linux/macOS ≈64, network gear ≈255) to absorb router hop decrements.

## How IDS Alerts Work

| Alert | Trigger |
|---|---|
| `NEW_DEVICE` | A MAC/IP pair not previously seen appears on the network |
| `ARP_SPOOF` | An IP already on file is suddenly claimed by a different MAC — the classic ARP cache-poisoning / MITM signature |
| `TRAFFIC_SPIKE` | A device exceeds a configurable packet count within a rolling time window |

## Disclaimer

This tool performs active network scanning and packet capture. Only run it on networks you own or have explicit authorization to monitor.

## License

MIT
