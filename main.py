#!/usr/bin/env python3
"""
NetMonitor v2 — entry point.

Usage examples:
    sudo python3 main.py --cidr 192.168.1.0/24
    sudo python3 main.py -i eth0 --cidr 10.0.0.0/24 --export report.json
    sudo python3 main.py --no-dashboard --export alerts.txt --export-format txt

Root/administrator privileges are required because raw packet capture
and ARP scanning need direct access to the network interface.
"""

import sys

from netmonitor.cli import main

if __name__ == "__main__":
    sys.exit(main())
