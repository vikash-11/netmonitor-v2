"""
NetMonitor v2 — ARP-based LAN device discovery, fingerprinting, and
lightweight IDS-style alerting.

Modules:
    device_table  — thread-safe shared device registry
    capture       — threaded Scapy packet capture layer
    discovery     — active ARP scanning + passive ARP observation
    fingerprint   — MAC vendor / TTL-based OS guessing
    ids_alerts    — rule-based alert engine (new device, ARP spoof, traffic spike)
    exporter      — JSON / CSV / TXT report export
    cli           — argparse entry point tying everything together
"""

__version__ = "2.0.0"

from .device_table import Device, DeviceTable
from .ids_alerts import Alert, AlertLevel, IDSEngine

__all__ = ["Device", "DeviceTable", "Alert", "AlertLevel", "IDSEngine", "__version__"]
