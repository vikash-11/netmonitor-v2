"""
discovery.py
------------
ARP-based device discovery, two modes:

1. Active scan (`active_arp_scan`) — broadcasts ARP "who-has" requests
   for every host in a given CIDR range and collects replies. Fast,
   thorough, but generates visible traffic (a handful of ARP frames per
   host) and needs to be run periodically rather than continuously.

2. Passive watch (`PassiveArpWatcher`) — the CaptureThread already feeds
   every sniffed ARP frame into the shared queue; this module's
   `process_frame` just reads sender IP/MAC out of ARP replies/requests
   that other hosts emit on their own. Zero extra traffic generated,
   but only sees devices that happen to talk during the observation
   window.

In practice NetMonitor runs both: an active scan on startup (and on a
timer) to populate the table quickly, and passive observation the rest
of the time to catch anything the active scan's snapshot missed and to
keep last-seen timestamps fresh.
"""

import ipaddress
from typing import List, Tuple

try:
    from scapy.all import ARP, Ether, srp
except ImportError:  # pragma: no cover
    ARP = Ether = srp = None

from .capture import CapturedFrame
from .device_table import DeviceTable


def active_arp_scan(cidr: str, iface: str = None, timeout: int = 3) -> List[Tuple[str, str]]:
    """
    Send ARP "who-has" broadcasts across `cidr` (e.g. "192.168.1.0/24")
    and return a list of (ip, mac) pairs that answered.
    """
    if srp is None:
        raise RuntimeError("scapy is not installed. Run: pip install scapy")

    network = ipaddress.ip_network(cidr, strict=False)
    arp_request = ARP(pdst=str(network))
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    answered, _unanswered = srp(
        packet, timeout=timeout, iface=iface, verbose=False
    )

    results = []
    for _sent, received in answered:
        results.append((received.psrc, received.hwsrc))
    return results


def seed_table_from_scan(table: DeviceTable, cidr: str, iface: str = None) -> int:
    """Run an active scan and load results straight into the device table."""
    found = active_arp_scan(cidr, iface=iface)
    for ip, mac in found:
        table.upsert(ip=ip, mac=mac)
    return len(found)


class PassiveArpWatcher:
    """
    Consumes CapturedFrame objects from the capture queue and updates the
    device table for any ARP traffic observed. Non-ARP (plain IP) frames
    are handed off untouched to the caller for fingerprinting/IDS use —
    this class only cares about the discovery side of things.
    """

    def __init__(self, table: DeviceTable):
        self.table = table

    def process_frame(self, frame: CapturedFrame) -> "tuple":
        """
        Update the device table from this frame and return
        (device, is_new_device, mac_changed) exactly like
        DeviceTable.upsert, for the IDS layer to react to.
        """
        return self.table.upsert(
            ip=frame.src_ip,
            mac=frame.src_mac,
            ttl=frame.ttl,
            packet_len=frame.length,
        )
