"""
device_table.py
----------------
Central, thread-safe store for everything NetMonitor knows about devices
on the LAN. Multiple threads touch this concurrently:

    - the ARP discovery thread (adds/refreshes devices)
    - the packet capture thread (bumps traffic counters)
    - the fingerprinting thread/pass (fills in vendor/OS guesses)
    - the IDS thread (reads it to evaluate rules)
    - the CLI thread (reads it to render output)

Every mutation and read goes through a single re-entrant lock (RLock) so
none of the above can interleave and corrupt shared state. RLock (rather
than a plain Lock) is used because a couple of higher-level methods here
call other locking methods on `self` internally, which would deadlock a
plain Lock.
"""

import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class Device:
    ip: str
    mac: str
    vendor: str = "Unknown"
    os_guess: str = "Unknown"
    hostname: str = "Unknown"
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    packet_count: int = 0
    byte_count: int = 0
    ttl_samples: List[int] = field(default_factory=list)
    is_new: bool = True  # cleared once the CLI/IDS has "acknowledged" it

    def as_dict(self) -> dict:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "vendor": self.vendor,
            "os_guess": self.os_guess,
            "hostname": self.hostname,
            "first_seen": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.first_seen)),
            "last_seen": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.last_seen)),
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
        }


class DeviceTable:
    def __init__(self):
        self._lock = threading.RLock()
        # keyed by IP — good enough for a single LAN segment where IPs
        # don't collide; MAC is still tracked per-device for spoof checks
        self._devices: Dict[str, Device] = {}
        # ip -> mac, kept separately so the IDS layer can cheaply diff
        # "who owns this IP right now" against "who owned it a moment ago"
        # to catch ARP spoofing (an IP suddenly claimed by a new MAC).
        self._ip_to_mac: Dict[str, str] = {}

    def upsert(self, ip: str, mac: str, ttl: Optional[int] = None,
               packet_len: int = 0) -> "tuple[Device, bool, bool]":
        """
        Add or refresh a device record.

        Returns (device, is_new_device, mac_changed) so callers (mainly
        the IDS layer) can react without re-deriving that state
        themselves.
        """
        with self._lock:
            mac_changed = False
            is_new_device = ip not in self._devices

            if is_new_device:
                dev = Device(ip=ip, mac=mac)
                self._devices[ip] = dev
            else:
                dev = self._devices[ip]
                if dev.mac != mac:
                    mac_changed = True
                    dev.mac = mac
                dev.last_seen = time.time()

            dev.packet_count += 1
            dev.byte_count += packet_len
            if ttl is not None:
                dev.ttl_samples.append(ttl)
                # keep the sample window bounded
                if len(dev.ttl_samples) > 20:
                    dev.ttl_samples.pop(0)

            self._ip_to_mac[ip] = mac
            return dev, is_new_device, mac_changed

    def set_fingerprint(self, ip: str, vendor: Optional[str] = None,
                         os_guess: Optional[str] = None,
                         hostname: Optional[str] = None) -> None:
        with self._lock:
            dev = self._devices.get(ip)
            if not dev:
                return
            if vendor:
                dev.vendor = vendor
            if os_guess:
                dev.os_guess = os_guess
            if hostname:
                dev.hostname = hostname

    def mark_seen(self, ip: str) -> None:
        with self._lock:
            dev = self._devices.get(ip)
            if dev:
                dev.is_new = False

    def get(self, ip: str) -> Optional[Device]:
        with self._lock:
            return self._devices.get(ip)

    def all_devices(self) -> List[Device]:
        with self._lock:
            # shallow copies so callers can render without holding the lock
            return list(self._devices.values())

    def mac_for_ip(self, ip: str) -> Optional[str]:
        with self._lock:
            return self._ip_to_mac.get(ip)

    def prune_stale(self, timeout_seconds: int = 300) -> List[str]:
        """Remove devices not seen within `timeout_seconds`. Returns removed IPs."""
        with self._lock:
            now = time.time()
            stale = [ip for ip, d in self._devices.items()
                     if now - d.last_seen > timeout_seconds]
            for ip in stale:
                del self._devices[ip]
                self._ip_to_mac.pop(ip, None)
            return stale

    def __len__(self) -> int:
        with self._lock:
            return len(self._devices)
