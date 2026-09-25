"""
ids_alerts.py
-------------
Lightweight, rule-based IDS layer. Not a signature-matching engine like
Snort — just a handful of heuristics that are cheap to evaluate per
packet/event and catch the common "something's off on my LAN" cases:

  1. NEW_DEVICE      — a MAC/IP pair we've never seen joins the network.
  2. ARP_SPOOF       — an IP we already have on file suddenly starts
                        being claimed by a *different* MAC. This is the
                        classic ARP cache poisoning / MITM signature
                        (attacker broadcasts "I am 192.168.1.1" from
                        their own MAC to hijack traffic to the gateway).
  3. TRAFFIC_SPIKE   — a device's packet rate over a sliding window
                        exceeds a configurable threshold (possible
                        scan, flood, or exfiltration).

Alerts are simple dataclasses pushed to an in-memory list (and optionally
a callback, e.g. to print or log immediately) rather than anything
stateful/persistent — keep this layer easy to reason about and extend.
"""

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Deque, Dict, List, Optional


class AlertLevel(Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


@dataclass
class Alert:
    level: AlertLevel
    category: str
    message: str
    ip: str
    mac: str
    timestamp: float = field(default_factory=time.time)

    def format(self) -> str:
        ts = time.strftime("%H:%M:%S", time.localtime(self.timestamp))
        return f"[{ts}] [{self.level.value:<8}] [{self.category}] {self.message}"


class IDSEngine:
    def __init__(self,
                 traffic_window_seconds: int = 10,
                 traffic_packet_threshold: int = 300,
                 on_alert: Optional[Callable[[Alert], None]] = None):
        """
        traffic_window_seconds / traffic_packet_threshold:
            if a single device sends more than `traffic_packet_threshold`
            packets within any rolling `traffic_window_seconds` window,
            a TRAFFIC_SPIKE alert fires.
        on_alert:
            optional callback invoked synchronously for every alert
            (e.g. wire this to the CLI's live output or a log file).
        """
        self.traffic_window_seconds = traffic_window_seconds
        self.traffic_packet_threshold = traffic_packet_threshold
        self.on_alert = on_alert

        self.alerts: List[Alert] = []
        # per-IP timestamp deque, used to compute a rolling packet rate
        self._packet_timestamps: Dict[str, Deque[float]] = defaultdict(deque)
        # devices already alerted-on for NEW_DEVICE, so we don't spam
        self._known_new: set = set()

    # -- internal helpers ---------------------------------------------

    def _raise(self, level: AlertLevel, category: str, message: str,
               ip: str, mac: str) -> None:
        alert = Alert(level=level, category=category, message=message, ip=ip, mac=mac)
        self.alerts.append(alert)
        if self.on_alert:
            self.on_alert(alert)

    # -- rule checks -----------------------------------------------------

    def check_new_device(self, ip: str, mac: str, is_new_device: bool) -> None:
        if is_new_device and ip not in self._known_new:
            self._known_new.add(ip)
            self._raise(
                AlertLevel.INFO, "NEW_DEVICE",
                f"New device joined the network: {ip} ({mac})",
                ip, mac,
            )

    def check_arp_spoof(self, ip: str, mac: str, mac_changed: bool,
                         previous_mac: Optional[str] = None) -> None:
        if mac_changed:
            self._raise(
                AlertLevel.CRITICAL, "ARP_SPOOF",
                f"Possible ARP spoofing: {ip} was {previous_mac}, "
                f"now claimed by {mac}",
                ip, mac,
            )

    def check_traffic_spike(self, ip: str, mac: str) -> None:
        now = time.time()
        dq = self._packet_timestamps[ip]
        dq.append(now)

        # drop timestamps outside the rolling window
        cutoff = now - self.traffic_window_seconds
        while dq and dq[0] < cutoff:
            dq.popleft()

        if len(dq) > self.traffic_packet_threshold:
            self._raise(
                AlertLevel.WARNING, "TRAFFIC_SPIKE",
                f"{ip} ({mac}) sent {len(dq)} packets in the last "
                f"{self.traffic_window_seconds}s (threshold "
                f"{self.traffic_packet_threshold})",
                ip, mac,
            )
            # reset so we don't refire every single packet after crossing
            dq.clear()

    # -- convenience: run everything at once for one discovery event -----

    def evaluate(self, ip: str, mac: str, is_new_device: bool,
                 mac_changed: bool, previous_mac: Optional[str] = None) -> None:
        self.check_new_device(ip, mac, is_new_device)
        self.check_arp_spoof(ip, mac, mac_changed, previous_mac)
        self.check_traffic_spike(ip, mac)

    def recent_alerts(self, n: int = 20) -> List[Alert]:
        return self.alerts[-n:]
