"""
capture.py
----------
Packet capture layer, built on Scapy's sniff().

Packet capture is continuous and I/O-bound (blocked waiting on the NIC),
so it runs on its own daemon thread via `scapy.sniff(prn=..., store=False)`.
The `prn` callback fires per-packet on that same capture thread — it must
stay fast and non-blocking, so it does nothing heavier than:

    1. pull out src IP/MAC/TTL/len (cheap field reads)
    2. push the parsed tuple onto a thread-safe Queue

All *processing* (device table updates, fingerprinting, IDS rule checks)
happens on a separate consumer thread draining that queue. This keeps a
burst of traffic from ever blocking the capture loop itself, and keeps
capture ignorant of everything downstream (single responsibility).
"""

import queue
import threading
from dataclasses import dataclass
from typing import Optional

try:
    from scapy.all import sniff, ARP, IP, Ether
except ImportError:  # pragma: no cover
    sniff = ARP = IP = Ether = None


@dataclass
class CapturedFrame:
    src_ip: str
    src_mac: str
    ttl: Optional[int]
    length: int
    is_arp: bool


class CaptureThread(threading.Thread):
    """
    Wraps scapy.sniff() in a daemon thread and feeds parsed frames into
    `out_queue` for a consumer to process.
    """

    def __init__(self, iface: Optional[str], out_queue: "queue.Queue[CapturedFrame]",
                 bpf_filter: str = "arp or ip"):
        super().__init__(daemon=True, name="CaptureThread")
        if sniff is None:
            raise RuntimeError(
                "scapy is not installed. Run: pip install scapy"
            )
        self.iface = iface
        self.out_queue = out_queue
        self.bpf_filter = bpf_filter
        self._stop_event = threading.Event()

    def _on_packet(self, pkt) -> None:
        try:
            if ARP in pkt:
                frame = CapturedFrame(
                    src_ip=pkt[ARP].psrc,
                    src_mac=pkt[ARP].hwsrc,
                    ttl=None,
                    length=len(pkt),
                    is_arp=True,
                )
                self.out_queue.put_nowait(frame)
            elif IP in pkt and Ether in pkt:
                frame = CapturedFrame(
                    src_ip=pkt[IP].src,
                    src_mac=pkt[Ether].src,
                    ttl=int(pkt[IP].ttl),
                    length=len(pkt),
                    is_arp=False,
                )
                self.out_queue.put_nowait(frame)
        except queue.Full:
            # processing thread is falling behind; drop the frame rather
            # than block the capture loop
            pass
        except Exception:
            # never let a malformed/odd packet kill the sniffer
            pass

    def run(self) -> None:
        sniff(
            iface=self.iface,
            filter=self.bpf_filter,
            prn=self._on_packet,
            store=False,
            stop_filter=lambda _pkt: self._stop_event.is_set(),
        )

    def stop(self) -> None:
        self._stop_event.set()
