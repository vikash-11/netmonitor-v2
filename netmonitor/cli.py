"""
cli.py
------
Ties every layer together and drives the program from the terminal:

    ARP active scan (startup) --> DeviceTable
    CaptureThread  --(queue)-->  processing loop --> DeviceTable
                                                   --> Fingerprinting
                                                   --> IDSEngine --> alerts printed live
    periodic refresh            --> plain terminal table redraw
    on exit / SIGINT            --> optional export to JSON/CSV/TXT

Output is a simple redraw-based terminal table (clear + reprint), not a
curses dashboard — keeps the dependency list at just scapy and stays
readable when piped/redirected, at the cost of a little flicker on very
narrow terminals. Swap `_render_table` for a curses UI if you want a
persistent, flicker-free dashboard later.
"""

import argparse
import os
import queue
import shutil
import sys
import threading
import time

from .capture import CaptureThread
from .device_table import DeviceTable
from .discovery import PassiveArpWatcher, seed_table_from_scan
from .exporter import export
from .fingerprint import fingerprint_device
from .ids_alerts import Alert, AlertLevel, IDSEngine


def _print_alert_live(alert: Alert) -> None:
    color = {
        AlertLevel.INFO: "\033[94m",       # blue
        AlertLevel.WARNING: "\033[93m",    # yellow
        AlertLevel.CRITICAL: "\033[91m",   # red
    }.get(alert.level, "")
    reset = "\033[0m"
    print(f"{color}{alert.format()}{reset}", file=sys.stderr)


def _render_table(table: DeviceTable, refresh_count: int) -> None:
    width = shutil.get_terminal_size(fallback=(100, 24)).columns
    os.system("cls" if os.name == "nt" else "clear")
    print("NetMonitor v2 — LAN Monitoring".center(width))
    print(f"devices: {len(table)}   refresh #{refresh_count}   "
          f"{time.strftime('%H:%M:%S')}".center(width))
    print("-" * width)
    header = f"{'IP':<16}{'MAC':<19}{'Vendor':<24}{'OS guess':<28}{'Pkts':>8}{'Bytes':>10}"
    print(header)
    print("-" * width)
    for d in sorted(table.all_devices(), key=lambda x: x.ip):
        flag = "*" if d.is_new else " "
        print(f"{flag}{d.ip:<15}{d.mac:<19}{d.vendor[:22]:<24}"
              f"{d.os_guess[:26]:<28}{d.packet_count:>8}{d.byte_count:>10}")
    print("-" * width)
    print("(* = newly discovered this session)   Ctrl+C to stop")


def _processing_loop(frame_queue: "queue.Queue", table: DeviceTable,
                      watcher: PassiveArpWatcher, ids: IDSEngine,
                      stop_event: threading.Event) -> None:
    """Consumer thread: drains frame_queue, updates table, runs fingerprinting + IDS."""
    while not stop_event.is_set():
        try:
            frame = frame_queue.get(timeout=0.5)
        except queue.Empty:
            continue

        previous_mac = table.mac_for_ip(frame.src_ip)
        device, is_new_device, mac_changed = watcher.process_frame(frame)

        # fingerprint on every update; cheap (dict lookup + small compute)
        vendor, os_guess = fingerprint_device(device.mac, device.ttl_samples)
        table.set_fingerprint(frame.src_ip, vendor=vendor, os_guess=os_guess)

        ids.evaluate(
            ip=frame.src_ip, mac=frame.src_mac,
            is_new_device=is_new_device, mac_changed=mac_changed,
            previous_mac=previous_mac,
        )


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netmonitor",
        description="NetMonitor v2 — ARP-based LAN device discovery, "
                     "fingerprinting, and lightweight IDS alerting.",
    )
    parser.add_argument("-i", "--iface", default=None,
                         help="Network interface to sniff on (default: scapy's auto-pick)")
    parser.add_argument("-c", "--cidr", default=None,
                         help="CIDR range for the initial active ARP scan, "
                              "e.g. 192.168.1.0/24. If omitted, active scan is skipped "
                              "and only passive discovery runs.")
    parser.add_argument("--refresh", type=float, default=2.0,
                         help="Terminal redraw interval in seconds (default: 2.0)")
    parser.add_argument("--traffic-window", type=int, default=10,
                         help="IDS rolling window (seconds) for traffic-spike detection")
    parser.add_argument("--traffic-threshold", type=int, default=300,
                         help="Packet count within the window that triggers a TRAFFIC_SPIKE alert")
    parser.add_argument("--export", dest="export_path", default=None,
                         help="Path to write a report to on exit, e.g. report.json")
    parser.add_argument("--export-format", choices=["json", "csv", "txt"], default="json",
                         help="Export format (default: json)")
    parser.add_argument("--no-dashboard", action="store_true",
                         help="Disable the redrawing table; only print alerts as they occur")
    return parser


def main(argv=None) -> int:
    args = build_arg_parser().parse_args(argv)

    table = DeviceTable()
    ids = IDSEngine(
        traffic_window_seconds=args.traffic_window,
        traffic_packet_threshold=args.traffic_threshold,
        on_alert=_print_alert_live,
    )
    watcher = PassiveArpWatcher(table)
    frame_queue: "queue.Queue" = queue.Queue(maxsize=5000)
    stop_event = threading.Event()

    if args.cidr:
        print(f"[*] Running active ARP scan on {args.cidr} ...")
        try:
            found = seed_table_from_scan(table, args.cidr, iface=args.iface)
            print(f"[*] Active scan found {found} device(s)")
        except PermissionError:
            print("[!] Active scan needs elevated privileges (try running with sudo).")
        except Exception as e:
            print(f"[!] Active scan failed: {e}")

    try:
        capture = CaptureThread(iface=args.iface, out_queue=frame_queue)
    except RuntimeError as e:
        print(f"[!] {e}")
        return 1

    processor = threading.Thread(
        target=_processing_loop,
        args=(frame_queue, table, watcher, ids, stop_event),
        daemon=True, name="ProcessingThread",
    )

    print("[*] Starting capture (Ctrl+C to stop)...")
    try:
        capture.start()
    except PermissionError:
        print("[!] Packet capture needs elevated privileges (try running with sudo).")
        return 1
    processor.start()

    refresh_count = 0
    try:
        while True:
            if not args.no_dashboard:
                _render_table(table, refresh_count)
                refresh_count += 1
            time.sleep(args.refresh)
    except KeyboardInterrupt:
        print("\n[*] Stopping...")
    finally:
        stop_event.set()
        capture.stop()

        if args.export_path:
            try:
                export(table, args.export_path, args.export_format,
                       alerts=ids.recent_alerts(n=len(ids.alerts)))
                print(f"[*] Report written to {args.export_path}")
            except Exception as e:
                print(f"[!] Export failed: {e}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
