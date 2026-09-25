"""
exporter.py
-----------
Writes the current device table (and optionally the alert log) out to
disk in JSON, CSV, or plain-text form. Kept format-agnostic and free of
any CLI/argparse concerns so it can be called from the CLI, a scheduled
job, or a unit test equally easily.
"""

import csv
import json
import time
from typing import List, Optional

from .device_table import DeviceTable
from .ids_alerts import Alert


def export_json(table: DeviceTable, path: str, alerts: Optional[List[Alert]] = None) -> None:
    payload = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "device_count": len(table),
        "devices": [d.as_dict() for d in table.all_devices()],
    }
    if alerts is not None:
        payload["alerts"] = [
            {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(a.timestamp)),
                "level": a.level.value,
                "category": a.category,
                "message": a.message,
                "ip": a.ip,
                "mac": a.mac,
            }
            for a in alerts
        ]
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def export_csv(table: DeviceTable, path: str) -> None:
    devices = table.all_devices()
    fieldnames = ["ip", "mac", "vendor", "os_guess", "hostname",
                  "first_seen", "last_seen", "packet_count", "byte_count"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for d in devices:
            writer.writerow(d.as_dict())


def export_txt(table: DeviceTable, path: str, alerts: Optional[List[Alert]] = None) -> None:
    devices = table.all_devices()
    lines = []
    lines.append(f"NetMonitor v2 report — generated {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Devices seen: {len(devices)}")
    lines.append("-" * 70)
    for d in devices:
        info = d.as_dict()
        lines.append(
            f"{info['ip']:<15} {info['mac']:<18} {info['vendor']:<22} "
            f"{info['os_guess']:<28} pkts={info['packet_count']:<6} "
            f"bytes={info['byte_count']}"
        )
    if alerts:
        lines.append("")
        lines.append("Alerts")
        lines.append("-" * 70)
        for a in alerts:
            lines.append(a.format())

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def export(table: DeviceTable, path: str, fmt: str, alerts: Optional[List[Alert]] = None) -> None:
    """Dispatch to the right exporter based on `fmt` ('json' | 'csv' | 'txt')."""
    fmt = fmt.lower()
    if fmt == "json":
        export_json(table, path, alerts=alerts)
    elif fmt == "csv":
        export_csv(table, path)
    elif fmt == "txt":
        export_txt(table, path, alerts=alerts)
    else:
        raise ValueError(f"Unsupported export format: {fmt}")
