"""
fingerprint.py
---------------
Lightweight, dependency-free device fingerprinting.

Two independent signals are combined:

1. MAC vendor prefix (OUI — first 3 octets of the MAC) -> manufacturer.
   This is looked up from a small bundled OUI table (`_OUI_TABLE`) rather
   than an external API, so the tool stays fully offline. Swap this for
   the full IEEE OUI CSV if you want broader coverage.

2. TTL fingerprinting -> rough OS family guess. Different OS network
   stacks default to different initial TTLs, and by the time a packet
   crosses your LAN the observed TTL is usually within a hop or two of
   the OS default:
       - Windows            -> default TTL 128
       - Linux / Android     -> default TTL 64
       - macOS / iOS / BSD  -> default TTL 64  (indistinguishable from
                                Linux by TTL alone — flagged as such)
       - Cisco/network gear -> default TTL 255
   We bucket the *observed* TTL up to the nearest common default
   (64 / 128 / 255) to absorb router hops, then map that to a guess.
"""

from typing import List, Optional

# A small, illustrative OUI table. Extend as needed, or load a full
# IEEE OUI list (manuf file from Wireshark) into this dict at startup.
_OUI_TABLE = {
    "00:1A:2B": "Cisco Systems",
    "00:0C:29": "VMware Virtual NIC",
    "00:50:56": "VMware Virtual NIC",
    "00:1B:63": "Apple",
    "F0:18:98": "Apple",
    "3C:5A:B4": "Apple (Google/other)",
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Foundation",
    "E4:5F:01": "Raspberry Pi Foundation",
    "00:1D:D8": "Microsoft",
    "7C:1E:52": "Samsung Electronics",
    "AC:37:43": "Samsung Electronics",
    "00:1E:C2": "Apple",
    "F4:F5:D8": "Google",
    "3C:D9:2B": "Hewlett Packard",
    "00:26:B0": "TP-Link Technologies",
    "50:C7:BF": "TP-Link Technologies",
    "00:14:BF": "Cisco-Linksys",
    "00:24:01": "D-Link",
    "00:0D:B9": "MikroTik",
    "08:00:27": "Oracle VirtualBox",
    "52:54:00": "QEMU/KVM Virtual NIC",
}

_COMMON_TTL_DEFAULTS = (64, 128, 255)


def lookup_vendor(mac: str) -> str:
    """Best-effort vendor guess from the MAC's OUI prefix."""
    if not mac or mac.count(":") < 2:
        return "Unknown"
    oui = mac.upper()[:8]  # "AA:BB:CC"
    return _OUI_TABLE.get(oui, "Unknown")


def guess_os_from_ttl(ttl_samples: List[int]) -> str:
    """
    Bucket observed TTLs to the nearest common OS default and return a
    human-readable guess. Uses the *maximum* observed TTL in the sample
    window, since TTL only decreases per hop — the max is the closest
    we get to the sender's original value.
    """
    if not ttl_samples:
        return "Unknown"

    observed = max(ttl_samples)
    nearest_default = min(_COMMON_TTL_DEFAULTS, key=lambda d: abs(d - observed)
                           if observed <= d else float("inf") if observed > d + 5 else abs(d - observed))

    # fall back: pick the smallest default that is >= observed (accounts
    # for hop decrement), else the closest by absolute distance
    candidates = [d for d in _COMMON_TTL_DEFAULTS if d >= observed]
    nearest_default = min(candidates) if candidates else min(
        _COMMON_TTL_DEFAULTS, key=lambda d: abs(d - observed)
    )

    if nearest_default == 64:
        return "Linux / Android / macOS (TTL~64)"
    if nearest_default == 128:
        return "Windows (TTL~128)"
    if nearest_default == 255:
        return "Network device / Cisco-like (TTL~255)"
    return "Unknown"


def fingerprint_device(mac: str, ttl_samples: List[int]) -> "tuple[str, str]":
    """Convenience wrapper returning (vendor, os_guess)."""
    return lookup_vendor(mac), guess_os_from_ttl(ttl_samples)
