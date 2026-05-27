"""
src/detectors.py — stateful threat detectors.

Each detector exposes a single method:
    analyse(packet, state) -> None
It inspects the packet, updates internal state, and appends ThreatEvent
objects to state when a threat is confirmed.
"""

from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, Set

from state import CaptureState, ThreatEvent


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def _now() -> datetime:
    return datetime.now()


def _event(severity, category, src, dst, detail) -> ThreatEvent:
    return ThreatEvent(
        timestamp=_now(),
        severity=severity,
        category=category,
        src_ip=src,
        dst_ip=dst,
        detail=detail,
    )


# ──────────────────────────────────────────────
# 1. Port scan detector
# ──────────────────────────────────────────────

class PortScanDetector:
    """
    Detects horizontal and vertical port scans.

    Thresholds (tunable):
      - SYN to ≥15 distinct ports from one source within 10 s  → HIGH
      - SYN to ≥30 distinct ports from one source within 10 s  → CRITICAL
    """

    WINDOW_SECONDS = 10
    THRESHOLD_HIGH = 15
    THRESHOLD_CRITICAL = 30

    def __init__(self):
        # src_ip → deque of (timestamp, dst_port)
        self._data: Dict[str, deque] = defaultdict(deque)
        # track already-alerted sources to avoid duplicate spam
        self._alerted: Dict[str, datetime] = {}

    def analyse(self, packet, state: CaptureState):
        try:
            from scapy.layers.inet import TCP, IP
        except ImportError:
            return

        if not (packet.haslayer(IP) and packet.haslayer(TCP)):
            return

        # Only SYN packets (flags & 0x02)
        tcp = packet[TCP]
        if not (tcp.flags & 0x02 and not tcp.flags & 0x10):
            return

        src = packet[IP].src
        dst = packet[IP].dst
        dport = tcp.dport
        now = _now()
        cutoff = now - timedelta(seconds=self.WINDOW_SECONDS)

        buf = self._data[src]
        buf.append((now, dport))

        # Purge old entries
        while buf and buf[0][0] < cutoff:
            buf.popleft()

        distinct_ports: Set[int] = {p for _, p in buf}
        count = len(distinct_ports)

        # Cooldown: don't re-alert within 15 s for same source
        last = self._alerted.get(src)
        if last and (now - last).total_seconds() < 15:
            return

        if count >= self.THRESHOLD_CRITICAL:
            state.add_event(_event(
                "CRITICAL", "PORT_SCAN", src, dst,
                f"SYN scan: {count} distinct ports in {self.WINDOW_SECONDS}s"
            ))
            self._alerted[src] = now
        elif count >= self.THRESHOLD_HIGH:
            state.add_event(_event(
                "HIGH", "PORT_SCAN", src, dst,
                f"SYN scan: {count} distinct ports in {self.WINDOW_SECONDS}s"
            ))
            self._alerted[src] = now


# ──────────────────────────────────────────────
# 2. ARP spoofing detector
# ──────────────────────────────────────────────

class ARPSpoofDetector:
    """
    Detects ARP cache poisoning by tracking IP→MAC mappings.
    Alerts when a known IP is claimed by a new MAC address.
    """

    def __init__(self):
        # ip → mac
        self._table: Dict[str, str] = {}

    def analyse(self, packet, state: CaptureState):
        try:
            from scapy.layers.l2 import ARP
        except ImportError:
            return

        if not packet.haslayer(ARP):
            return

        arp = packet.getlayer(ARP)
        # op=2 is ARP reply (is-at)
        if arp.op != 2:
            return

        ip = arp.psrc
        mac = arp.hwsrc

        if not ip or not mac:
            return

        known_mac = self._table.get(ip)
        if known_mac is None:
            self._table[ip] = mac
            return

        if known_mac != mac:
            state.add_event(_event(
                "CRITICAL", "ARP_SPOOF", mac, ip,
                f"IP {ip} changed MAC: {known_mac} → {mac}"
            ))
            # Update table to latest (attacker may keep changing)
            self._table[ip] = mac


# ──────────────────────────────────────────────
# 3. Suspicious DNS detector
# ──────────────────────────────────────────────

SUSPICIOUS_TLD = {".ru", ".cn", ".tk", ".top", ".xyz", ".pw", ".cc", ".su", ".bit"}
SUSPICIOUS_KEYWORDS = [
    "malware", "botnet", "c2", "payload", "dropper",
    "exfil", "ransomware", "phish", "trojan", "hack",
    "darkweb", "onion", "tor2web",
]
DGA_MIN_LEN = 16   # domains longer than this with high entropy are DGA candidates


def _shannon_entropy(s: str) -> float:
    import math
    if not s:
        return 0.0
    freq = defaultdict(int)
    for c in s:
        freq[c] += 1
    length = len(s)
    return -sum((f / length) * math.log2(f / length) for f in freq.values())


class DNSSuspiciousDetector:
    """
    Flags:
      - Queries to suspicious TLDs
      - Domain names containing threat-related keywords
      - Algorithmically generated domain names (high entropy, long label)
      - DNS over non-standard port (not 53)
    """

    def __init__(self):
        self._seen: Set[str] = set()

    def analyse(self, packet, state: CaptureState):
        try:
            from scapy.layers.dns import DNS, DNSQR
            from scapy.layers.inet import IP, UDP
        except ImportError:
            return

        if not packet.haslayer(DNS):
            return

        dns = packet[DNS]
        if dns.qr != 0 or not packet.haslayer(DNSQR):
            return  # only queries

        src = packet[IP].src if packet.haslayer(IP) else "?"
        dst = packet[IP].dst if packet.haslayer(IP) else "?"

        try:
            qname = packet[DNSQR].qname.decode("utf-8", errors="replace").rstrip(".")
        except Exception:
            return

        if qname in self._seen:
            return

        lower = qname.lower()

        # Non-standard port
        if packet.haslayer(UDP) and packet[UDP].dport not in (53, 5353):
            self._seen.add(qname)
            state.add_event(_event(
                "HIGH", "DNS_SUSPICIOUS", src, dst,
                f"DNS on non-standard port {packet[UDP].dport}: {qname}"
            ))
            return

        # Suspicious TLD
        for tld in SUSPICIOUS_TLD:
            if lower.endswith(tld):
                self._seen.add(qname)
                state.add_event(_event(
                    "MEDIUM", "DNS_SUSPICIOUS", src, dst,
                    f"Query to suspicious TLD ({tld}): {qname}"
                ))
                return

        # Keyword match
        for kw in SUSPICIOUS_KEYWORDS:
            if kw in lower:
                self._seen.add(qname)
                state.add_event(_event(
                    "HIGH", "DNS_SUSPICIOUS", src, dst,
                    f"Threat keyword '{kw}' in domain: {qname}"
                ))
                return

        # DGA heuristic: long label + high entropy
        label = lower.split(".")[0]
        if len(label) >= DGA_MIN_LEN and _shannon_entropy(label) > 3.5:
            self._seen.add(qname)
            state.add_event(_event(
                "MEDIUM", "DNS_SUSPICIOUS", src, dst,
                f"Possible DGA domain (entropy={_shannon_entropy(label):.2f}): {qname}"
            ))


# ──────────────────────────────────────────────
# 4. Brute-force detector (SSH / FTP)
# ──────────────────────────────────────────────

BRUTE_PORTS = {22: "SSH", 21: "FTP", 3389: "RDP", 23: "Telnet"}


class BruteForceDetector:
    """
    Detects repeated TCP SYN attempts to auth-related ports from one source.

    Thresholds:
      - ≥10 attempts in 30 s → MEDIUM
      - ≥25 attempts in 30 s → HIGH
      - ≥50 attempts in 30 s → CRITICAL
    """

    WINDOW_SECONDS = 30
    THRESHOLDS = [(50, "CRITICAL"), (25, "HIGH"), (10, "MEDIUM")]

    def __init__(self):
        # (src_ip, dst_port) → deque of timestamps
        self._data: Dict[tuple, deque] = defaultdict(deque)
        self._alerted: Dict[tuple, datetime] = {}

    def analyse(self, packet, state: CaptureState):
        try:
            from scapy.layers.inet import TCP, IP
        except ImportError:
            return

        if not (packet.haslayer(IP) and packet.haslayer(TCP)):
            return

        tcp = packet[TCP]
        if not (tcp.flags & 0x02 and not tcp.flags & 0x10):
            return  # SYN only

        dport = tcp.dport
        if dport not in BRUTE_PORTS:
            return

        src = packet[IP].src
        dst = packet[IP].dst
        now = _now()
        key = (src, dport)
        cutoff = now - timedelta(seconds=self.WINDOW_SECONDS)

        buf = self._data[key]
        buf.append(now)
        while buf and buf[0] < cutoff:
            buf.popleft()

        count = len(buf)

        last = self._alerted.get(key)
        if last and (now - last).total_seconds() < 20:
            return

        service = BRUTE_PORTS[dport]
        for threshold, severity in self.THRESHOLDS:
            if count >= threshold:
                state.add_event(_event(
                    severity, "BRUTE_FORCE", src, dst,
                    f"{service} brute-force: {count} SYNs in {self.WINDOW_SECONDS}s (port {dport})"
                ))
                self._alerted[key] = now
                break
