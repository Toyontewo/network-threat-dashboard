"""
src/state.py — shared mutable state passed between capture, detectors, and dashboard.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Tuple
import threading


SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "cyan",
    "INFO":     "dim",
}


@dataclass
class ThreatEvent:
    timestamp: datetime
    severity: str          # CRITICAL | HIGH | MEDIUM | LOW | INFO
    category: str          # PORT_SCAN | ARP_SPOOF | DNS_SUSPICIOUS | BRUTE_FORCE
    src_ip: str
    dst_ip: str
    detail: str

    def as_row(self) -> Tuple:
        return (
            self.timestamp.strftime("%H:%M:%S"),
            self.severity,
            self.category,
            self.src_ip,
            self.dst_ip,
            self.detail,
        )


@dataclass
class CaptureState:
    """Thread-safe container for all runtime data."""
    lock: threading.Lock = field(default_factory=threading.Lock)

    # Packet counters
    total_packets: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    icmp_packets: int = 0
    other_packets: int = 0

    # Threat events (all detectors append here)
    events: List[ThreatEvent] = field(default_factory=list)

    # Per-category counters
    threat_counts: Dict[str, int] = field(default_factory=lambda: {
        "PORT_SCAN": 0,
        "ARP_SPOOF": 0,
        "DNS_SUSPICIOUS": 0,
        "BRUTE_FORCE": 0,
    })

    # Top talkers: src_ip → packet count
    top_talkers: Dict[str, int] = field(default_factory=dict)

    # Capture metadata
    start_time: datetime = field(default_factory=datetime.now)
    source_label: str = "unknown"
    finished: bool = False

    def add_event(self, event: ThreatEvent):
        with self.lock:
            self.events.append(event)
            self.threat_counts[event.category] = self.threat_counts.get(event.category, 0) + 1

    def record_packet(self, proto: str, src_ip: str = None):
        with self.lock:
            self.total_packets += 1
            if proto == "TCP":
                self.tcp_packets += 1
            elif proto == "UDP":
                self.udp_packets += 1
            elif proto == "ICMP":
                self.icmp_packets += 1
            else:
                self.other_packets += 1
            if src_ip:
                self.top_talkers[src_ip] = self.top_talkers.get(src_ip, 0) + 1

    @property
    def total_threats(self) -> int:
        return len(self.events)

    def top_n_talkers(self, n: int = 5) -> List[Tuple[str, int]]:
        with self.lock:
            return sorted(self.top_talkers.items(), key=lambda x: x[1], reverse=True)[:n]

    def recent_events(self, n: int = 30) -> List[ThreatEvent]:
        with self.lock:
            return list(self.events[-n:])


CATEGORY_LABELS = {
    "PORT_SCAN":      "Port Scan",
    "ARP_SPOOF":      "ARP Spoof",
    "DNS_SUSPICIOUS": "DNS Suspicious",
    "BRUTE_FORCE":    "Brute Force",
}
