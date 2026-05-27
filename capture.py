"""
src/capture.py — packet capture backends.

LiveCapture   : uses scapy's sniff() in a background thread
PcapCapture   : reads a .pcap file and replays packets through detectors
"""

import threading
from state import CaptureState
from detectors import (
    PortScanDetector,
    ARPSpoofDetector,
    DNSSuspiciousDetector,
    BruteForceDetector,
)


def _get_proto(packet) -> str:
    try:
        from scapy.layers.inet import TCP, UDP, ICMP
    except ImportError:
        return "OTHER"
    if packet.haslayer(TCP):
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    if packet.haslayer(ICMP):
        return "ICMP"
    return "OTHER"


def _get_src_ip(packet) -> str:
    try:
        from scapy.layers.inet import IP
        if packet.haslayer(IP):
            return packet[IP].src
    except Exception:
        pass
    return None


class _BaseCapture:
    def __init__(self):
        self.state = CaptureState()
        self._detectors = [
            PortScanDetector(),
            ARPSpoofDetector(),
            DNSSuspiciousDetector(),
            BruteForceDetector(),
        ]

    def _process(self, packet):
        proto = _get_proto(packet)
        src_ip = _get_src_ip(packet)
        self.state.record_packet(proto, src_ip)
        for det in self._detectors:
            try:
                det.analyse(packet, self.state)
            except Exception:
                pass  # never let a detector crash the capture loop

    def start(self):
        raise NotImplementedError

    def stop(self):
        raise NotImplementedError


class LiveCapture(_BaseCapture):
    """
    Captures packets from a live network interface in a daemon thread.
    iface=None lets scapy pick the default interface.
    timeout=None runs indefinitely until stop() is called.
    """

    def __init__(self, iface=None, timeout=None):
        super().__init__()
        self.iface = iface
        self.timeout = timeout
        self._thread = None
        self._stop_event = threading.Event()
        self.state.source_label = f"live:{iface or 'default'}"

    def _sniff_loop(self):
        from scapy.all import sniff
        sniff(
            iface=self.iface,
            prn=self._process,
            store=False,
            stop_filter=lambda _: self._stop_event.is_set(),
            timeout=self.timeout,
        )
        self.state.finished = True

    def start(self):
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=3)


class PcapCapture(_BaseCapture):
    """
    Reads a .pcap / .pcapng file and processes all packets synchronously.
    Sets state.finished = True when complete.
    """

    def __init__(self, path: str):
        super().__init__()
        self.path = path
        self.state.source_label = f"pcap:{path}"

    def start(self):
        from scapy.all import PcapReader
        with PcapReader(self.path) as reader:
            for packet in reader:
                self._process(packet)
        self.state.finished = True

    def stop(self):
        # Nothing to stop — file reading is synchronous
        pass
