#!/usr/bin/env python3
"""
Network Threat Dashboard — main entry point.

Usage:
  Live capture (requires root):
    sudo python main.py --live --iface eth0

  Analyse a .pcap file:
    python main.py --pcap samples/capture.pcap

  Both with HTML report export:
    sudo python main.py --live --iface eth0 --report
    python main.py --pcap samples/capture.pcap --report
"""

import argparse
import sys
from capture import LiveCapture, PcapCapture
from dashboard import Dashboard
from reporter import generate_html_report


def parse_args():
    parser = argparse.ArgumentParser(
        description="Network Threat Dashboard — detect and visualise network threats in real time."
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--live", action="store_true", help="Live packet capture (requires root/admin)")
    mode.add_argument("--pcap", metavar="FILE", help="Analyse an existing .pcap file")

    parser.add_argument("--iface", default=None, help="Network interface for live capture (e.g. eth0, wlan0)")
    parser.add_argument("--report", action="store_true", help="Export an HTML report when done")
    parser.add_argument("--report-out", default="reports/threat_report.html", metavar="PATH",
                        help="Output path for the HTML report (default: reports/threat_report.html)")
    parser.add_argument("--timeout", type=int, default=0,
                        help="Stop live capture after N seconds (0 = run until Ctrl+C)")
    return parser.parse_args()


def main():
    args = parse_args()

    if args.live:
        try:
            from scapy.all import conf  # noqa — just check import
        except ImportError:
            print("[error] scapy is not installed. Run:  pip install scapy")
            sys.exit(1)
        capture = LiveCapture(iface=args.iface, timeout=args.timeout or None)
    else:
        import os
        if not os.path.isfile(args.pcap):
            print(f"[error] File not found: {args.pcap}")
            sys.exit(1)
        capture = PcapCapture(path=args.pcap)

    dashboard = Dashboard(capture)

    try:
        dashboard.run()
    except KeyboardInterrupt:
        pass
    finally:
        if args.report:
            out = args.report_out
            generate_html_report(capture.state, out)
            print(f"\n[+] HTML report saved → {out}")


if __name__ == "__main__":
    main()
