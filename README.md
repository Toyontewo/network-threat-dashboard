# Network Threat Dashboard 🛡️

A Python-based real-time network threat detection and visualisation tool.
Captures live traffic **or** analyses `.pcap` files, detects four classes of
threats, renders a live Rich terminal dashboard, and exports a self-contained
HTML report.

---

## Features

| Detector | What it catches |
|---|---|
| **Port Scan** | SYN scans — alerts at ≥15 ports (HIGH) and ≥30 ports (CRITICAL) within 10 s |
| **ARP Spoofing** | IP→MAC mapping changes in ARP replies (CRITICAL) |
| **Suspicious DNS** | Bad TLDs, threat keywords, DGA-like domains (high entropy), non-standard DNS port |
| **Brute Force** | Repeated SYNs to SSH/FTP/RDP/Telnet — graduated severity at 10/25/50 attempts in 30 s |

---

## Quick Start

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Generate a sample .pcap (no root needed)
```bash
python generate_sample_pcap.py
```

### 3. Analyse the sample file
```bash
python main.py --pcap samples/capture.pcap
```

### 4. Analyse and export an HTML report
```bash
python main.py --pcap samples/capture.pcap --report
# Report saved to: reports/threat_report.html
```

### 5. Live capture (requires root / Administrator)
```bash
sudo python main.py --live --iface eth0 --report
# Ctrl+C to stop; report auto-saved
```

---

## Project Structure

```
network_threat_dashboard/
├── main.py                    # Entry point & CLI
├── generate_sample_pcap.py    # Test pcap generator
├── requirements.txt
├── samples/                   # .pcap files
├── reports/                   # HTML reports (auto-created)
└── src/
    ├── state.py               # Shared CaptureState & ThreatEvent models
    ├── detectors.py           # Port scan, ARP, DNS, brute-force detectors
    ├── capture.py             # LiveCapture & PcapCapture backends
    ├── dashboard.py           # Rich terminal dashboard
    └── reporter.py            # HTML report generator
```

---

## CLI Reference

```
python main.py --live --iface <IFACE> [--timeout N] [--report] [--report-out PATH]
python main.py --pcap <FILE>                          [--report] [--report-out PATH]
```

| Flag | Description |
|---|---|
| `--live` | Live packet capture mode |
| `--pcap FILE` | Analyse a .pcap / .pcapng file |
| `--iface IFACE` | Network interface (default: scapy picks) |
| `--timeout N` | Stop live capture after N seconds |
| `--report` | Export HTML report when done |
| `--report-out PATH` | Report output path (default: `reports/threat_report.html`) |

---

## Detector Thresholds

All thresholds are defined as class constants — easy to tune:

```python
# src/detectors.py
class PortScanDetector:
    WINDOW_SECONDS = 10
    THRESHOLD_HIGH = 15
    THRESHOLD_CRITICAL = 30

class BruteForceDetector:
    WINDOW_SECONDS = 30
    THRESHOLDS = [(50, "CRITICAL"), (25, "HIGH"), (10, "MEDIUM")]
```

---

## Extending

To add a new detector:
1. Create a class in `src/detectors.py` with an `analyse(packet, state)` method.
2. Import and add an instance to the `_detectors` list in `src/capture.py`.
3. Add the new category key to `CaptureState.threat_counts` in `src/state.py`.

---

## Requirements

- Python 3.9+
- `scapy` ≥ 2.5.0
- `rich` ≥ 13.0.0
- Root/Administrator privileges for live capture only

---

## Author

Toyobong Samuel Ntewo — Network Security Analyst & Python Developer  
[GitHub](https://github.com/toyontewo) · [LinkedIn](https://www.linkedin.com/in/toyontewo/)
