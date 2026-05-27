"""
src/dashboard.py — live terminal dashboard powered by Rich.

Refreshes every second. Works for both live capture and pcap replay.
For pcap mode it starts capture in a thread so the dashboard stays responsive.
"""

import threading
import time
from datetime import datetime

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from state import CaptureState, SEVERITY_COLORS, CATEGORY_LABELS


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

def _severity_badge(sev: str) -> Text:
    color = SEVERITY_COLORS.get(sev, "white")
    return Text(f" {sev} ", style=f"{color} bold")


def _elapsed(start: datetime) -> str:
    secs = int((datetime.now() - start).total_seconds())
    h, rem = divmod(secs, 3600)
    m, s = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


class Dashboard:
    REFRESH_RATE = 1  # seconds

    def __init__(self, capture):
        self.capture = capture
        self.state: CaptureState = capture.state
        self.console = Console()

    # ── Panel builders ──────────────────────────────────────

    def _header_panel(self) -> Panel:
        mode = self.state.source_label
        elapsed = _elapsed(self.state.start_time)
        status = "[bold green]● LIVE[/]" if not self.state.finished else "[bold yellow]● FINISHED[/]"
        content = Text.assemble(
            ("  Network Threat Dashboard", "bold white"),
            ("  |  ", "dim"),
            (mode, "cyan"),
            ("  |  ", "dim"),
            ("Elapsed: ", "dim"),
            (elapsed, "white"),
            ("  |  ", "dim"),
        )
        content.append_text(Text.from_markup(status))
        return Panel(content, style="bold blue", padding=(0, 1))

    def _stats_panel(self) -> Panel:
        s = self.state
        table = Table.grid(expand=True, padding=(0, 2))
        table.add_column(justify="center")
        table.add_column(justify="center")
        table.add_column(justify="center")
        table.add_column(justify="center")
        table.add_column(justify="center")

        def stat(label, value, color="white"):
            return Text.assemble((str(value), f"bold {color}"), ("\n", ""), (label, "dim"))

        table.add_row(
            stat("Total Pkts",  s.total_packets,  "white"),
            stat("TCP",         s.tcp_packets,    "cyan"),
            stat("UDP",         s.udp_packets,    "blue"),
            stat("ICMP",        s.icmp_packets,   "magenta"),
            stat("Threats",     s.total_threats,  "red" if s.total_threats else "green"),
        )
        return Panel(table, title="[bold]Packet Stats[/]", box=box.ROUNDED, padding=(0, 1))

    def _threat_counts_panel(self) -> Panel:
        table = Table(show_header=False, box=None, expand=True, padding=(0, 2))
        table.add_column("Category", style="dim")
        table.add_column("Count", justify="right")

        colors = {
            "PORT_SCAN":      "cyan",
            "ARP_SPOOF":      "red",
            "DNS_SUSPICIOUS": "yellow",
            "BRUTE_FORCE":    "magenta",
        }
        for cat, label in CATEGORY_LABELS.items():
            count = self.state.threat_counts.get(cat, 0)
            color = colors[cat] if count else "dim"
            table.add_row(label, Text(str(count), style=f"bold {color}"))

        return Panel(table, title="[bold]Threats by Type[/]", box=box.ROUNDED, padding=(0, 1))

    def _top_talkers_panel(self) -> Panel:
        table = Table(show_header=False, box=None, expand=True, padding=(0, 1))
        table.add_column("IP", style="cyan", no_wrap=True)
        table.add_column("Packets", justify="right")

        talkers = self.state.top_n_talkers(5)
        if talkers:
            max_count = talkers[0][1] or 1
            for ip, count in talkers:
                bar_len = int((count / max_count) * 12)
                bar = "█" * bar_len
                table.add_row(ip, Text(f"{bar} {count}", style="bold white"))
        else:
            table.add_row("[dim]No data yet[/]", "")

        return Panel(table, title="[bold]Top Talkers[/]", box=box.ROUNDED, padding=(0, 1))

    def _events_panel(self, rows: int = 20) -> Panel:
        table = Table(
            box=box.SIMPLE_HEAD,
            expand=True,
            show_lines=False,
            padding=(0, 1),
        )
        table.add_column("Time",     style="dim",    width=10, no_wrap=True)
        table.add_column("Severity", width=10)
        table.add_column("Category", style="cyan",   width=16)
        table.add_column("Source",   style="white",  width=16)
        table.add_column("Dest",     style="white",  width=16)
        table.add_column("Detail",   style="dim")

        events = sorted(
            self.state.recent_events(rows),
            key=lambda e: SEVERITY_ORDER.get(e.severity, 99)
        )

        for ev in events:
            color = SEVERITY_COLORS.get(ev.severity, "white")
            table.add_row(
                ev.timestamp.strftime("%H:%M:%S"),
                Text(ev.severity, style=f"bold {color}"),
                CATEGORY_LABELS.get(ev.category, ev.category),
                ev.src_ip,
                ev.dst_ip,
                ev.detail,
            )

        title = f"[bold]Recent Threat Events[/] [dim]({self.state.total_threats} total)[/]"
        return Panel(table, title=title, box=box.ROUNDED, padding=(0, 1))

    def _footer_panel(self) -> Panel:
        content = Text("  [Ctrl+C] Stop capture   |   Report auto-saved if --report flag used", style="dim")
        return Panel(content, style="dim", padding=(0, 0))

    # ── Layout ──────────────────────────────────────────────

    def _build_layout(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(name="header",  size=3),
            Layout(name="stats",   size=5),
            Layout(name="middle",  size=10),
            Layout(name="events",  minimum_size=12),
            Layout(name="footer",  size=3),
        )
        layout["middle"].split_row(
            Layout(name="threat_counts"),
            Layout(name="top_talkers"),
        )
        return layout

    def _update_layout(self, layout: Layout):
        layout["header"].update(self._header_panel())
        layout["stats"].update(self._stats_panel())
        layout["threat_counts"].update(self._threat_counts_panel())
        layout["top_talkers"].update(self._top_talkers_panel())
        layout["events"].update(self._events_panel())
        layout["footer"].update(self._footer_panel())

    # ── Run ─────────────────────────────────────────────────

    def run(self):
        layout = self._build_layout()

        # For pcap: run capture in a background thread so the dashboard renders
        from capture import PcapCapture, LiveCapture

        if isinstance(self.capture, PcapCapture):
            t = threading.Thread(target=self.capture.start, daemon=True)
            t.start()
        else:
            self.capture.start()

        with Live(layout, refresh_per_second=1, screen=True, console=self.console):
            try:
                while True:
                    self._update_layout(layout)
                    time.sleep(self.REFRESH_RATE)
                    if self.state.finished:
                        # Give one final render
                        self._update_layout(layout)
                        time.sleep(2)
                        break
            except KeyboardInterrupt:
                self.capture.stop()
