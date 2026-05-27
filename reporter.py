"""
src/reporter.py — generates a self-contained HTML threat report.
No external dependencies: pure stdlib + inline CSS/JS.
"""

import os
from datetime import datetime
from state import CaptureState, CATEGORY_LABELS

SEV_COLOR = {
    "CRITICAL": "#cc0000",
    "HIGH":     "#e65c00",
    "MEDIUM":   "#b8860b",
    "LOW":      "#2255aa",
    "INFO":     "#555555",
}

SEV_BG = {
    "CRITICAL": "#ffe0e0",
    "HIGH":     "#fff0e0",
    "MEDIUM":   "#fffbe0",
    "LOW":      "#e0eaff",
    "INFO":     "#f0f0f0",
}


def _badge(severity):
    fg = SEV_COLOR.get(severity, "#333")
    bg = SEV_BG.get(severity, "#eee")
    return (f'<span style="background:{bg};color:{fg};border:1px solid {fg};'
            f'padding:1px 6px;font-size:11px;font-family:monospace;">{severity}</span>')


def _event_rows(state):
    if not state.events:
        return '<tr><td colspan="6" style="color:#999;padding:8px;">no threats detected</td></tr>'
    rows = []
    for ev in sorted(state.events, key=lambda e: e.timestamp, reverse=True):
        cat = CATEGORY_LABELS.get(ev.category, ev.category)
        rows.append(
            f'<tr>'
            f'<td style="font-family:monospace;color:#555">{ev.timestamp.strftime("%H:%M:%S")}</td>'
            f'<td>{_badge(ev.severity)}</td>'
            f'<td style="font-family:monospace">{cat}</td>'
            f'<td style="font-family:monospace">{ev.src_ip}</td>'
            f'<td style="font-family:monospace">{ev.dst_ip}</td>'
            f'<td style="color:#333">{ev.detail}</td>'
            f'</tr>'
        )
    return "\n".join(rows)


def _talker_rows(state):
    talkers = state.top_n_talkers(8)
    if not talkers:
        return '<tr><td colspan="2" style="color:#999">none</td></tr>'
    max_c = talkers[0][1] or 1
    rows = []
    for ip, count in talkers:
        pct = int((count / max_c) * 100)
        bar = "█" * (pct // 8) + "░" * (12 - pct // 8)
        rows.append(
            f'<tr>'
            f'<td style="font-family:monospace;padding:3px 8px">{ip}</td>'
            f'<td style="font-family:monospace;color:#555;padding:3px 8px">{bar} {count}</td>'
            f'</tr>'
        )
    return "\n".join(rows)


def _chart_data(state):
    items = []
    for cat, label in CATEGORY_LABELS.items():
        items.append(f'{{label:"{label}",value:{state.threat_counts.get(cat,0)}}}')
    return "[" + ",".join(items) + "]"


def generate_html_report(state: CaptureState, out_path: str):
    os.makedirs(os.path.dirname(out_path) if os.path.dirname(out_path) else ".", exist_ok=True)

    now = datetime.now()
    generated_at = now.strftime("%Y-%m-%d %H:%M:%S")
    secs = int((now - state.start_time).total_seconds())
    duration_str = f"{secs//3600:02d}:{(secs%3600)//60:02d}:{secs%60:02d}"

    total = state.total_threats
    critical = sum(1 for e in state.events if e.severity == "CRITICAL")
    high     = sum(1 for e in state.events if e.severity == "HIGH")
    threat_color = "#cc0000" if total else "#007700"

    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Threat Report - {generated_at}</title>
<style>
  body {{
    font-family: Arial, sans-serif;
    font-size: 13px;
    background: #f4f4f4;
    color: #222;
    margin: 0;
    padding: 16px;
  }}
  h1 {{
    font-size: 18px;
    margin: 0 0 4px 0;
    color: #111;
  }}
  h2 {{
    font-size: 13px;
    font-weight: bold;
    margin: 0 0 6px 0;
    color: #333;
    border-bottom: 1px solid #ccc;
    padding-bottom: 3px;
  }}
  .meta {{
    color: #666;
    font-size: 12px;
    margin-bottom: 14px;
  }}
  .row {{
    display: flex;
    gap: 12px;
    margin-bottom: 12px;
    flex-wrap: wrap;
  }}
  .box {{
    background: #fff;
    border: 1px solid #ccc;
    padding: 10px 14px;
    flex: 1;
    min-width: 160px;
  }}
  .stat-num {{
    font-size: 28px;
    font-weight: bold;
    line-height: 1.1;
  }}
  .stat-lbl {{
    font-size: 11px;
    color: #666;
    margin-top: 2px;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    background: #fff;
    border: 1px solid #ccc;
  }}
  th {{
    background: #e8e8e8;
    border: 1px solid #ccc;
    padding: 5px 8px;
    text-align: left;
    font-size: 12px;
  }}
  td {{
    border: 1px solid #ddd;
    padding: 4px 8px;
    vertical-align: middle;
  }}
  tr:nth-child(even) td {{ background: #fafafa; }}
  .section {{
    margin-bottom: 14px;
  }}
  .footer {{
    margin-top: 16px;
    font-size: 11px;
    color: #999;
    border-top: 1px solid #ddd;
    padding-top: 8px;
  }}
  canvas {{ display: block; margin-top: 6px; }}
</style>
</head>
<body>

<h1>Network Threat Report</h1>
<div class="meta">
  Source: <b>{state.source_label}</b> &nbsp;|&nbsp;
  Generated: {generated_at} &nbsp;|&nbsp;
  Duration: {duration_str} &nbsp;|&nbsp;
  Packets analysed: <b>{state.total_packets:,}</b>
</div>

<div class="row">
  <div class="box">
    <div class="stat-num" style="color:{threat_color}">{total}</div>
    <div class="stat-lbl">Total threats</div>
  </div>
  <div class="box">
    <div class="stat-num" style="color:#cc0000">{critical}</div>
    <div class="stat-lbl">Critical</div>
  </div>
  <div class="box">
    <div class="stat-num" style="color:#e65c00">{high}</div>
    <div class="stat-lbl">High</div>
  </div>
  <div class="box">
    <div class="stat-num">{state.tcp_packets:,}</div>
    <div class="stat-lbl">TCP packets</div>
  </div>
  <div class="box">
    <div class="stat-num">{state.udp_packets:,}</div>
    <div class="stat-lbl">UDP packets</div>
  </div>
  <div class="box">
    <div class="stat-num">{state.icmp_packets:,}</div>
    <div class="stat-lbl">ICMP packets</div>
  </div>
</div>

<div class="row">
  <div class="section" style="flex:1;min-width:220px">
    <h2>Threats by category</h2>
    <canvas id="bar" width="320" height="130"></canvas>
  </div>
  <div class="section" style="flex:1;min-width:220px">
    <h2>Top talkers</h2>
    <table>
      <thead><tr><th>IP address</th><th>Packets</th></tr></thead>
      <tbody>{_talker_rows(state)}</tbody>
    </table>
  </div>
</div>

<div class="section">
  <h2>Threat events ({total})</h2>
  <table>
    <thead>
      <tr>
        <th>Time</th>
        <th>Severity</th>
        <th>Category</th>
        <th>Source IP</th>
        <th>Dest IP</th>
        <th>Detail</th>
      </tr>
    </thead>
    <tbody>
      {_event_rows(state)}
    </tbody>
  </table>
</div>

<div class="footer">
  generated by network_threat_dashboard &mdash; {generated_at}
</div>

<script>
(function() {{
  var data = {_chart_data(state)};
  var colors = ['#4477cc', '#cc4444', '#ddaa22', '#7744aa'];
  var canvas = document.getElementById('bar');
  var ctx = canvas.getContext('2d');
  var maxVal = Math.max.apply(null, data.map(function(d){{return d.value||1}}));
  var barH = 22, gap = 8, padL = 110, padR = 40, padT = 10;

  canvas.height = data.length * (barH + gap) + padT + 10;

  data.forEach(function(d, i) {{
    var y = padT + i * (barH + gap);
    var barW = Math.max(2, (d.value / maxVal) * (canvas.width - padL - padR));

    ctx.fillStyle = '#eee';
    ctx.fillRect(padL, y, canvas.width - padL - padR, barH);

    ctx.fillStyle = colors[i % colors.length];
    ctx.fillRect(padL, y, barW, barH);

    ctx.fillStyle = '#333';
    ctx.font = '11px Arial';
    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';
    ctx.fillText(d.label, padL - 6, y + barH / 2);

    ctx.fillStyle = '#fff';
    ctx.textAlign = 'left';
    if (barW > 20) {{
      ctx.fillText(d.value, padL + 4, y + barH / 2);
    }} else {{
      ctx.fillStyle = '#333';
      ctx.fillText(d.value, padL + barW + 4, y + barH / 2);
    }}
  }});
}})();
</script>
</body>
</html>"""

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
