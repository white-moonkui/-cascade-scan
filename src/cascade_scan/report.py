"""
Scan report export — generate HTML/JSON security evaluation reports.

Zero external dependencies.  Self-contained HTML (inline CSS, no JS).
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from cascade_scan.engine import ScanResult
from cascade_scan.scorer import SecurityScorer


def export_json(
    result: ScanResult,
    output: Optional[Path] = None,
    metadata: Optional[dict] = None,
) -> dict:
    """Export scan results as a structured JSON dict.

    Returns the dict (also writes to *output* if provided).
    """
    scorer_summary = SecurityScorer.summary(result.probe_results)

    report: dict[str, Any] = {
        "exported_at": datetime.utcnow().isoformat() + "Z",
        "scan": {
            "score": result.score,
            "passed": result.passed,
            "overall_pass_rate": result.overall_pass_rate,
            "total_probes": result.total_probes,
            "passed_probes": result.passed_probes,
            "total_vectors": result.total_vectors,
            "blocked_vectors": result.blocked_vectors,
        },
        "scorer": scorer_summary,
        "probes": [],
    }

    if metadata:
        report["metadata"] = metadata

    for pr in result.probe_results:
        report["probes"].append(
            {
                "name": pr.probe_name,
                "passed": pr.passed,
                "severity": pr.severity,
                "total": pr.total,
                "blocked": pr.blocked,
                "pass_rate": pr.pass_rate,
                "details": pr.details,
            }
        )

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(report, indent=2, default=str, ensure_ascii=False)
        )

    return report


def export_html(
    result: ScanResult,
    output: Optional[Path] = None,
    metadata: Optional[dict] = None,
    dark: bool = False,
) -> str:
    """Generate a self-contained HTML security evaluation report.

    Returns the HTML string (also writes to *output* if provided).

    Args:
        result: Scan result to render.
        output: Optional output file path.
        metadata: Optional dict to include as report metadata.
        dark: If True, force dark mode regardless of OS preference.
              If False (default), the user's OS preference via
              ``prefers-color-scheme`` is respected.
    """
    scorer_summary = SecurityScorer.summary(result.probe_results)

    # Summary cards
    grade_color = _grade_color(scorer_summary["grade"])
    score_color = "green" if result.passed else "red"

    cards_html = f"""
    <div class="card {score_color}"><div class="num">{result.score:.0f}</div><div class="label">Security Score</div></div>
    <div class="card" style="background:{grade_color}"><div class="num" style="color:#fff">{scorer_summary['grade']}</div><div class="label" style="color:#fff">Grade</div></div>
    <div class="card green"><div class="num">{result.blocked_vectors}</div><div class="label">Blocked (of {result.total_vectors})</div></div>
    <div class="card blue"><div class="num">{result.passed_probes}</div><div class="label">Probes Passed (of {result.total_probes})</div></div>
"""

    # Probe result table (with drill-down anchor links)
    probes_rows = ""
    for idx, pr in enumerate(result.probe_results):
        badge = _pass_badge(pr.passed)
        pass_bar = _pass_bar(pr.pass_rate)
        anchor = f"probe-{idx}"
        probes_rows += f"""
        <tr>
            <td>{badge}</td>
            <td><a href="#{anchor}" class="probe-link">{pr.probe_name}</a></td>
            <td><span class="sev {pr.severity}">{pr.severity}</span></td>
            <td>{pr.blocked}/{pr.total}</td>
            <td>{pr.pass_rate * 100:.0f}%</td>
            <td>{pass_bar}</td>
        </tr>"""

    # Probe detail sections — each in a <details>/<summary> collapsible
    # block (drill-down) with anchor link from summary table.
    details_html = ""
    for idx, pr in enumerate(result.probe_results):
        if not pr.details:
            continue
        anchor = f"probe-{idx}"
        badge = _pass_badge(pr.passed)
        open_attr = ' open' if not pr.passed else ''
        details_html += f"""
        <details id="{anchor}" class="probe-detail"{open_attr}>
        <summary>{badge} <strong>{pr.probe_name}</strong> &mdash;
                 {pr.blocked}/{pr.total} blocked
                 ({pr.pass_rate * 100:.0f}%, severity={pr.severity})
        </summary>
        <table>
        <thead><tr><th>#</th><th>Vector</th><th>Result</th><th>Detail</th></tr></thead>
        <tbody>"""
        for i, d in enumerate(pr.details[:200]):  # limit to 200 rows
            vec = d.get("vector", d.get("tool", "test"))
            blocked = d.get("blocked", d.get("correctly_blocked", False))
            # Some vectors have a 'result' badge from the probe itself
            badge = ('<span class="badge ok">BLOCKED</span>' if blocked
                     else '<span class="badge fail">PASSED</span>')
            # Other keys shown as compact key=value pairs
            extras = {k: v for k, v in d.items()
                      if k not in ("vector", "blocked", "correctly_blocked")}
            extras_str = " ".join(f'<span class="kv"><b>{_escape(k)}</b>={_escape(str(v))}</span>'
                                  for k, v in extras.items())
            details_html += f"<tr><td>{i + 1}</td><td><code>{_escape(vec)}</code></td><td>{badge}</td><td>{extras_str}</td></tr>"
        if len(pr.details) > 200:
            details_html += f"<tr><td colspan='4'><em>… {len(pr.details) - 200} more vectors omitted</em></td></tr>"
        details_html += "</tbody></table></details>"

    color_scheme_meta = (
        '<meta name="color-scheme" content="dark light">' if dark is False
        else '<meta name="color-scheme" content="dark">'
    )
    body_class = ' class="dark"' if dark else ''

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
{color_scheme_meta}
<title>cascade-scan — Security Evaluation Report</title>
<style>
  :root {{
    --bg: #f8f9fa; --fg: #222; --card-bg: #fff; --subtle: #666;
    --table-bg: #fff; --table-row: #fafafa; --th-bg: #f0f0f0;
    --code-bg: #f4f4f4; --border: rgba(0,0,0,0.1);
  }}
  @media (prefers-color-scheme: dark) {{
    :root {{
      --bg: #0f1419; --fg: #e6e6e6; --card-bg: #1c2128; --subtle: #8b949e;
      --table-bg: #161b22; --table-row: #1c2128; --th-bg: #21262d;
      --code-bg: #21262d; --border: rgba(255,255,255,0.1);
    }}
  }}
  body.dark {{
    --bg: #0f1419; --fg: #e6e6e6; --card-bg: #1c2128; --subtle: #8b949e;
    --table-bg: #161b22; --table-row: #1c2128; --th-bg: #21262d;
    --code-bg: #21262d; --border: rgba(255,255,255,0.1);
  }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         max-width: 1100px; margin: 0 auto; padding: 20px;
         background: var(--bg); color: var(--fg); }}
  h1 {{ font-size: 1.6em; margin-bottom: 4px; }}
  .subtitle {{ color: var(--subtle); font-size: 0.9em; margin-top: 0; }}
  .summary {{ display: flex; gap: 16px; flex-wrap: wrap; margin: 20px 0; }}
  .card {{ background: var(--card-bg); border-radius: 8px; padding: 16px 20px;
           flex: 1; min-width: 120px; box-shadow: 0 1px 3px var(--border); }}
  .card .num {{ font-size: 2em; font-weight: 700; line-height: 1.2; }}
  .card .label {{ font-size: 0.85em; color: var(--subtle); }}
  .card.green .num {{ color: #2e7d32; }}
  .card.red .num {{ color: #c62828; }}
  .card.blue .num {{ color: #1565c0; }}
  h2 {{ font-size: 1.2em; margin: 28px 0 8px; }}
  table {{ width: 100%; border-collapse: collapse; background: var(--table-bg);
           border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px var(--border);
           margin: 8px 0 16px; }}
  th, td {{ text-align: left; padding: 8px 12px; font-size: 0.9em; }}
  th {{ background: var(--th-bg); font-weight: 600; }}
  tr:nth-child(even) {{ background: var(--table-row); }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px;
            font-size: 0.8em; font-weight: 600; }}
  .badge.ok {{ background: #e8f5e9; color: #2e7d32; }}
  .badge.fail {{ background: #fbe9e7; color: #c62828; }}
  .badge.warn {{ background: #fff8e1; color: #f57f17; }}
  .sev {{ display: inline-block; padding: 1px 6px; border-radius: 3px;
          font-size: 0.75em; font-weight: 600; }}
  .sev.low {{ background: #e8f5e9; color: #2e7d32; }}
  .sev.medium {{ background: #fff8e1; color: #f57f17; }}
  .sev.high {{ background: #fbe9e7; color: #c62828; }}
  .sev.critical {{ background: #fce4ec; color: #b71c1c; font-weight: 700; }}
  .pass-bar {{ width: 100px; height: 8px; background: var(--th-bg);
               border-radius: 4px; overflow: hidden;
               display: inline-block; vertical-align: middle; }}
  .pass-bar-fill {{ height: 100%; border-radius: 4px; }}
  code {{ background: var(--code-bg); padding: 1px 4px; border-radius: 3px;
          font-size: 0.9em; word-break: break-all; }}
  .verdict {{ font-size: 1.1em; font-weight: 700; padding: 8px 16px;
              border-radius: 6px; display: inline-block; margin: 16px 0; }}
  .verdict.pass {{ background: #e8f5e9; color: #2e7d32; }}
  .verdict.fail {{ background: #fbe9e7; color: #c62828; }}
  /* Drill-down: <details>/<summary> per probe */
  .probe-detail {{ margin: 12px 0; background: var(--card-bg);
                   border-radius: 8px; box-shadow: 0 1px 3px var(--border); }}
  .probe-detail > summary {{ padding: 12px 16px; cursor: pointer;
                              font-size: 0.95em; user-select: none;
                              border-bottom: 1px solid var(--border); }}
  .probe-detail > summary:hover {{ background: var(--table-row); }}
  .probe-detail[open] > summary {{ border-bottom: 1px solid var(--border); }}
  .probe-detail table {{ box-shadow: none; border-radius: 0 0 8px 8px; }}
  .probe-link {{ color: inherit; text-decoration: none; border-bottom: 1px dotted var(--subtle); }}
  .probe-link:hover {{ border-bottom-color: var(--fg); }}
  .kv {{ display: inline-block; margin-right: 8px; font-size: 0.85em; color: var(--subtle); }}
  .kv b {{ color: var(--fg); font-weight: 600; }}
  footer {{ margin-top: 32px; font-size: 0.8em; color: var(--subtle); text-align: center; }}
</style>
</head>
<body{body_class}>
<h1>cascade-scan — Security Evaluation Report</h1>
<p class="subtitle">
  Score: {result.score:.1f}/100 |
  Grade: {scorer_summary['grade']} |
  Probes: {result.passed_probes}/{result.total_probes} passed |
  Vectors: {result.blocked_vectors}/{result.total_vectors} blocked
</p>

<div class="verdict {'pass' if result.passed else 'fail'}">
  {'PASS' if result.passed else 'FAIL'}: Security score {'≥' if result.passed else '<'} 70
</div>

<div class="summary">
  {cards_html}
</div>

<h2>Probe Results</h2>
<table>
<thead><tr><th>Result</th><th>Probe</th><th>Severity</th><th>Blocked</th><th>Rate</th><th>Bar</th></tr></thead>
<tbody>
  {probes_rows}
</tbody>
</table>

<h2>Score Breakdown</h2>
<table>
<thead><tr><th>Probe</th><th>Pass Rate</th><th>Weight</th><th>Contribution</th></tr></thead>
<tbody>
"""
    for bd in scorer_summary["breakdown"]:
        html += f"<tr><td>{bd['probe']}</td><td>{bd['pass_rate']*100:.0f}%</td><td>{bd['weight']:.1f}x</td><td>{bd['contribution']:.1f}</td></tr>"

    html += f"""
</tbody>
</table>

<h2>Probe Detail</h2>
{details_html}

<footer>cascade-scan — Generated at {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")} UTC</footer>
</body>
</html>"""

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(html, encoding="utf-8")

    return html


# ── internal helpers ─────────────────────────────────────────────────


def _grade_color(grade: str) -> str:
    colors = {
        "A+": "#1b5e20",
        "A": "#2e7d32",
        "B+": "#f57f17",
        "B": "#ef6c00",
        "C": "#e65100",
        "D": "#c62828",
        "F": "#b71c1c",
    }
    return colors.get(grade, "#666")


def _pass_badge(passed: bool) -> str:
    if passed:
        return '<span class="badge ok">PASS</span>'
    return '<span class="badge fail">FAIL</span>'


def _pass_bar(rate: float) -> str:
    pct = rate * 100
    color = "#2e7d32" if pct >= 80 else "#f57f17" if pct >= 50 else "#c62828"
    return (
        f'<span class="pass-bar">'
        f'<span class="pass-bar-fill" style="width:{pct}%;background:{color}"></span>'
        f'</span>'
    )


def _escape(text: str) -> str:
    """Minimal HTML escaping."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
