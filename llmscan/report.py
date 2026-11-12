"""Turns scan results into JSON, a console table, or a standalone HTML report."""
import html
import json

SEV_COLOR = {"Critical": "#b42318", "High": "#c4320a", "Medium": "#b54708", "Low": "#475467"}
STATUS_COLOR = {"FAIL": "#b42318", "PASS": "#067647", "ERROR": "#475467"}


def to_json(result: dict) -> str:
    return json.dumps(result, indent=2)


def to_console(result: dict) -> str:
    s = result["summary"]
    lines = [
        f"Target: {result['target']}   Scanned: {result['scanned_at']}",
        f"Probes: {s['total']}  FAIL: {s['failed']}  PASS: {s['passed']}  ERROR: {s['errors']}  Risk score: {s['risk_score']}/100",
        "-" * 96,
    ]
    for f in result["findings"]:
        lines.append(f"[{f['status']:5}] {f['probe_id']:7} {f['severity']:8} {f['owasp'][:34]:34} {f['name']}")
        if f["status"] != "PASS":
            lines.append(f"         -> {f['evidence']}")
    return "\n".join(lines)


def to_html(result: dict) -> str:
    s = result["summary"]
    e = html.escape
    rows = []
    for f in result["findings"]:
        rows.append(f"""
<details class="f">
  <summary><span class="st" style="background:{STATUS_COLOR[f['status']]}">{f['status']}</span>
    <b>{e(f['probe_id'])}</b> {e(f['name'])}
    <span class="sev" style="color:{SEV_COLOR[f['severity']]}">{f['severity']}</span>
    <span class="tag">{e(f['owasp'])}</span><span class="tag">ATLAS {e(f['atlas'])}</span></summary>
  <p><b>Evidence:</b> {e(f['evidence'])}</p>
  <p><b>Attack prompt</b></p><pre>{e(f['prompt'])}</pre>
  <p><b>Model reply</b> (shown as text, never rendered)</p><pre>{e(f['response'])}</pre>
  <p><b>Remediation:</b> {e(f['remediation'])}</p>
</details>""")
    sev = " ".join(f"<span class='pill'>{k}: {v}</span>" for k, v in s["by_severity"].items())
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>LLM Security Scan Report</title>
<style>
body{{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:0;background:#f8f9fb;color:#1d2939}}
.wrap{{max-width:960px;margin:0 auto;padding:24px 16px}}
h1{{margin:0 0 4px}} .meta{{color:#667085;margin-bottom:16px}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:16px}}
.card{{background:#fff;border:1px solid #e4e7ec;border-radius:10px;padding:12px}}
.card b{{display:block;font-size:26px}}
.pill{{display:inline-block;background:#fff;border:1px solid #e4e7ec;border-radius:20px;padding:2px 10px;margin:2px}}
.f{{background:#fff;border:1px solid #e4e7ec;border-radius:10px;margin:8px 0;padding:10px 14px}}
.f summary{{cursor:pointer;line-height:1.9}}
.st{{color:#fff;border-radius:6px;padding:2px 8px;font-size:12px;margin-right:6px}}
.sev{{font-weight:600;margin-left:6px}} .tag{{font-size:12px;color:#475467;background:#f2f4f7;border-radius:6px;padding:2px 6px;margin-left:6px}}
pre{{white-space:pre-wrap;word-break:break-word;background:#f2f4f7;padding:10px;border-radius:8px;max-height:260px;overflow:auto}}
</style></head><body><div class="wrap">
<h1>LLM Security Scan Report</h1>
<div class="meta">Target: <b>{e(result['target'])}</b> &middot; {e(result['scanned_at'])} &middot; OWASP Top 10 for LLM Applications</div>
<div class="cards">
 <div class="card">Risk score<b>{s['risk_score']}/100</b></div>
 <div class="card">Vulnerable (FAIL)<b style="color:#b42318">{s['failed']}</b></div>
 <div class="card">Defended (PASS)<b style="color:#067647">{s['passed']}</b></div>
 <div class="card">Errors<b>{s['errors']}</b></div>
</div>
<div>Failed by severity: {sev}</div>
{''.join(rows)}
</div></body></html>"""
