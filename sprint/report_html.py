"""HTML one-pager generator (v5) — the client deliverable.

Same content as report.py, as a single self-contained HTML file a
client can open, print, or forward: no external assets, semantic
landmarks, status always shown as text (never color alone), and
every audit string HTML-escaped — audit details quote DNS data,
which is attacker-controlled input and is never rendered raw.
"""
from __future__ import annotations

import html
import sys

from sprint.audit import audit
from sprint.report import corrected_records
from sprint.risk import estimate

CSS = """
body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;margin:2rem auto;max-width:52rem;padding:0 1rem;color:#1a1a1a;line-height:1.5}
h1{font-size:1.6rem;margin-bottom:.2rem} h2{font-size:1.15rem;margin-top:2rem}
.score{font-size:2rem;font-weight:700}
table{border-collapse:collapse;width:100%}
th,td{border:1px solid #b9bec4;padding:.45rem .6rem;text-align:left;vertical-align:top}
th{background:#eef1f4}
.st{font-weight:700;white-space:nowrap}
.pass{color:#0b6e2f}.warn{color:#8a5a00}.fail{color:#b00020}
code,pre{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.86rem}
pre{background:#f4f5f6;padding:.7rem;overflow-x:auto;white-space:pre-wrap}
.risk{background:#fdf6e3;border:1px solid #d9c98a;padding:.8rem 1rem}
footer{margin-top:2.5rem;color:#444;font-size:.9rem}
@media print{.risk{border-color:#999}}
"""


def render_html_from_result(domain: str, result: dict) -> str:
    esc = html.escape
    est = estimate(result)
    rows = []
    for name, c in result["checks"].items():
        rows.append(
            f'<tr><th scope="row">{esc(name.upper())}</th>'
            f'<td class="st {esc(c["status"])}">{esc(c["status"].upper())}</td>'
            f"<td>{esc(c['detail'])}</td></tr>"
        )
    recs = corrected_records(domain, result)
    rec_block = (
        "<pre>" + "\n".join(esc(r) for r in recs) + "</pre>"
        if recs else "<p>Nothing to change — all checks pass.</p>"
    )
    drivers = ", ".join(esc(d.upper()) for d in est["drivers"]) or "none"
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Email Authentication Report — {esc(domain)}</title>
<style>{CSS}</style>
</head>
<body>
<header>
<h1>Email Authentication Fix Sprint — Report for {esc(domain)}</h1>
<p class="score">{result['score']}/{result['max_score']}</p>
</header>
<main>
<section aria-labelledby="state">
<h2 id="state">Current state</h2>
<table>
<tr><th scope="col">Check</th><th scope="col">Status</th><th scope="col">Finding</th></tr>
{''.join(rows)}
</table>
</section>
<section aria-labelledby="risk">
<h2 id="risk">What the gaps cost</h2>
<div class="risk">
<p>Estimated annual exposure while these gaps stay open:
<strong>${est['low']:,}–${est['high']:,}</strong>.</p>
<p>This is a planning estimate: the un-passing weighted share of the
six checks applied to an $8,000–$30,000 small-business email-incident
band. Biggest drivers: {drivers}.</p>
</div>
</section>
<section aria-labelledby="fix">
<h2 id="fix">Publish these corrected records</h2>
{rec_block}
</section>
<section aria-labelledby="rollout">
<h2 id="rollout">Rollout</h2>
<ol>
<li>Publish the records above.</li>
<li>Monitor DMARC aggregate reports for 14 days.</li>
<li>Raise DMARC p=none → quarantine (pct=25) → reject.</li>
<li>Publish BIMI last — it only displays once DMARC is enforced.</li>
<li>Re-run the audit to verify full marks.</li>
</ol>
</section>
</main>
<footer>Delivered under the 48-hour Email Authentication Fix Sprint ($149).
Propagation note: DNS changes can take up to 24–48 hours to be visible
everywhere; verification runs after propagation.</footer>
</body>
</html>"""


def render_html(domain: str) -> str:
    return render_html_from_result(domain, audit(domain))


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        print("usage: python3 -m sprint.report_html <domain> [out.html]")
        raise SystemExit(2)
    out = render_html(sys.argv[1])
    if len(sys.argv) == 3:
        with open(sys.argv[2], "w", encoding="utf-8") as f:
            f.write(out)
        print(f"wrote {sys.argv[2]}")
    else:
        print(out)
