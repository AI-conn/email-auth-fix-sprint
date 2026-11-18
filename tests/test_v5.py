"""v5 tests — written first (TDD red phase).

Covers: the dollar-risk estimator (transparent math) and the HTML
one-pager (complete, self-contained, escaped, accessible labels).
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from sprint import report_html, risk  # noqa: E402

FAILS = []


def check(name, cond):
    print(("PASS " if cond else "FAIL ") + name)
    if not cond:
        FAILS.append(name)


def result(score, statuses):
    checks = {n: {"status": s, "detail": f"{n} detail", "record": ""}
              for n, s in statuses.items()}
    return {"domain": "ex.com", "checks": checks, "score": score,
            "max_score": 6}


ALL_PASS = {n: "pass" for n in
            ("spf", "dkim", "dmarc", "mta_sts", "tls_rpt", "bimi")}
ALL_FAIL = {n: "fail" for n in ALL_PASS}

# --- risk estimator ---------------------------------------------------------
est = risk.estimate(result(6.0, ALL_PASS))
check("risk: full pass means zero estimated exposure",
      est["low"] == 0 and est["high"] == 0 and est["drivers"] == [])

est = risk.estimate(result(0.0, ALL_FAIL))
check("risk: total failure reaches the full incident band",
      est["low"] == risk.INCIDENT_LOW and est["high"] == risk.INCIDENT_HIGH)

est = risk.estimate(result(4.5, {**ALL_PASS, "dmarc": "warn",
                                 "dkim": "warn", "mta_sts": "warn",
                                 "tls_rpt": "warn", "bimi": "warn"}))
check("risk: 25% missing = 25% of the band",
      est["low"] == risk.INCIDENT_LOW // 4
      and est["high"] == risk.INCIDENT_HIGH // 4)
check("risk: drivers name the worst gap first (dmarc heaviest)",
      est["drivers"][0] == "dmarc")

# --- HTML one-pager -----------------------------------------------------------
r = result(4.5, {**ALL_PASS, "dmarc": "warn"})
r["checks"]["dmarc"]["detail"] = "weak <script>alert(1)</script> detail"
html = report_html.render_html_from_result("ex.com", r)
check("html: standalone document", html.startswith("<!DOCTYPE html>"))
check("html: names the domain and the score",
      "ex.com" in html and "4.5/6" in html)
check("html: all six checks rendered",
      all(n.upper() in html for n in ALL_PASS))
check("html: audit details are escaped, never raw",
      "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html)
check("html: status shown as text, not color alone",
      "WARN" in html and "PASS" in html)
check("html: risk estimate printed with its basis",
      "$" in html and "estimate" in html.lower())
check("html: no external assets (single file deliverable)",
      "http://" not in html.replace("https://ex.com", "")
      and "<link" not in html and "<img" not in html)

print()
if FAILS:
    print(f"{len(FAILS)} FAILING")
    sys.exit(1)
print("ALL V5 TESTS PASS")
