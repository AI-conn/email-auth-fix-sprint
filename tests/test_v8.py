"""v8 tests — written first (TDD red phase).

Pricing tiers with delivery checklists, and the QA validator
that keeps an inconsistent or placeholder deliverable from ever
reaching a client.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from sprint import pricing, qa  # noqa: E402

FAILS = []


def check(name, cond):
    print(("PASS " if cond else "FAIL ") + name)
    if not cond:
        FAILS.append(name)


# --- pricing ------------------------------------------------------------------
tiers = pricing.TIERS
check("three tiers at $149 / $299 / $499",
      [t["price"] for t in tiers] == [149, 299, 499])
check("every tier carries a delivery checklist",
      all(len(t["includes"]) >= 4 for t in tiers))
check("includes grow monotonically (each tier ⊇ the last)",
      all(set(tiers[i]["includes"]) <= set(tiers[i + 1]["includes"])
          for i in range(len(tiers) - 1)))
q = pricing.quote("Sprint", domains=1)
check("quote: base tier, one domain = $149", q["total"] == 149)
q = pricing.quote("Sprint", domains=3)
check("quote: extra domains at $99 each", q["total"] == 149 + 2 * 99)
q = pricing.quote("Team", domains=5)
check("quote: Team covers five domains at $499", q["total"] == 499)

# --- QA validator ---------------------------------------------------------------
def result(score=4.5):
    checks = {
        "spf": {"status": "pass", "detail": "ok", "record": "v=spf1 -all"},
        "dkim": {"status": "warn", "detail": "weak <key> detail",
                 "record": []},
        "dmarc": {"status": "fail", "detail": "no dmarc", "record": ""},
        "mta_sts": {"status": "warn", "detail": "none", "record": ""},
        "tls_rpt": {"status": "warn", "detail": "none", "record": ""},
        "bimi": {"status": "warn", "detail": "none", "record": ""},
    }
    return {"domain": "ex.com", "checks": checks, "score": score,
            "max_score": 6}


# risk for 4.5/6: 25% missing -> $2,000-$7,500 (see risk.py)
MD = ("# Report for ex.com\nScore: 4.5/6\n"
      "Estimated annual exposure: $2,000–$7,500\n")
HTML = ("<p class=\"score\">4.5/6</p><p>$2,000–$7,500</p>"
        "<td>weak &lt;key&gt; detail</td>")

r = result()
check("validator accepts a consistent bundle",
      qa.validate_bundle("ex.com", r, MD, HTML) == [])
check("validator catches a score mismatch",
      any("score" in p for p in qa.validate_bundle(
          "ex.com", r, MD.replace("4.5/6", "5.0/6"), HTML)))
check("validator catches a missing risk figure",
      any("risk" in p for p in qa.validate_bundle(
          "ex.com", r, MD.replace("$2,000–$7,500", ""), HTML)))
check("validator catches placeholder text",
      any("placeholder" in p for p in qa.validate_bundle(
          "ex.com", r, MD + "\nTODO: fill in\n", HTML)))
check("validator catches unescaped audit data in HTML",
      any("unescaped" in p for p in qa.validate_bundle(
          "ex.com", r, MD, HTML.replace("&lt;key&gt;", "<key>"))))
check("validator catches a failed check with no corrected record",
      any("corrected" in p for p in qa.validate_bundle(
          "ex.com", r, MD, HTML, corrected=[])))

print()
if FAILS:
    print(f"{len(FAILS)} FAILING")
    sys.exit(1)
print("ALL V8 TESTS PASS")
