"""v6 tests — written first (TDD red phase).

The outreach pack: PAS-structured first touch built from the
prospect's own worst failing check, a dollar figure, the
propagation disclaimer, two follow-ups, and a hard skip for
domains that already score full marks.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from sprint import outreach  # noqa: E402

FAILS = []


def check(name, cond):
    print(("PASS " if cond else "FAIL ") + name)
    if not cond:
        FAILS.append(name)


def canned(domain):
    if domain == "clean.com":
        checks = {n: {"status": "pass", "detail": "ok", "record": ""}
                  for n in ("spf", "dkim", "dmarc", "mta_sts",
                            "tls_rpt", "bimi")}
        return {"domain": domain, "checks": checks, "score": 6.0,
                "max_score": 6}
    checks = {
        "spf": {"status": "warn", "detail": "SPF soft fail only",
                "record": "v=spf1 ~all"},
        "dkim": {"status": "warn", "detail": "No DKIM key found",
                 "record": []},
        "dmarc": {"status": "fail",
                  "detail": "No DMARC record — no policy, no spoofing reports",
                  "record": ""},
        "mta_sts": {"status": "warn", "detail": "No MTA-STS", "record": ""},
        "tls_rpt": {"status": "warn", "detail": "No TLS-RPT", "record": ""},
        "bimi": {"status": "warn", "detail": "No BIMI", "record": ""},
    }
    return {"domain": domain, "checks": checks, "score": 1.5,
            "max_score": 6}


pack = outreach.build_pack(
    [{"name": "Maui Bakery", "domain": "bakery.example"},
     {"name": "Clean Co", "domain": "clean.com"}],
    audit_fn=canned)

check("pack has one entry per prospect", len(pack) == 2)
weak = next(p for p in pack if p["domain"] == "bakery.example")
clean = next(p for p in pack if p["domain"] == "clean.com")

check("full-marks domain is skipped, not pitched",
      clean["status"] == "not-a-prospect" and "first_touch" not in clean)
check("first touch leads with the worst real finding (DMARC)",
      "DMARC" in weak["first_touch"]["body"]
      and "No DMARC record" in weak["first_touch"]["body"])
check("first touch carries the dollar exposure",
      "$" in weak["first_touch"]["body"])
check("problem comes before the price (PAS)",
      weak["first_touch"]["body"].index("DMARC")
      < weak["first_touch"]["body"].index("$149"))
check("48h promise carries the propagation disclaimer",
      "propagation" in weak["first_touch"]["body"].lower())
check("two follow-ups exist (day 3 bump, day 7 breakup)",
      "followup_day3" in weak and "followup_day7" in weak
      and len(weak["followup_day3"]["body"]) > 40
      and len(weak["followup_day7"]["body"]) > 40)
check("subject names the domain",
      "bakery.example" in weak["first_touch"]["subject"])

md = outreach.pack_to_markdown(pack)
check("markdown pack renders both prospects",
      "Maui Bakery" in md and "Clean Co" in md)

print()
if FAILS:
    print(f"{len(FAILS)} FAILING")
    sys.exit(1)
print("ALL V6 TESTS PASS")
