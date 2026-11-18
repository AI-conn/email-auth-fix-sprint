"""v7 tests — written first (TDD red phase).

Evidence discipline: the benchmark board renderer, the ADR
record of the transport decision, and the reproduction script.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from sprint import benchmark  # noqa: E402

FAILS = []
ROOT = os.path.join(os.path.dirname(__file__), "..")


def check(name, cond):
    print(("PASS " if cond else "FAIL ") + name)
    if not cond:
        FAILS.append(name)


def canned(domain, score):
    checks = {n: {"status": "pass", "detail": "", "record": ""}
              for n in ("spf", "dkim", "dmarc", "mta_sts",
                        "tls_rpt", "bimi")}
    return {"domain": domain, "checks": checks, "score": score,
            "max_score": 6}


results = [canned(f"d{i}.example", float(i)) for i in range(10)]
md = benchmark.render_board(results)
check("board renders a markdown table with all 10 domains",
      md.count(".example") == 10 and "| Domain |" in md)
check("board is worst-first", md.index("d0.example") < md.index("d9.example"))
check("board names the standing 10-domain list",
      len(benchmark.BOARD) == 10 and "khesf.com" in benchmark.BOARD)

adr = os.path.join(ROOT, "docs", "adr", "0001-dns-transport.md")
check("ADR for the DNS transport decision exists",
      os.path.exists(adr))
if os.path.exists(adr):
    text = open(adr, encoding="utf-8").read()
    check("ADR records the three transport defects",
      all(w in text for w in ("512", "REFUSED", "truncat")))
    check("ADR records the decision and an alternative",
      "Decision" in text and "lternative" in text)

repro = os.path.join(ROOT, "reproduce.sh")
check("reproduce.sh exists and is executable",
      os.path.exists(repro) and os.access(repro, os.X_OK))

print()
if FAILS:
    print(f"{len(FAILS)} FAILING")
    sys.exit(1)
print("ALL V7 TESTS PASS")
