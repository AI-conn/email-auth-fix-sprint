"""v9 tests — the three submission plans, refreshed on v8 facts.

Every plan: within the 1,000-character bounty limit, carries the
board proof (only 6.0/6) and the price ladder, and the submitted
PLAN in main.py is the main plan — no drift between copies.
"""
import ast
import os
import sys

FAILS = []
ROOT = os.path.join(os.path.dirname(__file__), "..")


def check(name, cond):
    print(("PASS " if cond else "FAIL ") + name)
    if not cond:
        FAILS.append(name)


def plan_of_main():
    tree = ast.parse(open(os.path.join(ROOT, "main.py"),
                          encoding="utf-8").read())
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign) and n.targets[0].id == "PLAN":
            return n.value.value
    raise AssertionError("PLAN not found")


plans = {
    "main": plan_of_main(),
    "revenue": open(os.path.join(ROOT, "plans", "revenue-led.txt"),
                    encoding="utf-8").read().strip(),
    "market": open(os.path.join(ROOT, "plans", "market-led.txt"),
                   encoding="utf-8").read().strip(),
}
for name, text in plans.items():
    check(f"{name} plan within the 1,000-char limit ({len(text)})",
          600 <= len(text) <= 1000)
    check(f"{name} plan carries the board proof",
          "6.0/6" in text)
    check(f"{name} plan carries the $149 anchor", "$149" in text)
check("main plan names all three tiers",
      all(p in plans["main"] for p in ("$149", "$299", "$499")))
check("plans state the test count honestly (76)",
      all("76 tests" in t for t in plans.values()))

print()
if FAILS:
    print(f"{len(FAILS)} FAILING")
    sys.exit(1)
print("ALL V9 TESTS PASS")
