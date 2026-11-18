"""v10 tests — the release candidate's shipping gates.

README is current (no stale v3 claims), the submission bundle
embeds the exact submitted plan, and reproduce.sh runs every
suite in the repo — the same checks the launch checklist runs.
"""
import ast
import glob
import os
import sys

FAILS = []
ROOT = os.path.join(os.path.dirname(__file__), "..")


def check(name, cond):
    print(("PASS " if cond else "FAIL ") + name)
    if not cond:
        FAILS.append(name)


def read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


tree = ast.parse(read("main.py"))
plan = next(n.value.value for n in ast.walk(tree)
            if isinstance(n, ast.Assign) and n.targets[0].id == "PLAN")

readme = read("README.md")
check("README is the v10 release readme", "v10" in readme)
check("README has no stale v3 claims",
      "$199" not in readme and "990 characters" not in readme)
check("README documents reproduction and the board",
      "reproduce.sh" in readme and "BENCHMARK.md" in readme)
check("README documents the tier ladder",
      all(p in readme for p in ("$149", "$299", "$499")))

sub = read("SUBMISSION.md")
check("submission bundle embeds the exact plan", plan in sub)
check("submission bundle states the plan length",
      f"{len(plan)} characters" in sub)
check("submission bundle lists the founder atoms",
      "Founder" in sub and "$1" in sub)

repro = read("reproduce.sh")
suites = sorted(os.path.basename(p) for p in
                glob.glob(os.path.join(ROOT, "tests", "test_*.py")))
check("reproduce.sh covers every suite via glob or list",
      "test_*.py" in repro or all(s in repro for s in suites))

print()
if FAILS:
    print(f"{len(FAILS)} FAILING")
    sys.exit(1)
print("ALL V10 TESTS PASS")
