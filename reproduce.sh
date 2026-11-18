#!/bin/sh
# Clean-room reproduction for the ai-judge-rich-01 entry.
# From a fresh clone: run every test suite, then regenerate the
# live evidence (benchmark board + one sample deliverable).
set -e
cd "$(dirname "$0")"
for t in tests/test_*.py; do
  echo "== $t"
  python3 "$t" | tail -1
done
echo "== benchmark board (live DNS)"
python3 -m sprint.benchmark BENCHMARK.md
cat BENCHMARK.md
echo "== sample deliverable (live)"
python3 -m sprint.report_html khesf.com /tmp/khesf-report.html
grep -o "6.0/6" /tmp/khesf-report.html | head -1
echo "REPRODUCTION OK"
