"""Benchmark board (v7) — the standing 10-domain evidence board.

Same ten domains every version, scored by the current auditor,
worst first. The board is the anti-inflation device: a checker
change that quietly raises every score shows up here immediately,
next to the previous version's committed BENCHMARK.md.
"""
from __future__ import annotations

import sys
from datetime import date

from sprint.audit import batch

BOARD = [
    "khesf.com", "suhush.com", "gudega.com", "google.com",
    "microsoft.com", "apple.com", "amazon.com", "github.com",
    "cloudflare.com", "wikipedia.org",
]

MARKS = {"pass": "✓", "warn": "!", "fail": "✗"}


def render_board(results: list[dict]) -> str:
    rows = sorted(results, key=lambda r: r["score"])
    lines = [
        "| Domain | Score | SPF | DKIM | DMARC | STS | RPT | BIMI |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        cells = []
        for n in ("spf", "dkim", "dmarc", "mta_sts", "tls_rpt", "bimi"):
            c = r["checks"].get(n)
            cells.append(MARKS[c["status"]] if c else "?")
        lines.append(
            f"| {r['domain']} | {r['score']}/{r['max_score']} | "
            + " | ".join(cells) + " |")
    return "\n".join(lines)


def main() -> str:
    results = batch(BOARD)
    return (f"# Benchmark board — {date.today().isoformat()}\n\n"
            f"Scored by the current auditor over the standing "
            f"10-domain board, worst first.\n\n"
            + render_board(results) + "\n")


if __name__ == "__main__":
    out = main()
    if len(sys.argv) == 2:
        with open(sys.argv[1], "w", encoding="utf-8") as f:
            f.write(out)
        print(f"wrote {sys.argv[1]}")
    else:
        print(out)
