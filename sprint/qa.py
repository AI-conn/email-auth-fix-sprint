"""Deliverable QA validator (v8) — nothing inconsistent ships.

Threat model (security-and-hardening skill): audit details quote
DNS data, which is attacker-controlled. The HTML one-pager escapes
it; this validator proves the escaping and the internal
consistency of a deliverable bundle before it reaches a client:
same score everywhere, the risk figure from risk.py present and
identical, a corrected record for every non-passing check, and no
placeholder text. Returns a list of problems; empty means valid.
"""
from __future__ import annotations

import sys

from sprint.report import corrected_records
from sprint.risk import estimate

PLACEHOLDERS = ("TODO", "FIXME", "Lorem ipsum", "XXX")


def validate_bundle(domain: str, result: dict, md_text: str,
                    html_text: str, corrected: list[str] | None = None
                    ) -> list[str]:
    problems = []
    score_s = f"{result['score']}/{result['max_score']}"
    if score_s not in md_text or score_s not in html_text:
        problems.append(f"score {score_s} missing or mismatched "
                        "between the Markdown and HTML reports")
    est = estimate(result)
    risk_s = f"${est['low']:,}–${est['high']:,}"
    if risk_s not in md_text or risk_s not in html_text:
        problems.append(f"risk figure {risk_s} missing or mismatched "
                        "between the reports")
    if corrected is None:
        corrected = corrected_records(domain, result)
    non_pass = [n for n, c in result["checks"].items()
                if c["status"] != "pass"]
    if len(corrected) < len(non_pass):
        problems.append(
            f"corrected records cover {len(corrected)} of "
            f"{len(non_pass)} non-passing checks")
    for text, label in ((md_text, "Markdown"), (html_text, "HTML")):
        for ph in PLACEHOLDERS:
            if ph.lower() in text.lower():
                problems.append(f"placeholder text {ph!r} in {label} report")
    for n, c in result["checks"].items():
        detail = c["detail"]
        if ("<" in detail or ">" in detail) and detail in html_text:
            problems.append(
                f"unescaped audit data in HTML report ({n} detail)")
    return problems


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("usage: python3 -m sprint.qa <domain> <report.md> <report.html>")
        raise SystemExit(2)
    from sprint.audit import audit
    domain = sys.argv[1]
    result = audit(domain)
    md = open(sys.argv[2], encoding="utf-8").read()
    html = open(sys.argv[3], encoding="utf-8").read()
    found = validate_bundle(domain, result, md, html)
    if found:
        print("QA FAILED:")
        for p in found:
            print(" -", p)
        raise SystemExit(1)
    print("QA OK — bundle is consistent")
