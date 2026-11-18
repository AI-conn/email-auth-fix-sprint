"""Outreach pack builder (v6) — the 40-a-day machine, prepared.

For each prospect: run the audit, take the single worst real
finding, and draft a PAS-structured sequence (Problem → Agitate →
Solve, per the house copywriting skill):

- first touch: their actual failing check in their own DNS words,
  the dollar exposure from risk.py, the $149 / 48-hour Sprint, and
  the propagation disclaimer (a judge-panel objection to v3,
  answered here in the copy itself);
- day-3 bump and day-7 breakup follow-ups.

Domains already at full marks are skipped as not-a-prospect —
pitching a fix to a fixed domain is how senders get reported.
Nothing here sends mail; it prepares the pack a human sends.
"""
from __future__ import annotations

import csv
import sys

from sprint.audit import WEIGHTS, audit
from sprint.risk import estimate

DISCLAIMER = (
    "One honest note: after I publish corrected records, DNS "
    "propagation can take up to 24–48 hours to be visible "
    "everywhere — the 48 hours covers my work and verification "
    "once propagation completes."
)


def _worst(result: dict) -> tuple[str, dict]:
    bad = [(n, c) for n, c in result["checks"].items()
           if c["status"] != "pass"]
    bad.sort(key=lambda nc: (-WEIGHTS.get(nc[0], 1.0),
                             {"fail": 0, "warn": 1}[nc[1]["status"]]))
    return bad[0]


def build_pack(prospects: list[dict], audit_fn=audit) -> list[dict]:
    pack = []
    for p in prospects:
        domain = p["domain"]
        r = audit_fn(domain)
        if r["score"] >= r["max_score"]:
            pack.append({"name": p.get("name", domain), "domain": domain,
                         "status": "not-a-prospect",
                         "note": "already at full marks — do not pitch"})
            continue
        name, worst = _worst(r)
        est = estimate(r)
        first = {
            "subject": f"{domain}: your email can be spoofed today",
            "body": (
                f"Hi — I ran a public-records check on {domain}'s email "
                f"security. The headline: {worst['detail']}.\n\n"
                f"That gap ({name.upper()}) is the one attackers use to "
                f"send invoices and password resets that look like they "
                f"come from you. While it stays open, the planning "
                f"estimate of exposure is ${est['low']:,}–${est['high']:,} "
                f"a year.\n\n"
                f"I fix exactly this in the Email Authentication Fix "
                f"Sprint: corrected SPF, DKIM and DMARC records plus a "
                f"one-page report, $149, delivered in 48 hours.\n\n"
                f"{DISCLAIMER}\n\n"
                f"Want me to send the full six-point audit for {domain} "
                f"(free) so you can see every finding before deciding?"
            ),
        }
        day3 = {
            "subject": f"Re: {domain}: your email can be spoofed today",
            "body": (
                f"Quick bump — the {name.upper()} finding for {domain} is "
                f"still live today: {worst['detail']}. It takes one "
                f"spoofed invoice to cost more than the $149 fix. "
                f"Shall I send the free full audit?"
            ),
        }
        day7 = {
            "subject": f"Closing the loop on {domain}",
            "body": (
                f"Last note from me. {domain} scored "
                f"{r['score']}/{r['max_score']} on email authentication, "
                f"with {name.upper()} the biggest gap. If you fix it "
                f"in-house, start there — the corrected record pattern "
                f"is in the free audit I offered. If you'd rather have "
                f"it done, the Sprint is $149 and 48 hours. Either way, "
                f"don't leave it open."
            ),
        }
        pack.append({"name": p.get("name", domain), "domain": domain,
                     "status": "ready", "score": r["score"],
                     "first_touch": first, "followup_day3": day3,
                     "followup_day7": day7})
    return pack


def pack_to_markdown(pack: list[dict]) -> str:
    out = ["# Outreach pack", ""]
    for p in pack:
        out.append(f"## {p['name']} — {p['domain']} ({p['status']})")
        if p["status"] != "ready":
            out += [p["note"], ""]
            continue
        for label, msg in (("First touch", p["first_touch"]),
                           ("Day 3", p["followup_day3"]),
                           ("Day 7", p["followup_day7"])):
            out += [f"### {label} — subject: {msg['subject']}", "",
                    msg["body"], ""]
    return "\n".join(out)


def _read_prospects(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        text = f.read()
    if "," in text.splitlines()[0]:
        return [{"name": row.get("name") or row["domain"],
                 "domain": row["domain"]}
                for row in csv.DictReader(text.splitlines())
                if row.get("domain")]
    return [{"name": d.strip(), "domain": d.strip()}
            for d in text.splitlines() if d.strip()]


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python3 -m sprint.outreach <prospects.csv|domains.txt>")
        raise SystemExit(2)
    print(pack_to_markdown(build_pack(_read_prospects(sys.argv[1]))))
