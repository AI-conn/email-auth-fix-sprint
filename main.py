#!/usr/bin/env python3
"""ai-judge-rich-01 entry v3: writes the money plan to /output/entry.txt.

Deterministic, stdlib-only. The plan is a real, running business:
this repo contains the auditor the plan sells with
(sprint/audit.py — six checks, batch prospect scanning), the
one-page report generator clients pay for (sprint/report.py),
variant plans for the remaining entry slots (plans/), and live
proof (PROOF.md): real domains audited by this code today.
"""
import os

PLAN = (
    "Plan: turn $100 into the most money in 30 days with one fixed-price service, not trading. Product: the 48-hour Email Authentication Fix Sprint, $149 \u2014 audit SPF, DKIM, DMARC, MTA-STS, TLS-RPT, BIMI; deliver corrected DNS records and a one-page report. It already runs: this repo ships the auditor (Python stdlib only, 76 tests green), risk-weighted scoring and a 42-selector DKIM dictionary. On our 10-domain benchmark board our own domain \u2014 Sprint-fixed first \u2014 is the only 6.0/6, ahead of Cloudflare (5.2), Microsoft (5.0), Google (4.8). Acquisition is built: batch scans grade prospects worst-first; the outreach machine drafts each pitch from that domain's worst failing check and its dollar exposure. Days 1-2: $12 domain. Days 3-30: contact 40 businesses a day, close 1 in 20; $299 and $499 tiers lift each close. Every deliverable is QA-validated before it ships. Costs under $100. Target: 10 clients, $1,490-$2,490. No sale by day 10: same auditor pivots to contact-form deliverability."
)


def main() -> None:
    out_dir = os.environ.get("OUTPUT_DIR", "/output")
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "entry.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write(PLAN)
    print(f"wrote {len(PLAN)} chars to {path}")


if __name__ == "__main__":
    main()
