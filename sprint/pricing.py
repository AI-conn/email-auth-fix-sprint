"""Pricing tiers (v8) — what the Sprint sells, and what each tier
must deliver before it counts as done. Checklists are cumulative:
every tier includes everything the cheaper one does.
"""
from __future__ import annotations

EXTRA_DOMAIN = 99

_SPRINT = [
    "Six-check audit (SPF, DKIM, DMARC, MTA-STS, TLS-RPT, BIMI)",
    "Corrected DNS records, ready to publish",
    "One-page report (Markdown + HTML one-pager)",
    "Phased DMARC rollout plan (monitor → quarantine → reject)",
    "Post-publish verification re-audit",
]
_WATCH = _SPRINT + [
    "30 days of DMARC aggregate-report monitoring",
    "Weekly exposure re-score with drift alerts",
    "DKIM key-rotation reminder at 12 months",
]
_TEAM = _WATCH + [
    "Up to 5 domains covered",
    "Subdomain (sp=) policy review",
    "Priority 24-hour turnaround",
    "Staff briefing note: what changed and why",
]

TIERS = [
    {"name": "Sprint", "price": 149, "domains": 1, "includes": _SPRINT},
    {"name": "Sprint + Watch", "price": 299, "domains": 1,
     "includes": _WATCH},
    {"name": "Team", "price": 499, "domains": 5, "includes": _TEAM},
]


def quote(tier_name: str, domains: int = 1) -> dict:
    for t in TIERS:
        if t["name"] == tier_name:
            extra = max(0, domains - t["domains"])
            return {"tier": t["name"], "domains": domains,
                    "extra_domains": extra,
                    "total": t["price"] + extra * EXTRA_DOMAIN}
    raise ValueError(f"unknown tier: {tier_name}")
