"""One-page Sprint report generator v3.

Takes an audit result (sprint.audit.audit) and emits the client
deliverable: current state across all six checks, the exact
corrected DNS records to publish, and the phased DMARC rollout
(monitor -> quarantine -> reject) so enforcement never breaks
legitimate mail.

v3 fixes a v2 defect: a record ending in +all was passed through
unchanged, leaving the client authorizing the whole internet.
v3 rewrites +all to -all like every other non-enforced ending.
"""
from __future__ import annotations

import sys

from sprint.audit import audit


def corrected_records(domain: str, result: dict) -> list[str]:
    out = []
    checks = result["checks"]
    spf = checks["spf"]
    if spf["status"] != "pass":
        base = spf["record"] or "v=spf1 include:_spf.google.com"
        for ending in ("~all", "?all", "+all"):
            base = base.replace(ending, "-all")
        if "-all" not in base:
            base += " -all"
        out.append(f"TXT  {domain}            {base}")
    if checks["dkim"]["status"] != "pass":
        out.append(
            f"TXT  <selector>._domainkey.{domain}  v=DKIM1; k=rsa; p=<2048-bit public key from your mail provider>"
            "  (enable DKIM signing in Google Workspace / Microsoft 365 first, then publish the key it gives you;"
            " rotate any key under 2048-bit)"
        )
    if checks["dmarc"]["status"] != "pass":
        out.append(
            f"TXT  _dmarc.{domain}  v=DMARC1; p=none; rua=mailto:dmarc@{domain}; pct=100"
            "  (phase 1: monitor 2 weeks, then p=quarantine pct=25, then p=reject)"
        )
    if checks["mta_sts"]["status"] != "pass":
        out.append(
            f"TXT  _mta-sts.{domain}  v=STSv1; id={20260101000000}  (plus the policy file at"
            " https://mta-sts." + domain + "/.well-known/mta-sts.txt, mode: enforce)"
        )
    if checks["tls_rpt"]["status"] != "pass":
        out.append(f"TXT  _smtp._tls.{domain}  v=TLSRPTv1; rua=mailto:tlsrpt@{domain}")
    if checks["bimi"]["status"] != "pass":
        out.append(
            f"TXT  default._bimi.{domain}  v=BIMI1; l=https://{domain}/bimi.svg; a=https://{domain}/bimi-vmc.pem"
            "  (publish last — BIMI only displays once DMARC is at p=reject)"
        )
    return out


def render(domain: str) -> str:
    r = audit(domain)
    from sprint.risk import estimate
    est = estimate(r)
    lines = [
        f"# Email Authentication Fix Sprint — Report for {domain}",
        "",
        f"Score: {r['score']}/{r['max_score']}",
        f"Estimated annual exposure while gaps stay open: ${est['low']:,}–${est['high']:,}"
        " (planning estimate — un-passing weighted share × $8k–$30k incident band)",
        "",
        "## Current state",
    ]
    for name, c in r["checks"].items():
        lines.append(f"- **{name.upper()}** ({c['status']}): {c['detail']}")
    lines += ["", "## Publish these corrected records"]
    recs = corrected_records(domain, r)
    lines += [f"- `{x}`" for x in recs] or ["- Nothing to change — all checks pass."]
    lines += [
        "",
        "## Rollout",
        "1. Publish the records above. 2. Monitor DMARC aggregate reports for 14 days.",
        "3. Raise DMARC p=none -> quarantine (pct=25) -> reject. 4. Publish BIMI last.",
        "5. Re-run this audit to verify full marks.",
        "",
        "Delivered under the 48-hour Email Authentication Fix Sprint ($149).",
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python3 -m sprint.report <domain>")
        raise SystemExit(2)
    print(render(sys.argv[1]))
