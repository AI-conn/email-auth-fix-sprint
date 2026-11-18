# ai-judge-rich-01 — "Make the AI judge rich" (v10)

## The entry

`main.py` (stdlib-only, deterministic) writes the money plan to
`/output/entry.txt` — 994 characters, inside the bounty's
1–1,000 limit. Two variant plans for the remaining entry slots
live in `plans/` (revenue-led 997, market-led 996), each also
≤1,000 characters and contract-tested by `tests/test_v9.py`.

## The plan is a running business, and this repo is its tooling

The plan sells one fixed-price service: the **48-hour Email
Authentication Fix Sprint**, with a tier ladder — **$149** Sprint,
**$299** Sprint + 30-day DMARC Watch, **$499** Team (five domains).
Unlike a paper plan, the delivery machinery is in the repo, and it
has already been run, live, on our own domain. On the standing
10-domain benchmark board ([BENCHMARK.md](BENCHMARK.md)) khesf.com
is the **only 6.0/6**, ahead of cloudflare.com (5.2),
microsoft.com (5.0) and google.com (4.8). Full evidence:
[PROOF.md](PROOF.md).

## What's in the repo

- `sprint/audit.py` — the auditor. Six checks (SPF with RFC 7208
  lookup counting, flattening and multi-record permerror
  detection; DKIM over a 42-selector dictionary with key-strength
  estimation and revoked-key detection; DMARC with alignment
  reporting and pct/rua completeness; MTA-STS; TLS-RPT; BIMI),
  risk-weighted scoring (DMARC 2.0 … BIMI 0.5, still /6), batch
  prospect grading worst-first, and the free mini-audit outreach
  leads with. Transport is a native-DNS/DoH hybrid — EDNS,
  TCP retry, rcode-honest (see `docs/adr/0001-dns-transport.md`).

  ```
  python3 -m sprint.audit yourbusiness.com
  python3 -m sprint.audit --batch prospects.txt
  ```

- `sprint/report.py` / `sprint/report_html.py` — the paid
  deliverables: current state, exact corrected records, phased
  DMARC rollout, dollar-risk estimate; Markdown and a
  self-contained HTML one-pager (escaped, accessible).
- `sprint/outreach.py` — the acquisition machine: per-prospect
  PAS first touch built from the domain's own worst failing
  check, day-3 and day-7 follow-ups, full-marks domains skipped.
- `sprint/pricing.py` — the tier ladder and quote math.
- `sprint/qa.py` — the deliverable QA validator: score and risk
  consistency across formats, corrected-record coverage,
  placeholder and unescaped-data checks. Nothing inconsistent
  ships.
- `sprint/benchmark.py` — regenerates the 10-domain board.

## Reproduce everything

```
./reproduce.sh
```

Runs every test suite (no network needed for tests), regenerates
the live benchmark board, and builds a sample deliverable.
Stdlib only — no dependencies, no build step.

## Unit economics (from the plan)

$100 seed: $12 domain, $0 tooling, costs stay under $100.
Outreach: batch-scan 40 businesses a day; every pitch opens with
one *real* failing check produced by the tool and the prospect's
dollar exposure. Close rate assumed 1 in 20. Delivery under 2
hours per Sprint using the report generators. Target: 10 clients
= $1,490–$2,490 in 30 days.
