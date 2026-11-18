# ADR 0001 — DNS transport: native-first hybrid, rcode-honest

Status: accepted (v4, 2026-11-17). Recorded in v7 under the
documentation-and-adrs skill: decisions and their *why* live here,
not only in code comments.

## Context

v1–v3 resolved DNS exclusively over DNS-over-HTTPS (Cloudflare
dns-json). It worked, but cost ~2 s per query and throttled under
parallel load. v4's deeper checks (42 DKIM selectors, SPF
flattening) made query volume the bottleneck — and exposed three
defects that any transport must answer:

1. **512-byte truncation.** A real DKIM public key makes the TXT
   answer ~700 bytes. Plain UDP without EDNS returns that answer
   truncated with zero records: the key is *there* and the client
   sees nothing. (Found live: khesf.com's Proton key invisible to
   our own native client while `dig` saw it.)
2. **REFUSED read as "no record".** Under batch load, resolvers
   rate-limit with rcode 5 (REFUSED) and an empty answer section.
   A client that ignores rcode reports healthy domains as missing
   DKIM/DMARC — false findings against innocent prospects.
3. **Mismatched datagrams.** Under parallel load a gateway can
   deliver another query's response to a waiting socket; accepting
   it uncritically corrupts results nondeterministically.

## Decision

Native DNS first, DoH as fallback, in `sprint/audit.py`:

- UDP with an EDNS OPT record (4096-byte buffer); on the TC bit,
  retry over TCP. TCP is also the fallback where UDP is blocked.
- Response accepted only when its transaction id *and* question
  name match the query.
- rcode is honored: NXDOMAIN is a definitive empty; SERVFAIL and
  REFUSED raise, so `fetch_txt` backs off, retries once, then
  falls back to DoH. An error is never rendered as a finding.
- Fetches are paced through one semaphore; batch and selector
  probing use bounded thread pools sized under resolver limits.

## Alternatives considered

- **DoH-only (v3 status quo):** portable, but ~2 s/query, burst
  throttling, and a hard dependency on one provider's JSON API.
- **Shelling out to `dig`:** not stdlib, not portable, and parses
  human output — rejected.
- **dnspython:** a real dependency; the Sprint's promise is
  stdlib-only, runs anywhere Python runs — rejected.

## Consequences

Full audits complete in ~1–3 s per domain; the 10-domain board is
stable across repeated runs (three identical boards recorded for
v4). The auditor now works on networks where DoH is blocked, and
on networks where UDP is blocked, and says "lookup failed" instead
of inventing a finding when both fail.
