"""v4 tests — written first (TDD red phase), against the real v3 API.

Covers: SPF flattening (include chains expanded to terminal
mechanisms), DMARC alignment reporting, the 40+ DKIM selector
dictionary, and risk-weighted scoring in audit().
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sprint"))
import audit as A  # noqa: E402

FAILS = []


def check(name, cond):
    print(("PASS " if cond else "FAIL ") + name)
    if not cond:
        FAILS.append(name)


ZONE = {
    "ex.com": ["v=spf1 include:_spf.ex.com ip4:192.0.2.5 -all"],
    "_spf.ex.com": ["v=spf1 include:_spf2.ex.com a mx -all"],
    "_spf2.ex.com": ["v=spf1 ip4:198.51.100.0/24 -all"],
    "loop.com": ["v=spf1 include:loop.com -all"],
}


def fake_fetch(name):
    return ZONE.get(name, [])


# --- SPF flattening -------------------------------------------------------
terms, lookups, notes = A.flatten_spf(ZONE["ex.com"][0], fetcher=fake_fetch)
check("flatten expands nested includes to terminal ip terms",
      "ip4:198.51.100.0/24" in terms and "ip4:192.0.2.5" in terms)
check("flatten counts lookups recursively (2 includes + a + mx = 4)",
      lookups == 4)
check("flatten keeps the terminal -all", "-all" in terms)

terms2, _, notes2 = A.flatten_spf(ZONE["loop.com"][0], fetcher=fake_fetch)
check("flatten survives an include loop with a note",
      len(notes2) > 0)

r = A.check_spf(ZONE["ex.com"], fetcher=fake_fetch)
check("spf detail reports the flattened mechanism count",
      r["status"] == "pass" and "flattens to" in r["detail"])

# --- DMARC alignment -------------------------------------------------------
r = A.check_dmarc(["v=DMARC1; p=reject; aspf=s; adkim=s; "
                   "rua=mailto:r@ex.com"])
check("dmarc detail reports strict alignment",
      r["status"] == "pass" and "alignment" in r["detail"]
      and "strict" in r["detail"])
r = A.check_dmarc(["v=DMARC1; p=reject; rua=mailto:r@ex.com"])
check("dmarc detail defaults to relaxed alignment",
      r["status"] == "pass" and "relaxed" in r["detail"])

# --- selector dictionary ---------------------------------------------------
check("dkim selector dictionary covers 40+ providers",
      len(A.COMMON_SELECTORS) >= 40)

# --- risk-weighted scoring ---------------------------------------------------
def zone_fetch(zone):
    return lambda name: zone.get(name, [])


core_only = {
    "a.com": ["v=spf1 -all"],
    "_dmarc.a.com": ["v=DMARC1; p=reject; rua=mailto:r@a.com"],
}
# spf pass 1.0 + dmarc pass 2.0 + dkim warn .75 + sts/rpt/bimi warn .25 ea
check("weighted score: core-only domain = 4.5 of 6",
      A.audit("a.com", fetcher=zone_fetch(core_only))["score"] == 4.5)

full = {
    "b.com": ["v=spf1 -all"],
    "google._domainkey.b.com": ["v=DKIM1; k=rsa; p=" + "A" * 400],
    "_dmarc.b.com": ["v=DMARC1; p=reject; rua=mailto:r@b.com"],
    "_mta-sts.b.com": ["v=STSv1; id=1"],
    "_smtp._tls.b.com": ["v=TLSRPTv1; rua=mailto:r@b.com"],
    "default._bimi.b.com": ["v=BIMI1; l=https://b.com/logo.svg;"],
}
check("weighted score: full pass still totals 6.0",
      A.audit("b.com", fetcher=zone_fetch(full))["score"] == 6.0)

# --- native DNS parser -----------------------------------------------------
import struct as _struct

def _canned_response():
    # header: id, flags 0x8180, qd=1, an=1; question x.com TXT;
    # answer via name pointer 0xC00C, TXT rdata one string "hello"
    hdr = _struct.pack(">HHHHHH", 1, 0x8180, 1, 1, 0, 0)
    q = b"\x01x\x03com\x00" + _struct.pack(">HH", 16, 1)
    rdata = b"\x05hello"
    ans = b"\xc0\x0c" + _struct.pack(">HHIH", 16, 1, 300, len(rdata)) + rdata
    return hdr + q + ans


txts, cname = A._parse_txt_answers(_canned_response())
check("native DNS parser extracts TXT from a canned response",
      txts == ["hello"] and cname is None)

print()
if FAILS:
    print(f"{len(FAILS)} FAILING")
    sys.exit(1)
print("ALL V4 TESTS PASS")
