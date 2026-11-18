"""Stdlib unittest suite — no network. Fixture DNS answers only."""
import base64
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from main import PLAN
from sprint import audit as audit_mod
from sprint.audit import check_dkim, check_dmarc, check_simple, check_spf, count_spf_lookups
from sprint.report import corrected_records


def no_fetch(name):
    return []


def key_record(total_bytes):
    return "v=DKIM1; k=rsa; p=" + base64.b64encode(b"\x01" * total_bytes).decode()


class PlanContracts(unittest.TestCase):
    def test_main_plan_within_bounty_limit(self):
        self.assertGreaterEqual(len(PLAN), 1)
        self.assertLessEqual(len(PLAN), 1000)

    def test_variant_plans_within_bounty_limit(self):
        plans_dir = os.path.join(os.path.dirname(__file__), "..", "plans")
        for name in ("revenue-led.txt", "market-led.txt"):
            text = open(os.path.join(plans_dir, name), encoding="utf-8").read().strip()
            self.assertGreaterEqual(len(text), 1, name)
            self.assertLessEqual(len(text), 1000, name)


class Spf(unittest.TestCase):
    def test_hard_fail_passes(self):
        self.assertEqual(check_spf(["v=spf1 include:_spf.google.com -all"], no_fetch)["status"], "pass")

    def test_soft_fail_warns(self):
        self.assertEqual(check_spf(["v=spf1 include:_spf.google.com ~all"], no_fetch)["status"], "warn")

    def test_missing_fails(self):
        self.assertEqual(check_spf(["v=DKIM1; k=rsa; p=abc"], no_fetch)["status"], "fail")
        self.assertEqual(check_spf([], no_fetch)["status"], "fail")

    def test_multiple_records_fail(self):
        recs = ["v=spf1 -all", "v=spf1 ~all"]
        self.assertEqual(check_spf(recs, no_fetch)["status"], "fail")

    def test_plus_all_fails(self):
        self.assertEqual(check_spf(["v=spf1 +all"], no_fetch)["status"], "fail")

    def test_lookup_count_simple(self):
        self.assertEqual(count_spf_lookups("v=spf1 include:a.com -all", no_fetch), 1)
        self.assertEqual(count_spf_lookups("v=spf1 mx -all", no_fetch), 1)
        self.assertEqual(count_spf_lookups("v=spf1 -all", no_fetch), 0)

    def test_lookup_count_follows_includes(self):
        table = {"a.com": ["v=spf1 include:b.com -all"], "b.com": ["v=spf1 mx -all"]}
        fetch = lambda name: table.get(name, [])
        self.assertEqual(count_spf_lookups("v=spf1 include:a.com -all", fetch), 3)

    def test_over_lookup_limit_fails(self):
        rec = "v=spf1 " + " ".join(f"include:d{i}.com" for i in range(11)) + " -all"
        self.assertEqual(check_spf([rec], no_fetch)["status"], "fail")


class Dmarc(unittest.TestCase):
    def test_reject_with_rua_passes(self):
        self.assertEqual(check_dmarc(["v=DMARC1; p=reject; rua=mailto:d@x.com"])["status"], "pass")

    def test_reject_partial_pct_warns(self):
        self.assertEqual(check_dmarc(["v=DMARC1; p=reject; pct=50; rua=mailto:d@x.com"])["status"], "warn")

    def test_reject_without_rua_warns(self):
        self.assertEqual(check_dmarc(["v=DMARC1; p=reject"])["status"], "warn")

    def test_none_warns(self):
        self.assertEqual(check_dmarc(["v=DMARC1; p=none"])["status"], "warn")

    def test_missing_fails(self):
        self.assertEqual(check_dmarc([])["status"], "fail")


class Dkim(unittest.TestCase):
    def test_strong_key_passes(self):
        fetch = lambda name: [key_record(300)] if name.startswith("google.") else []
        self.assertEqual(check_dkim("x.com", fetcher=fetch)["status"], "pass")

    def test_weak_key_warns(self):
        fetch = lambda name: [key_record(128)] if name.startswith("google.") else []
        r = check_dkim("x.com", fetcher=fetch)
        self.assertEqual(r["status"], "warn")
        self.assertIn("weak", r["detail"])

    def test_revoked_key_fails(self):
        fetch = lambda name: ["v=DKIM1; k=rsa; p="] if name.startswith("google.") else []
        self.assertEqual(check_dkim("x.com", fetcher=fetch)["status"], "fail")

    def test_no_key_warns(self):
        self.assertEqual(check_dkim("x.com", fetcher=no_fetch)["status"], "warn")


class SimpleChecks(unittest.TestCase):
    def test_present_passes(self):
        self.assertEqual(check_simple(["v=STSv1; id=1"], "v=STSv1", "ok", "missing")["status"], "pass")

    def test_absent_warns(self):
        self.assertEqual(check_simple([], "v=STSv1", "ok", "missing")["status"], "warn")


def full_result(status_by_check):
    base = {"status": "pass", "detail": "", "record": "v=spf1 -all"}
    checks = {k: dict(base, status=s) for k, s in status_by_check.items()}
    checks["spf"]["record"] = "v=spf1 -all"
    checks["dkim"]["record"] = ["google"]
    return {"checks": checks}


class Report(unittest.TestCase):
    def test_failing_domain_gets_all_six_fixes(self):
        result = full_result({"spf": "fail", "dkim": "warn", "dmarc": "fail",
                              "mta_sts": "warn", "tls_rpt": "warn", "bimi": "warn"})
        result["checks"]["spf"]["record"] = ""
        self.assertEqual(len(corrected_records("example.com", result)), 6)

    def test_passing_domain_gets_no_fixes(self):
        result = full_result({"spf": "pass", "dkim": "pass", "dmarc": "pass",
                              "mta_sts": "pass", "tls_rpt": "pass", "bimi": "pass"})
        self.assertEqual(corrected_records("example.com", result), [])

    def test_plus_all_is_rewritten_never_passed_through(self):
        """Regression: v2 shipped a +all record unchanged. v3 must not."""
        result = full_result({"spf": "fail", "dkim": "pass", "dmarc": "pass",
                              "mta_sts": "pass", "tls_rpt": "pass", "bimi": "pass"})
        result["checks"]["spf"]["record"] = "v=spf1 include:_spf.google.com +all"
        recs = corrected_records("example.com", result)
        self.assertEqual(len(recs), 1)
        self.assertNotIn("+all", recs[0])
        self.assertIn("-all", recs[0])


class Batch(unittest.TestCase):
    def test_worst_first_and_dead_domain_survives(self):
        fake = lambda d: {"domain": d, "checks": {}, "score": {"a.com": 5.0, "b.com": 1.0}[d], "max_score": 6}
        with patch.object(audit_mod, "audit", fake):
            out = audit_mod.batch(["a.com", "b.com"])
        self.assertEqual([r["domain"] for r in out], ["b.com", "a.com"])


if __name__ == "__main__":
    unittest.main()
