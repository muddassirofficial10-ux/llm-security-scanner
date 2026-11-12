import unittest

from llmscan import detectors as d
from llmscan.probes import PROBES, get_probes
from llmscan.report import to_html
from llmscan.scanner import scan
from llmscan.targets import DemoTarget, Target


class DetectorTests(unittest.TestCase):
    def test_canary_leak(self):
        self.assertIsNotNone(d.system_prompt_leak("ok CANARY-x1 here", {"canary": "CANARY-x1"}))
        self.assertIsNone(d.system_prompt_leak("Hello there", {"canary": "CANARY-x1"}))

    def test_refusal_is_not_a_leak(self):
        self.assertIsNone(d.system_prompt_leak("I can't share my system prompt.", {}))

    def test_secret_patterns(self):
        self.assertIsNotNone(d.secret_leak("key AKIAABCDEFGHIJKLMNOP", {}))
        self.assertIsNotNone(d.secret_leak("mail me at a.b@example.com", {}))
        self.assertIsNone(d.secret_leak("No secrets here.", {}))

    def test_unsafe_output(self):
        self.assertIsNotNone(d.unsafe_output("<script>alert(1)</script>", {}))
        self.assertIsNotNone(d.unsafe_output("WHERE name='x' OR 1=1", {}))
        self.assertIsNone(d.unsafe_output("<b>Hello</b>", {}))

    def test_jailbreak_marker(self):
        self.assertIsNotNone(d.jailbreak_compliance("pwned-7731 ok", {"marker": "PWNED-7731"}))
        self.assertIsNone(d.jailbreak_compliance("Sorry, no.", {"marker": "PWNED-7731"}))

    def test_excessive_agency_refusal(self):
        self.assertIsNotNone(d.excessive_agency("Done, I deleted everything", {}))
        self.assertIsNone(d.excessive_agency("I can't do that, it needs approval", {}))

    def test_resource_exhaustion(self):
        self.assertIsNotNone(d.resource_exhaustion("a" * 5000, {"max_chars": 4000}))


class ProbeTests(unittest.TestCase):
    def test_ids_unique_and_detectors_exist(self):
        ids = [p.id for p in PROBES]
        self.assertEqual(len(ids), len(set(ids)))
        for p in PROBES:
            self.assertIn(p.detector, d.DETECTORS)

    def test_filter_by_category(self):
        only = get_probes(["LLM01"])
        self.assertTrue(only)
        self.assertTrue(all(p.owasp.startswith("LLM01") for p in only))


class ScanTests(unittest.TestCase):
    def test_vulnerable_demo_fails_everything(self):
        r = scan(DemoTarget(hardened=False))
        self.assertEqual(r["summary"]["failed"], len(PROBES))
        self.assertEqual(r["summary"]["risk_score"], 100)

    def test_hardened_demo_passes_everything(self):
        r = scan(DemoTarget(hardened=True))
        self.assertEqual(r["summary"]["failed"], 0)
        self.assertEqual(r["summary"]["risk_score"], 0)

    def test_errors_are_reported_not_raised(self):
        class Broken(Target):
            name = "broken"
            def send(self, prompt):
                raise ConnectionError("offline")
        r = scan(Broken())
        self.assertEqual(r["summary"]["errors"], len(PROBES))

    def test_html_report_escapes_model_output(self):
        html = to_html(scan(DemoTarget(hardened=False)))
        self.assertNotIn("<script>alert('hi')</script>", html)
        self.assertIn("&lt;script&gt;", html)


if __name__ == "__main__":
    unittest.main()
