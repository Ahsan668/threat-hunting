import unittest
import json
from threat_hunter.generators.report_generator import ReportGenerator

class TestReport(unittest.TestCase):
    def setUp(self):
        self.g = ReportGenerator()
    def test_json(self):
        r = self.g.generate_json_report([], [])
        d = json.loads(r)
        self.assertIn("timestamp", d)
    def test_text(self):
        r = self.g.generate_text_report([], [])
        self.assertIn("THREAT HUNTING INCIDENT REPORT", r)
    def test_html(self):
        r = self.g.generate_html_report([], [])
        self.assertIn("<!DOCTYPE html>", r)
    def test_summary(self):
        s = self.g._summarize([], [])
        self.assertEqual(s["total_iocs"], 0)
    def test_empty(self):
        r = self.g.generate_json_report([], [])
        d = json.loads(r)
        self.assertEqual(len(d["hunt_results"]), 0)
    def test_no_enrich(self):
        h = [{"ioc": "1.1.1.1", "ioc_type": "ipv4", "siem": "splunk", "hits": 1}]
        r = self.g.generate_json_report(h, [])
        d = json.loads(r)
        self.assertEqual(len(d["enrichment_data"]), 0)
if __name__ == "__main__":
    unittest.main()
