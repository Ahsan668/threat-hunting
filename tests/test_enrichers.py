import unittest
from threat_hunter.enrichers.virustotal import VirusTotalEnricher
from threat_hunter.enrichers.abuseipdb import AbuseIPDBEnricher

class TestVT(unittest.TestCase):
    def test_hash(self):
        e = VirusTotalEnricher(api_key=None)
        r = e.enrich_hash("abc123")
        self.assertEqual(r["status"], "no_api_key")
    def test_domain(self):
        e = VirusTotalEnricher(api_key=None)
        r = e.enrich_domain("test.com")
        self.assertEqual(r["status"], "no_api_key")
    def test_ip(self):
        e = VirusTotalEnricher(api_key=None)
        r = e.enrich_ip("8.8.8.8")
        self.assertEqual(r["status"], "no_api_key")

class TestAbuse(unittest.TestCase):
    def test_ip(self):
        e = AbuseIPDBEnricher(api_key=None)
        r = e.enrich_ip("8.8.8.8")
        self.assertEqual(r["status"], "no_api_key")
    def test_ipv6(self):
        e = AbuseIPDBEnricher(api_key=None)
        r = e.enrich_ip("2001:db8::1")
        self.assertEqual(r["status"], "no_api_key")
    def test_struct(self):
        e = AbuseIPDBEnricher(api_key=None)
        r = e.enrich_ip("1.1.1.1")
        self.assertIn("value", r)
if __name__ == "__main__":
    unittest.main()
