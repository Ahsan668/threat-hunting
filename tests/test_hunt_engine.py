import unittest
from threat_hunter.core.hunt_engine import HuntEngine

class TestHuntEngine(unittest.TestCase):
    def setUp(self):
        self.engine = HuntEngine()
    def test_ipv4(self):
        r = self.engine.hunt("192.168.247.129", siem="splunk")
        self.assertEqual(r["ioc_type"], "ipv4")
    def test_domain(self):
        r = self.engine.hunt("polaris.fr", siem="splunk")
        self.assertEqual(r["ioc_type"], "domain")
    def test_url(self):
        r = self.engine.hunt("https://malware.com/payload", siem="elk")
        self.assertEqual(r["ioc_type"], "url")
    def test_unknown(self):
        r = self.engine.hunt("randomtext123xyz")
        self.assertEqual(r["status"], "Unknown")
if __name__ == "__main__":
    unittest.main()
