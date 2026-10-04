import unittest
from threat_hunter.core.ioc_parser import IOCParser

class TestIOCParser(unittest.TestCase):
    def test_ipv4(self):
        r = IOCParser.parse_ioc("192.168.247.129")
        self.assertEqual(r["type"], "ipv4")
    def test_domain(self):
        r = IOCParser.parse_ioc("polaris.fr")
        self.assertEqual(r["type"], "domain")
    def test_url(self):
        r = IOCParser.parse_ioc("https://malware.com/payload")
        self.assertEqual(r["type"], "url")
    def test_email(self):
        r = IOCParser.parse_ioc("attacker@badguy.com")
        self.assertEqual(r["type"], "email")
    def test_unknown(self):
        r = IOCParser.parse_ioc("randomtext123xyz")
        self.assertEqual(r["type"], "unknown")
if __name__ == "__main__":
    unittest.main()
