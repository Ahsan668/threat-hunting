import requests
from typing import Dict

class SplunkHunter:
    def __init__(self, host='localhost', port=8089, username='admin', password='', demo_mode=True):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.demo_mode = demo_mode
        self.url = f"https://{host}:{port}"

    def hunt_ipv4(self, ioc: str) -> Dict:
        if self.demo_mode:
            mock_data = {
                '192.168.247.129': 487,
                '24.8.40.184': 342,
                '8.8.8.8': 12,
            }
            hits = mock_data.get(ioc, 0)
            return {'ioc': ioc, 'ioc_type': 'ipv4', 'siem': 'splunk', 'hits': hits}
        return {'ioc': ioc, 'ioc_type': 'ipv4', 'siem': 'splunk', 'hits': 0}

    def hunt_domain(self, ioc: str) -> Dict:
        if self.demo_mode:
            mock_data = {
                'polaris.fr': 234,
                'frothly.com': 156,
            }
            hits = mock_data.get(ioc, 0)
            return {'ioc': ioc, 'ioc_type': 'domain', 'siem': 'splunk', 'hits': hits}
        return {'ioc': ioc, 'ioc_type': 'domain', 'siem': 'splunk', 'hits': 0}

    def hunt_hash(self, ioc: str) -> Dict:
        if self.demo_mode:
            return {'ioc': ioc, 'ioc_type': 'sha256', 'siem': 'splunk', 'hits': 128}
        return {'ioc': ioc, 'ioc_type': 'sha256', 'siem': 'splunk', 'hits': 0}

    def hunt_url(self, ioc: str) -> Dict:
        if self.demo_mode:
            return {'ioc': ioc, 'ioc_type': 'url', 'siem': 'splunk', 'hits': 89}
        return {'ioc': ioc, 'ioc_type': 'url', 'siem': 'splunk', 'hits': 0}

    def hunt_email(self, ioc: str) -> Dict:
        if self.demo_mode:
            mock_data = {
                'attacker@frothly.com': 67,
                'admin@frothly.com': 45,
            }
            hits = mock_data.get(ioc, 0)
            return {'ioc': ioc, 'ioc_type': 'email', 'siem': 'splunk', 'hits': hits}
        return {'ioc': ioc, 'ioc_type': 'email', 'siem': 'splunk', 'hits': 0}
