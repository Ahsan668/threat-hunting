import requests
from typing import Dict

class ELKHunter:
    def __init__(self, host='localhost', port=9200, username='elastic', password='', demo_mode=True):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.demo_mode = demo_mode
        self.url = f"http://{host}:{port}"

    def hunt_ipv4(self, ioc: str) -> Dict:
        if self.demo_mode:
            mock_data = {
                '192.168.247.129': 512,
                '24.8.40.184': 378,
                '8.8.8.8': 8,
            }
            hits = mock_data.get(ioc, 0)
            return {'ioc': ioc, 'ioc_type': 'ipv4', 'siem': 'elasticsearch', 'hits': hits}
        return {'ioc': ioc, 'ioc_type': 'ipv4', 'siem': 'elasticsearch', 'hits': 0}

    def hunt_domain(self, ioc: str) -> Dict:
        if self.demo_mode:
            mock_data = {
                'polaris.fr': 289,
                'frothly.com': 178,
            }
            hits = mock_data.get(ioc, 0)
            return {'ioc': ioc, 'ioc_type': 'domain', 'siem': 'elasticsearch', 'hits': hits}
        return {'ioc': ioc, 'ioc_type': 'domain', 'siem': 'elasticsearch', 'hits': 0}

    def hunt_hash(self, ioc: str) -> Dict:
        if self.demo_mode:
            return {'ioc': ioc, 'ioc_type': 'sha256', 'siem': 'elasticsearch', 'hits': 156}
        return {'ioc': ioc, 'ioc_type': 'sha256', 'siem': 'elasticsearch', 'hits': 0}

    def hunt_url(self, ioc: str) -> Dict:
        if self.demo_mode:
            return {'ioc': ioc, 'ioc_type': 'url', 'siem': 'elasticsearch', 'hits': 112}
        return {'ioc': ioc, 'ioc_type': 'url', 'siem': 'elasticsearch', 'hits': 0}

    def hunt_email(self, ioc: str) -> Dict:
        if self.demo_mode:
            mock_data = {
                'attacker@frothly.com': 89,
                'admin@frothly.com': 34,
            }
            hits = mock_data.get(ioc, 0)
            return {'ioc': ioc, 'ioc_type': 'email', 'siem': 'elasticsearch', 'hits': hits}
        return {'ioc': ioc, 'ioc_type': 'email', 'siem': 'elasticsearch', 'hits': 0}
