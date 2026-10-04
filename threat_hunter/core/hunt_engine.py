from typing import Dict
from threat_hunter.core.ioc_parser import IOCParser
from threat_hunter.integrations.splunk_api import SplunkHunter
from threat_hunter.integrations.elk_api import ELKHunter

class HuntEngine:
    def __init__(self, splunk_config: Dict = None, elk_config: Dict = None):
        self.splunk = SplunkHunter(**(splunk_config or {"host": "localhost", "port": 8089, "username": "admin"}))
        self.elk = ELKHunter(**(elk_config or {"host": "localhost", "port": 9200, "username": "elastic"}))
    
    def hunt(self, ioc: str, siem: str = "splunk") -> Dict:
        parsed = IOCParser.parse_ioc(ioc)
        if not parsed["detected"]:
            return {"ioc": ioc, "status": "Unknown"}
        ioc_type = parsed["type"]
        return self._hunt_splunk(ioc, ioc_type) if siem == "splunk" else self._hunt_elk(ioc, ioc_type)
    
    def _hunt_splunk(self, ioc: str, ioc_type: str) -> Dict:
        if ioc_type in ["ipv4", "ipv6"]:
            return self.splunk.hunt_ipv4(ioc)
        elif ioc_type == "domain":
            return self.splunk.hunt_domain(ioc)
        elif ioc_type == "url":
            return self.splunk.hunt_url(ioc)
        elif ioc_type == "email":
            return self.splunk.hunt_email(ioc)
        else:
            return self.splunk.hunt_hash(ioc, ioc_type)
    
    def _hunt_elk(self, ioc: str, ioc_type: str) -> Dict:
        if ioc_type in ["ipv4", "ipv6"]:
            return self.elk.hunt_ipv4(ioc)
        elif ioc_type == "domain":
            return self.elk.hunt_domain(ioc)
        elif ioc_type == "url":
            return self.elk.hunt_url(ioc)
        elif ioc_type == "email":
            return self.elk.hunt_email(ioc)
        else:
            return self.elk.hunt_hash(ioc, ioc_type)