import requests
from typing import Dict, Optional
from threat_hunter.core.config import get_secret

class AbuseIPDBEnricher:
    """
    Query AbuseIPDB API for IP abuse reports.
    Supports: IPv4 and IPv6 addresses
    """
    
    BASE_URL = "https://api.abuseipdb.com/api/v2"
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or get_secret("ABUSEIPDB_API_KEY")
    
    def enrich_ip(self, ip: str) -> Dict:
        """Query AbuseIPDB for IP abuse reports"""
        if not self.api_key:
            return {"value": ip, "status": "no_api_key", "engine": "abuseipdb"}
        
        try:
            url = f"{self.BASE_URL}/check"
            headers = {
                "Key": self.api_key,
                "Accept": "application/json"
            }
            params = {
                "ipAddress": ip,
                "maxAgeInDays": 90,
                "verbose": ""
            }
            
            response = requests.get(url, headers=headers, params=params, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                abuse_data = data.get("data", {})
                return {
                    "value": ip,
                    "status": "found",
                    "engine": "abuseipdb",
                    "abuse_score": abuse_data.get("abuseConfidenceScore", 0),
                    "total_reports": abuse_data.get("totalReports", 0),
                    "is_whitelisted": abuse_data.get("isWhitelisted", False),
                    "isp": abuse_data.get("isp", "unknown"),
                    "country": abuse_data.get("countryCode", "unknown"),
                }
            elif response.status_code == 404:
                return {"value": ip, "status": "not_found", "engine": "abuseipdb"}
            else:
                return {"value": ip, "status": f"error_{response.status_code}", "engine": "abuseipdb"}
        except Exception as e:
            return {"value": ip, "status": f"error: {str(e)}", "engine": "abuseipdb"}