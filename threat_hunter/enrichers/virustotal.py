import requests
from typing import Dict, Optional
from threat_hunter.core.config import get_secret

class VirusTotalEnricher:
    """
    Query VirusTotal API for file/domain/IP reputation.
    Supports: files (by hash), domains, URLs, IPs
    """
    
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or get_secret("VIRUSTOTAL_API_KEY")
        self.headers = {"x-apikey": self.api_key} if self.api_key else {}
    
    def enrich_hash(self, hash_value: str) -> Dict:
        """Query VirusTotal for file hash reputation"""
        if not self.api_key:
            return {"value": hash_value, "status": "no_api_key", "engine": "virustotal"}
        
        try:
            url = f"{self.BASE_URL}/files/{hash_value}"
            response = requests.get(url, headers=self.headers, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                attrs = data.get("data", {}).get("attributes", {})
                return {
                    "value": hash_value,
                    "status": "found",
                    "engine": "virustotal",
                    "malicious_count": attrs.get("last_analysis_stats", {}).get("malicious", 0),
                    "suspicious_count": attrs.get("last_analysis_stats", {}).get("suspicious", 0),
                    "undetected_count": attrs.get("last_analysis_stats", {}).get("undetected", 0),
                }
            elif response.status_code == 404:
                return {"value": hash_value, "status": "not_found", "engine": "virustotal"}
            else:
                return {"value": hash_value, "status": f"error_{response.status_code}", "engine": "virustotal"}
        except Exception as e:
            return {"value": hash_value, "status": f"error: {str(e)}", "engine": "virustotal"}
    
    def enrich_domain(self, domain: str) -> Dict:
        """Query VirusTotal for domain reputation"""
        if not self.api_key:
            return {"value": domain, "status": "no_api_key", "engine": "virustotal"}
        
        try:
            url = f"{self.BASE_URL}/domains/{domain}"
            response = requests.get(url, headers=self.headers, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                attrs = data.get("data", {}).get("attributes", {})
                return {
                    "value": domain,
                    "status": "found",
                    "engine": "virustotal",
                    "malicious_count": attrs.get("last_analysis_stats", {}).get("malicious", 0),
                    "suspicious_count": attrs.get("last_analysis_stats", {}).get("suspicious", 0),
                    "categories": attrs.get("categories", {}),
                }
            elif response.status_code == 404:
                return {"value": domain, "status": "not_found", "engine": "virustotal"}
            else:
                return {"value": domain, "status": f"error_{response.status_code}", "engine": "virustotal"}
        except Exception as e:
            return {"value": domain, "status": f"error: {str(e)}", "engine": "virustotal"}
    
    def enrich_ip(self, ip: str) -> Dict:
        """Query VirusTotal for IP reputation"""
        if not self.api_key:
            return {"value": ip, "status": "no_api_key", "engine": "virustotal"}
        
        try:
            url = f"{self.BASE_URL}/ip_addresses/{ip}"
            response = requests.get(url, headers=self.headers, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                attrs = data.get("data", {}).get("attributes", {})
                return {
                    "value": ip,
                    "status": "found",
                    "engine": "virustotal",
                    "malicious_count": attrs.get("last_analysis_stats", {}).get("malicious", 0),
                    "suspicious_count": attrs.get("last_analysis_stats", {}).get("suspicious", 0),
                    "country": attrs.get("country", "unknown"),
                }
            elif response.status_code == 404:
                return {"value": ip, "status": "not_found", "engine": "virustotal"}
            else:
                return {"value": ip, "status": f"error_{response.status_code}", "engine": "virustotal"}
        except Exception as e:
            return {"value": ip, "status": f"error: {str(e)}", "engine": "virustotal"}