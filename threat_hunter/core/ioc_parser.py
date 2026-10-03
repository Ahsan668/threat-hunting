import re
from typing import Optional, Dict
from enum import Enum


class IOCType(str, Enum):
    """Indicator of Compromise types"""
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    MD5_HASH = "md5"
    SHA1_HASH = "sha1"
    SHA256_HASH = "sha256"
    UNKNOWN = "unknown"


class IOCParser:
    """Parse and identify IOC types"""
    
    IPV4_PATTERN = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    IPV6_PATTERN = r'^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4})$'
    DOMAIN_PATTERN = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    URL_PATTERN = r'^https?://[^\s/$.?#].[^\s]*$'
    EMAIL_PATTERN = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    MD5_PATTERN = r'^[a-fA-F0-9]{32}$'
    SHA1_PATTERN = r'^[a-fA-F0-9]{40}$'
    SHA256_PATTERN = r'^[a-fA-F0-9]{64}$'
    
    @staticmethod
    def detect_ioc_type(value: str):
        """Detect the type of IOC from its value"""
        value = value.strip()
        
        if re.match(IOCParser.URL_PATTERN, value):
            return IOCType.URL
        
        if re.match(IOCParser.EMAIL_PATTERN, value):
            return IOCType.EMAIL
        
        if re.match(IOCParser.IPV4_PATTERN, value):
            return IOCType.IPV4
        
        if re.match(IOCParser.IPV6_PATTERN, value):
            return IOCType.IPV6
        
        if re.match(IOCParser.SHA256_PATTERN, value):
            return IOCType.SHA256_HASH
        
        if re.match(IOCParser.SHA1_PATTERN, value):
            return IOCType.SHA1_HASH
        
        if re.match(IOCParser.MD5_PATTERN, value):
            return IOCType.MD5_HASH
        
        if re.match(IOCParser.DOMAIN_PATTERN, value):
            return IOCType.DOMAIN
        
        return IOCType.UNKNOWN
    
    @staticmethod
    def parse_ioc(value: str):
        """Parse IOC and return structured data"""
        ioc_type = IOCParser.detect_ioc_type(value)
        
        return {
            "value": value.strip(),
            "type": ioc_type.value,
            "detected": ioc_type != IOCType.UNKNOWN
        }
