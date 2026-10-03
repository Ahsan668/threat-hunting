import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from threat_hunter.core.ioc_parser import IOCParser, IOCType


def test_ipv4_detection():
    """Test IPv4 detection"""
    result = IOCParser.parse_ioc("192.168.247.129")
    assert result["type"] == "ipv4"
    assert result["detected"] == True
    print("✅ IPv4 detection works")


def test_domain_detection():
    """Test domain detection"""
    result = IOCParser.parse_ioc("polaris.fr")
    assert result["type"] == "domain"
    assert result["detected"] == True
    print("✅ Domain detection works")


def test_url_detection():
    """Test URL detection"""
    result = IOCParser.parse_ioc("https://malware.com/payload")
    assert result["type"] == "url"
    assert result["detected"] == True
    print("✅ URL detection works")


def test_email_detection():
    """Test email detection"""
    result = IOCParser.parse_ioc("attacker@badguy.com")
    assert result["type"] == "email"
    assert result["detected"] == True
    print("✅ Email detection works")


def test_md5_detection():
    """Test MD5 hash detection"""
    result = IOCParser.parse_ioc("3c6cb8d1afc403d16eaf0b9d1afbe90f")
    assert result["type"] == "md5"
    assert result["detected"] == True
    print("✅ MD5 detection works")


def test_sha1_detection():
    """Test SHA1 hash detection"""
    result = IOCParser.parse_ioc("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3")
    assert result["type"] == "sha1"
    assert result["detected"] == True
    print("✅ SHA1 detection works")


def test_sha256_detection():
    """Test SHA256 hash detection"""
    result = IOCParser.parse_ioc("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert result["type"] == "sha256"
    assert result["detected"] == True
    print("✅ SHA256 detection works")


def test_unknown_detection():
    """Test unknown IOC type"""
    result = IOCParser.parse_ioc("randomtext123xyz")
    assert result["detected"] == False
    print("✅ Unknown type detection works")


def run_all_tests():
    """Run all tests"""
    print("\n" + "="*60)
    print("Running IOC Parser Tests".center(60))
    print("="*60 + "\n")
    
    try:
        test_ipv4_detection()
        test_domain_detection()
        test_url_detection()
        test_email_detection()
        test_md5_detection()
        test_sha1_detection()
        test_sha256_detection()
        test_unknown_detection()
        
        print("\n" + "="*60)
        print("All tests passed! ✅".center(60))
        print("="*60 + "\n")
        return True
    except AssertionError as e:
        print(f"\n❌ Test failed: {e}\n")
        return False


if __name__ == "__main__":
    run_all_tests()