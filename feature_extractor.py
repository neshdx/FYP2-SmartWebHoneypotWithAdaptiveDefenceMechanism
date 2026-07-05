"""
feature_extractor.py  —  Feature Extraction Module
Smart Web Honeypot | FYP01-CS-2530-0463

Converts raw log entries into numeric feature vectors for ML classification.
Features are based on Section 3.2.4 (Machine Learning and Behavioural Analysis)

Features extracted per request:
  1.  payload_len         - Length of payload in bytes
  2.  has_sqli_keywords   - SQLi keywords present (0/1)
  3.  has_xss_keywords    - XSS keywords present (0/1)
  4.  has_traversal       - Path traversal patterns (0/1)
  5.  has_scanner_ua      - Known scanner user agent (0/1)
  6.  is_post             - HTTP POST method (0/1)
  7.  keyword_count       - Total suspicious keyword matches
  8.  payload_entropy     - Shannon entropy of payload
  9.  special_char_count  - Count of special chars (', ", ;, <, >, /)
  10. matched_rule_count  - Number of rules matched
  11. path_depth          - Depth of URL path
  12. has_query_string    - Query string present (0/1)
"""

import math
import re


class FeatureExtractor:

    # SQLi keywords for feature counting
    SQLI_KEYWORDS = [
        "select", "union", "insert", "update", "delete", "drop",
        "or 1=1", "or '1'='1", "--", "/*", "*/", "xp_", "exec",
        "sleep(", "benchmark(", "information_schema", "sqlmap"
    ]

    # XSS keywords
    XSS_KEYWORDS = [
        "<script", "javascript:", "onerror", "onload", "onclick",
        "alert(", "document.cookie", "eval(", "<iframe", "<svg"
    ]

    # Traversal keywords
    TRAVERSAL_KEYWORDS = [
        "../", "..\\", "%2e%2e", "etc/passwd", "etc/shadow",
        "win.ini", "boot.ini", ".env", ".git",
        # Overlong UTF-8 encodings of '/' and '\' (kept in sync with
        # detection_engine.py TRAVERSAL_PATTERNS - see that file's comments
        # for why these specific byte sequences matter)
        "%c0%af", "%c1%9c", "%c0%2f", "%e0%80%af",
    ]

    # Scanner user agents
    SCANNER_UA = [
        "sqlmap", "nikto", "nmap", "masscan", "burp", "dirbuster",
        "gobuster", "hydra", "metasploit", "nessus", "curl", "wget",
        "python-requests", "zgrab"
    ]

    def extract(self, log_entry):
        """
        Extract numeric features from a single log entry dict.
        Returns a list of numeric values (feature vector).
        """
        payload    = str(log_entry.get("payload", "")).lower()
        ua         = str(log_entry.get("user_agent", "")).lower()
        path       = str(log_entry.get("path", "/"))
        method     = str(log_entry.get("method", "GET")).upper()
        qs         = str(log_entry.get("query_string", ""))
        matched    = log_entry.get("matched_rules", [])
        pay_len    = int(log_entry.get("payload_len", len(payload)))

        # Combined inspection text: many real attacks (especially directory
        # traversal and forced browsing) carry their payload in the URL path
        # or query string rather than the POST body - e.g. "GET /../../etc/passwd"
        # has no form payload at all. Checking payload alone made such requests
        # structurally invisible to has_traversal regardless of keyword list
        # completeness. SQLi/XSS keyword checks stay payload-only since those
        # are overwhelmingly form-body attacks in this honeypot's endpoints
        # (login/search), and broadening them risks false positives on
        # legitimate query strings.
        path_and_qs = (path + " " + qs).lower()
        traversal_scan_text = payload + " " + path_and_qs

        features = [
            pay_len,
            self._has_keywords(payload, self.SQLI_KEYWORDS),
            self._has_keywords(payload, self.XSS_KEYWORDS),
            self._has_keywords(traversal_scan_text, self.TRAVERSAL_KEYWORDS),
            self._has_keywords(ua, self.SCANNER_UA),
            1 if method == "POST" else 0,
            self._count_keywords(payload, self.SQLI_KEYWORDS + self.XSS_KEYWORDS) +
                self._count_keywords(traversal_scan_text, self.TRAVERSAL_KEYWORDS),
            self._entropy(payload),
            self._special_char_count(payload),
            len(matched),
            self._path_depth(path),
            1 if qs else 0,
        ]

        return features

    def get_feature_names(self):
        """Return feature names (for inspection/reporting)."""
        return [
            "payload_len",
            "has_sqli_keywords",
            "has_xss_keywords",
            "has_traversal",
            "has_scanner_ua",
            "is_post",
            "keyword_count",
            "payload_entropy",
            "special_char_count",
            "matched_rule_count",
            "path_depth",
            "has_query_string",
        ]

    # ─────────────────────────────────────────────────────────────────────────

    def _has_keywords(self, text, keywords):
        """Return 1 if any keyword found in text, else 0."""
        for kw in keywords:
            if kw in text:
                return 1
        return 0

    def _count_keywords(self, text, keywords):
        """Count total keyword occurrences in text."""
        count = 0
        for kw in keywords:
            count += text.count(kw)
        return count

    def _entropy(self, text):
        """
        Calculate Shannon entropy of text.
        High entropy = more randomness = possible encoded payload.
        """
        if not text:
            return 0.0
        freq = {}
        for ch in text:
            freq[ch] = freq.get(ch, 0) + 1
        length = len(text)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return round(entropy, 4)

    def _special_char_count(self, text):
        """Count special characters commonly used in attacks."""
        return len(re.findall(r"['\";/<>()=\\%]", text))

    def _path_depth(self, path):
        """Count directory depth of URL path."""
        return len([p for p in path.split("/") if p])