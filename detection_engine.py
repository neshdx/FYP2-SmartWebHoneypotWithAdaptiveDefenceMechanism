"""
detection_engine.py — Hybrid Detection Engine
Smart Web Honeypot | FYP01-CS-2530-0463
"""

import re
import time
from collections import defaultdict


class DetectionEngine:

    SQLI_PATTERNS = [
        r"(\bOR\b|\bAND\b)\s+[\'\"]?\d+[\'\"]?\s*=\s*[\'\"]?\d+[\'\"]?",
        r"--[+\-\s]*$",                                    # was --\s*$ : now also catches --+- / --- endings
        r"#\s*$",                                          # MySQL # comment terminator
        r";\s*(DROP|DELETE|INSERT|UPDATE|SELECT|CREATE|ALTER)",
        # UNION...SELECT, now matches /**/ inline-comment separators (sqlmap space2comment bypass)
        # as well as normal whitespace, e.g. "UNION/**/SELECT" or "UNION SELECT"
        r"UNION(\s|/\*.*?\*/)+(ALL(\s|/\*.*?\*/)+)?SELECT",
        r"'\s*OR\s*'",
        r"'\s*=\s*'",
        r"\bSLEEP\s*\(\d+\)",
        r"\bBENCHMARK\s*\(",
        r"xp_cmdshell",
        r"information_schema",
        r"0x[0-9a-fA-F]+",
        r"CHAR\s*\(\d+",
        r"sqlmap",
        r"havij",
        r"/\*.*?\*/",                                       # bare inline SQL comment used as space substitute
    ]

    XSS_PATTERNS = [
        r"<script[\s\S]*?>[\s\S]*?</script>",
        r"javascript\s*:",
        r"on\w+\s*=\s*['\"]",
        r"<img[^>]+src\s*=\s*['\"]?javascript",
        r"<iframe[\s\S]*?>",
        r"document\.cookie",
        r"document\.write\s*\(",
        r"eval\s*\(",
        r"alert\s*\(",
        r"prompt\s*\(",
        r"<svg[\s\S]*?on\w+",
        r"&#\d+;",
        r"%3Cscript",
        r"base64,",
        r"String\.fromCharCode",                            # common XSS filter-evasion technique
        r"fromCharCode\s*\(",
        r"<svg[^>]*/?>",                                    # bare svg tag (catches <svg/onload=...> without requiring 'on')
    ]

    TRAVERSAL_PATTERNS = [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e%2f",
        r"%252e%252e%252f",
        # Overlong UTF-8 encodings of '/' and '\' - classic IIS/Apache traversal bypass
        # (%c0%af decodes to '/', %c1%9c decodes to '\' on vulnerable decoders)
        r"%c0%af",
        r"%c1%9c",
        r"%c0%2f",
        r"%e0%80%af",
        r"etc/passwd",
        r"etc%c0%afpasswd",                                 # encoded variant seen directly in payload
        r"etc\\\\?shadow",
        r"win\.ini",
        r"boot\.ini",
        r"proc/self",
        r"/var/www",
        r"\.php$",
        r"\.(env|config|bak|sql|log)$",
        r"wp-admin",
        r"phpmyadmin",
        r"\.git/",
    ]

    SCANNER_UA_PATTERNS = [
        r"sqlmap", r"nikto", r"nmap", r"masscan",
        r"burpsuite", r"dirbuster", r"gobuster",
        r"hydra", r"metasploit", r"nessus", r"openvas",
        r"python-requests", r"curl/", r"wget/", r"zgrab",
    ]

    BRUTE_FORCE_THRESHOLD = 5
    BRUTE_FORCE_WINDOW = 60

    # Behavioural scanner detection - UA-independent. A real Nikto run was
    # found (20-min, 2000+ request scan) to fall through to NONE on the
    # large majority of requests, because Nikto does not send its
    # self-identifying UA string on every request (several of its own
    # plugins deliberately test with generic/no UA as an evasion check).
    # UA matching alone is therefore an insufficient signal for sustained
    # scanning activity - this adds a behavioural fallback: many distinct
    # 404-triggering paths from the same IP in a short window looks like
    # reconnaissance regardless of what UA string accompanies it.
    SCAN_RATE_THRESHOLD = 10   # distinct unknown paths from one IP...
    SCAN_RATE_WINDOW = 30      # ...within this many seconds

    def __init__(self):
        self._login_attempts = defaultdict(list)
        self._subnet_attacks = defaultdict(list)  # NEW: Track attacks per /24 subnet
        self._path_probe_history = defaultdict(list)  # NEW: (timestamp, path) per IP for behavioural scan detection

        self._sqli_re = [
            re.compile(p, re.IGNORECASE)
            for p in self.SQLI_PATTERNS
        ]

        self._xss_re = [
            re.compile(p, re.IGNORECASE)
            for p in self.XSS_PATTERNS
        ]

        self._traversal_re = [
            re.compile(p, re.IGNORECASE)
            for p in self.TRAVERSAL_PATTERNS
        ]

        self._scanner_re = [
            re.compile(p, re.IGNORECASE)
            for p in self.SCANNER_UA_PATTERNS
        ]

        self.ml_enabled = False
        
        try:
            from ml_model import MLModel
            from feature_extractor import FeatureExtractor
            
            
            self.ml_model = MLModel()
            self.extractor = FeatureExtractor()
            
            if self.ml_model.is_trained:
                self.ml_enabled = True
                print("[*] ML Detection Layer ACTIVE")
                
        except Exception as e:
            print("[!] ML Load Error:", e)

        # CVSS scorer — answers "how severe IS this attack type", computed
        # per-request using real signals (matched rules, encoding, path).
        # Kept as a SEPARATE concern from ML confidence — see the matrix
        # in _combine_severity_and_confidence() for how the two combine.
        from cvss_scorer import CVSSScorer
        self.cvss_scorer = CVSSScorer()

    def _threat_level_from_cvss_severity(self, cvss_severity: str) -> str:
        """
        Map CVSS severity band -> internal threat_level label used by the
        dashboard/logger. This is a label translation only — the actual
        severity number comes from CVSSScorer.score(), computed per-request.
        """
        return {
            "CRITICAL": "HIGH",
            "HIGH":     "HIGH",
            "MEDIUM":   "MEDIUM",
            "LOW":      "LOW",
            "NONE":     "NORMAL",
        }.get(cvss_severity, "NORMAL")

    def analyse(self, request, payload, ip):

        matched_rules = []
        attack_type = "NONE"
        threat_level = "NORMAL"

        user_agent = request.headers.get("User-Agent", "")

        # NEW: Check for encoded attacks
        encoding_info = self._detect_encoding(payload)
        if encoding_info["suspicious"]:
            matched_rules.append(f"Encoding: {encoding_info['type']}")

        # ---------------------------
        # SQL Injection Detection
        # ---------------------------
        sqli_matches = self._check_patterns(
            payload,
            self._sqli_re
        )

        if sqli_matches:
            matched_rules.extend(
                [f"SQLi: {m}" for m in sqli_matches]
            )

            attack_type = "SQL_INJECTION"
            threat_level = "HIGH"

        # ---------------------------
        # XSS Detection
        # ---------------------------
        xss_matches = self._check_patterns(
            payload,
            self._xss_re
        )

        if xss_matches:

            matched_rules.extend(
                [f"XSS: {m}" for m in xss_matches]
            )

            if attack_type == "NONE":
                attack_type = "XSS"

            threat_level = "HIGH"

        # ---------------------------
        # Traversal Detection
        # ---------------------------
        traversal_matches = self._check_patterns(
            payload,
            self._traversal_re
        )

        if traversal_matches:

            matched_rules.extend(
                [f"Traversal: {m}" for m in traversal_matches]
            )

            if attack_type == "NONE":
                attack_type = "DIRECTORY_TRAVERSAL"

            if threat_level != "HIGH":
                threat_level = "MEDIUM"

        # ---------------------------
        # Attack Payload Check
        # ---------------------------
        is_attack_payload = (
            len(sqli_matches) > 0
            or len(xss_matches) > 0
            or len(traversal_matches) > 0
        )

        # ---------------------------
        # Brute Force Detection
        # ---------------------------
        if (
            not is_attack_payload
            and request.path == "/login"
            and request.method == "POST"
        ):

            username = request.form.get(
                "username",
                ""
            )

            is_brute, count = self._check_brute_force(
                ip,
                username
            )

            if is_brute:

                matched_rules.append(
                    f"Brute Force: {count} attempts"
                )

                attack_type = "BRUTE_FORCE"
                threat_level = "HIGH"

        # ---------------------------
        # Scanner Detection
        # ---------------------------
        # A scanner-tool User-Agent ALONE is weak evidence - legitimate uses
        # exist (health checks, manual testing, monitoring scripts). Without
        # this guard, every bare curl request was being labelled SCANNER/
        # MEDIUM purely on UA, including normal-shaped login attempts with
        # garbage credentials - which is indistinguishable from a human
        # mistyping a password, just sent via curl instead of a browser.
        #
        # SCANNER should mean "this looks like probing/reconnaissance", not
        # "this used curl". Probing looks like: hitting non-standard paths,
        # sending query strings, or zero/near-empty payloads (banner-grab
        # style requests). A normal-shaped username+password POST to /login
        # is NOT probing behaviour regardless of UA - it's what every login
        # attempt looks like, malicious or not, and should be left for the
        # SQLi/XSS/brute-force checks above (or ML) to judge on content,
        # not flagged as SCANNER by default.
        scanner_match = self._check_scanner_ua(user_agent)

        is_standard_login_shape = (
            request.path == "/login"
            and request.method == "POST"
            and len(payload.strip()) > 0
        )

        has_probe_signal = (
            bool(request.query_string)
            or request.path not in ("/", "/login")
            or len(payload.strip()) == 0
        )

        # Behavioural fallback - fires independently of UA. Catches scanners
        # that omit or vary their UA string (a real gap found during a full
        # Nikto run: most requests had no recognisable UA and fell through
        # to NONE despite being clear forced-browsing reconnaissance).
        is_scan_rate, distinct_paths = self._check_scan_rate(ip, request.path)

        if attack_type == "NONE" and not is_standard_login_shape:
            if scanner_match and has_probe_signal:
                matched_rules.append(f"Scanner UA: {scanner_match}")
                attack_type = "SCANNER"
                threat_level = "LOW"
            elif is_scan_rate:
                matched_rules.append(
                    f"Scan Rate: {distinct_paths} distinct paths in {self.SCAN_RATE_WINDOW}s"
                )
                attack_type = "SCANNER"
                threat_level = "LOW"

        # ---------------------------
        # Large Payload
        # ---------------------------
        if (
            len(payload) > 500
            and threat_level == "NORMAL"
        ):

            matched_rules.append(
                "Anomaly: large payload"
            )

            threat_level = "LOW"
            
        ml_result = {}
        
        if self.ml_enabled:
            
            try:
                
                log_entry = {
                    "payload": payload,
                    "payload_len": len(payload),
                    "user_agent": user_agent,
                    "method": request.method,
                    "path": request.path,
                    "query_string": request.query_string.decode(errors="replace"),
                    "matched_rules": matched_rules
                    }
                
                features = self.extractor.extract(
                    log_entry
                    )
                
                ml_result = self.ml_model.predict(
                    features
                    )
                    
                print("[ML]", ml_result)
                
            except Exception as e:
                
                ml_result = {
                    "error": str(e)
                }
             
# ==================================================
# ENSEMBLE DECISION (Rule-Based + ML)
# ==================================================

# ==================================================
# ENSEMBLE DECISION (CVSS Severity x ML Confidence)
# ==================================================
# This is the part that previously clashed: CVSS and ML confidence were
# competing to decide the response on their own. They now answer two
# different questions and get COMBINED, not chosen between:
#
#   CVSS severity   -> "how bad would this be if it's real?"
#   ML confidence    -> "how sure am I this classification is correct?"
#
# A request can be CVSS-critical but low-confidence (escalate cautiously,
# don't commit to an elaborate honey trap that might burn itself on a
# false positive), or CVSS-low but high-confidence (just log it, not
# worth an adaptive response). See _combine_severity_and_confidence().

        ml_confidence = 0.0
        ml_attack_type = None

        if ml_result and ml_result.get("ml_used"):
            ml_confidence = ml_result.get("confidence", 0.0)
            ml_attack_type = ml_result.get("attack_type")

        # Step 1: CVSS severity — computed PER-REQUEST from real signals
        # (how many rules matched, whether the payload was encoded, whether
        # a sensitive path was targeted). Never reads ml_confidence.
        cvss_result = self.cvss_scorer.score(
            attack_type=attack_type,
            matched_rules=matched_rules,
            encoding_info=encoding_info,
            path=request.path,
        )
        threat_level = self._threat_level_from_cvss_severity(cvss_result["cvss_severity"])

        # Step 2: Combine CVSS severity with ML confidence to choose the
        # actual adaptive response — this is the fully ML-driven part.
        adaptive_response, response_tier = self._combine_severity_and_confidence(
            attack_type=attack_type,
            cvss_severity=cvss_result["cvss_severity"],
            ml_confidence=ml_confidence,
        )

        return {
            "threat_level": threat_level,
            "attack_type": attack_type,
            "matched_rules": matched_rules,
            "ip": ip,
            "user_agent": user_agent,
            "payload_len": len(payload),
            "ml_result": ml_result,
            "ml_confidence": ml_confidence,
            "cvss_score": cvss_result["cvss_score"],
            "cvss_severity": cvss_result["cvss_severity"],
            "cvss_vector": cvss_result["cvss_vector"],
            "cvss_modifiers": cvss_result["modifiers_applied"],
            "response_tier": response_tier,
            "adaptive_response": adaptive_response,
        }

    def _combine_severity_and_confidence(self, attack_type, cvss_severity, ml_confidence):
        """
        The actual decision matrix. Both axes matter:

                          LOW/MED CVSS         HIGH/CRITICAL CVSS
                       ┌────────────────────┬────────────────────────┐
        HIGH ML conf   │ log + light action │ FULL adaptive response │
        (>= 0.80)      │                    │ (honey trap, fake err) │
                       ├────────────────────┼────────────────────────┤
        LOW ML conf    │ log only           │ cautious escalation    │
        (< 0.80)       │                    │ (throttle, don't       │
                       │                    │ commit to elaborate    │
                       │                    │ deception yet)         │
                       └────────────────────┴────────────────────────┘

        Returns (response_label, tier) where tier in
        {"FULL", "CAUTIOUS", "LIGHT", "LOG_ONLY"} — tier is what
        deception_module.py actually switches on; response_label is a
        human-readable string for the dashboard.
        """
        high_cvss = cvss_severity in ("HIGH", "CRITICAL")
        high_conf = ml_confidence >= 0.80

        if attack_type in ("NONE", None):
            return "Normal Portal Page", "LOG_ONLY"

        if high_cvss and high_conf:
            tier = "FULL"
        elif high_cvss and not high_conf:
            tier = "CAUTIOUS"
        elif not high_cvss and high_conf:
            tier = "LIGHT"
        else:
            tier = "LOG_ONLY"

        labels = {
            "SQL_INJECTION": {
                "FULL":     "Fake SQL Error (Honey Trap)",
                "CAUTIOUS": "Fake SQL Error (Cautious — low ML confidence on critical CVSS)",
                "LIGHT":    "Generic Login Error",
                "LOG_ONLY": "Normal Portal Page + Logged",
            },
            "BRUTE_FORCE": {
                "FULL":     "Fake Login Success (Strong Honey Trap)",
                "CAUTIOUS": "Account Locked + Throttle (Cautious)",
                "LIGHT":    "Login Failed",
                "LOG_ONLY": "Normal Portal Page + Logged",
            },
            "DIRECTORY_TRAVERSAL": {
                "FULL":     "Fake Directory Listing",
                "CAUTIOUS": "404 + Throttle (Cautious)",
                "LIGHT":    "404 Not Found",
                "LOG_ONLY": "404 Not Found",
            },
            "XSS": {
                "FULL":     "Input Sanitised + Honeytoken Logged",
                "CAUTIOUS": "Invalid Input Error + Throttle",
                "LIGHT":    "Invalid Input Error",
                "LOG_ONLY": "Normal Portal Page + Logged",
            },
            "SCANNER": {
                "FULL":     "Fake Service Banner",
                "CAUTIOUS": "Normal Page + Delay",
                "LIGHT":    "Normal Page + Delay",
                # was "Normal Portal Page + Logged" - identical text to what
                # NONE/no-attack traffic shows, making confirmed scanner
                # activity indistinguishable from genuinely normal traffic
                # at a glance in the dashboard, even though attack_type
                # itself was always correctly recorded as SCANNER
                "LOG_ONLY": "Scanner Probe Logged (No Response Change)",
            },
        }

        response = labels.get(attack_type, {}).get(tier, "Normal Portal Page + Logged")
        return response, tier

    def _check_patterns(self, payload, patterns):

        matched = []

        for regex in patterns:

            m = regex.search(payload)

            if m:
                matched.append(
                    m.group(0)[:50]
                )

        return matched

    def _check_scanner_ua(self, user_agent):

        for regex in self._scanner_re:

            m = regex.search(user_agent)

            if m:
                return m.group(0)

        return None

    def _check_brute_force(
        self,
        ip,
        username=""
    ):

        now = time.time()

        window_start = (
            now - self.BRUTE_FORCE_WINDOW
        )

        key = f"{ip}:{username}"

        self._login_attempts[key] = [
            t
            for t in self._login_attempts[key]
            if t > window_start
        ]

        self._login_attempts[key].append(now)

        count = len(
            self._login_attempts[key]
        )

        return (
            count >= self.BRUTE_FORCE_THRESHOLD,
            count
        )

    def _check_scan_rate(self, ip, path):
        """
        UA-independent behavioural scanner check. Tracks distinct paths
        probed by a single IP within a rolling window, regardless of
        User-Agent. A tool sending no/generic UA but rapidly probing many
        non-standard paths (forced browsing / extension enumeration, the
        exact pattern a real Nikto scan produces) is still recognisable
        as reconnaissance from this behaviour alone.

        Returns (is_scanning, distinct_path_count).
        """
        now = time.time()
        window_start = now - self.SCAN_RATE_WINDOW

        history = self._path_probe_history[ip]
        history = [(t, p) for (t, p) in history if t > window_start]
        history.append((now, path))
        self._path_probe_history[ip] = history

        distinct_paths = len({p for (_, p) in history})

        return (
            distinct_paths >= self.SCAN_RATE_THRESHOLD,
            distinct_paths
        )

    def _detect_encoding(self, payload):
        """
        NEW: Detect URL encoding, Base64, hex, unicode escapes.
        These often indicate obfuscation attempts.
        """
        encoding_scores = {
            "url_encoded": 0,
            "base64": 0,
            "hex": 0,
            "unicode": 0,
            "js_obfuscation": 0,
        }

        # URL encoding pattern: %XX
        url_encoded_count = len(re.findall(r'%[0-9a-fA-F]{2}', payload))
        if url_encoded_count > 3:
            encoding_scores["url_encoded"] += url_encoded_count

        # Base64 pattern: long alphanumeric + padding
        import base64
        try:
            if len(payload) > 10 and re.match(r'^[A-Za-z0-9+/]+={0,2}$', payload[-20:]):
                decoded = base64.b64decode(payload)
                if decoded and len(decoded) > 0:
                    encoding_scores["base64"] += 1
        except:
            pass

        # Hex pattern: 0x followed by hex chars
        hex_count = len(re.findall(r'0x[0-9a-fA-F]+', payload))
        if hex_count > 2:
            encoding_scores["hex"] += hex_count

        # Unicode escapes: \u or &#
        unicode_count = len(re.findall(r'\\u[0-9a-fA-F]{4}|&#\d+;|&#x[0-9a-fA-F]+;', payload))
        if unicode_count > 0:
            encoding_scores["unicode"] += unicode_count

        # JS-level obfuscation: String.fromCharCode, eval(atob(...)), unescape()
        # These deliberately hide the real payload from naive keyword scanning -
        # this is what slipped through as only MEDIUM severity in earlier testing,
        # since plain base64/hex checks don't catch JS-native obfuscation calls.
        js_obf_count = len(re.findall(
            r'fromCharCode|atob\s*\(|unescape\s*\(|String\.raw|eval\s*\(\s*atob',
            payload, re.IGNORECASE
        ))
        if js_obf_count > 0:
            encoding_scores["js_obfuscation"] += js_obf_count * 2  # weighted higher - deliberate evasion

        highest_score = max(encoding_scores.values())
        if highest_score > 0:
            encoding_type = max(encoding_scores, key=encoding_scores.get)
            return {
                "suspicious": True,
                "type": encoding_type,
                "score": highest_score
            }

        return {"suspicious": False, "type": None, "score": 0}

    def _get_subnet(self, ip_address):
        """Extract /24 subnet from IP (for subnet-level tracking)."""
        try:
            parts = ip_address.split(".")
            if len(parts) >= 3:
                return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        except:
            pass
        return ip_address

    def _check_subnet_attacks(self, ip, request_type="login"):
        """
        NEW: Track attacks per /24 subnet (distributed brute force).
        If 5+ different IPs in same subnet attack within 60s, flag distributed attack.
        """
        subnet = self._get_subnet(ip)
        now = time.time()
        window_start = now - self.BRUTE_FORCE_WINDOW

        # Clean old entries
        self._subnet_attacks[subnet] = [
            (t, ip_addr)
            for t, ip_addr in self._subnet_attacks[subnet]
            if t > window_start
        ]

        # Add current attack
        self._subnet_attacks[subnet].append((now, ip))

        # Count unique IPs in this subnet
        unique_ips = len(set(ip_addr for _, ip_addr in self._subnet_attacks[subnet]))
        attack_count = len(self._subnet_attacks[subnet])

        is_distributed = unique_ips >= 3 and attack_count >= 5

        return is_distributed, unique_ips, attack_count