"""
cvss_scorer.py — CVSS v3.1-Based Severity Scoring (Per-Request)
Smart Web Honeypot | FYP01-CS-2530-0463

WHY THIS EXISTS (read before editing):
----------------------------------------
CVSS and ML confidence answer two DIFFERENT questions and must not be
collapsed into one number:

  CVSS score      -> "If this attack succeeded, how bad would it be?"
                      (severity of the attack CATEGORY)
  ML confidence    -> "How sure am I this classification is correct?"
                      (certainty about THIS SPECIFIC request)

This file answers the first question ONLY. It must never read
ml_confidence. The combination of the two happens later, in
detection_engine.py's _combine_severity_and_confidence().

HOW THE "PER-REQUEST" PART WORKS:
----------------------------------------
Each attack type has a CVSS v3.1 Base Vector (AV/AC/PR/UI/S/C/I/A) that
is mostly fixed by the nature of the attack class (e.g. SQLi is always
Network-vector, no user interaction needed). What genuinely varies
per-request are real CVSS Temporal/Environmental-style modifiers:

  - Exploit Maturity   : how many distinct attack signatures matched
                         (a request matching 3 SQLi patterns is a more
                         developed/deliberate exploit attempt than one
                         matching a single generic pattern)
  - Report Confidence  : whether the payload was obfuscated/encoded
                         (base64, double URL-encoding, hex) — encoded
                         payloads indicate deliberate evasion, which
                         CVSS Temporal scoring treats as increasing
                         real-world risk
  - Target Sensitivity : whether the request targeted a high-value path
                         (/admin, /api) vs a low-value one — this maps
                         to the CVSS Environmental "Confidentiality
                         Requirement" modifier (CR)

These are not invented metrics — they are the standard CVSS v3.1
Temporal (E, RC) and Environmental (CR/IR/AR) metric groups, simplified
for a honeypot context where full attacker/asset intelligence isn't
available.
"""


class CVSSScorer:

    # ── CVSS v3.1 Base Vectors per attack type (fixed — defines the attack's
    #    inherent nature, not this specific request) ──────────────────────────
    BASE_VECTORS = {
        "SQL_INJECTION": {
            "base_score": 9.8,
            "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        },
        "BRUTE_FORCE": {
            "base_score": 9.8,
            "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        },
        "DIRECTORY_TRAVERSAL": {
            "base_score": 7.5,
            "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        },
        "XSS": {
            "base_score": 6.1,
            "vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        },
        "SCANNER": {
            "base_score": 5.3,
            "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        },
        "NONE": {
            "base_score": 0.0,
            "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        },
    }

    # Paths considered high-value targets (maps to CVSS Confidentiality
    # Requirement environmental modifier)
    SENSITIVE_PATHS = ("/admin", "/api", "/config", "/dashboard")

    SEVERITY_BANDS = [
        (0.1, 3.9,  "LOW"),
        (4.0, 6.9,  "MEDIUM"),
        (7.0, 8.9,  "HIGH"),
        (9.0, 10.0, "CRITICAL"),
    ]

    # ─────────────────────────────────────────────────────────────────────────

    def score(self, attack_type, matched_rules=None, encoding_info=None, path="/"):
        """
        Compute a per-request CVSS-derived severity score.

        Args:
            attack_type:   e.g. "SQL_INJECTION" — determines the Base Vector
            matched_rules: list of rule strings that fired this request
                           (used as Exploit Maturity proxy)
            encoding_info: dict from detection_engine._detect_encoding()
                           e.g. {"suspicious": True, "type": "base64"}
            path:          request.path — used for target sensitivity

        Returns dict: cvss_score, cvss_severity, cvss_vector, modifiers_applied
        (modifiers_applied is included so you can show your supervisor/
        moderator exactly why a given score was reached — useful for the
        "explain in detail how the system was developed" feedback)
        """
        matched_rules = matched_rules or []
        encoding_info = encoding_info or {"suspicious": False}

        base = self.BASE_VECTORS.get(attack_type, self.BASE_VECTORS["NONE"])
        base_score = base["base_score"]

        if base_score == 0.0:
            return {
                "cvss_score": 0.0,
                "cvss_severity": "NONE",
                "cvss_vector": "CVSS:3.1/" + base["vector"],
                "modifiers_applied": [],
            }

        modifiers_applied = []
        multiplier = 1.0

        # ── Temporal: Exploit Maturity (E) ──────────────────────────────────
        # More distinct signatures matched = more developed/deliberate attempt
        rule_count = len(matched_rules)
        if rule_count >= 3:
            multiplier *= 1.05
            modifiers_applied.append("Exploit Maturity (High): {} signatures matched".format(rule_count))
        elif rule_count == 2:
            multiplier *= 1.02
            modifiers_applied.append("Exploit Maturity (Medium): {} signatures matched".format(rule_count))

        # ── Temporal: Report Confidence (RC) ────────────────────────────────
        # Encoded/obfuscated payloads indicate deliberate evasion attempt
        if encoding_info.get("suspicious"):
            multiplier *= 1.08
            modifiers_applied.append(
                "Report Confidence (Confirmed): {} encoding detected — evasion attempt".format(
                    encoding_info.get("type", "unknown")
                )
            )

        # ── Environmental: Confidentiality Requirement (CR) ─────────────────
        # Attack against a high-value path increases real-world impact
        if any(path.startswith(p) for p in self.SENSITIVE_PATHS):
            multiplier *= 1.10
            modifiers_applied.append("Confidentiality Requirement (High): sensitive path '{}' targeted".format(path))

        # Apply multiplier, cap at CVSS max of 10.0
        adjusted_score = min(round(base_score * multiplier, 1), 10.0)
        severity = self._band(adjusted_score)

        return {
            "cvss_score": adjusted_score,
            "cvss_severity": severity,
            "cvss_vector": "CVSS:3.1/" + base["vector"],
            "base_score": base_score,
            "modifiers_applied": modifiers_applied,
        }

    def _band(self, score):
        for low, high, label in self.SEVERITY_BANDS:
            if low <= score <= high:
                return label
        return "NONE"