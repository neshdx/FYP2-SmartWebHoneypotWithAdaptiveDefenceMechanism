"""
deception_module.py  —  Deception Module (Enhanced)
Smart Web Honeypot | FYP01-CS-2530-0463

Implements Cyber Deception Theory with DYNAMIC FAKE DATA:
  - Simulation: presenting realistic fake assets
  - Honey Tokens: fake credentials with varying responses
  - Response Variation: randomized deception to avoid fingerprinting
  - Attacker Engagement: diverse fake data keeps attacker interested

Adaptive responses based on threat_level + ML_confidence:
  NORMAL -> Realistic portal pages
  LOW    -> Slightly slower response + standard page
  MEDIUM -> Fake error messages, deceptive content
  HIGH   -> Throttled response + deeply deceptive fake DB errors / honey data
"""

import time
import random
from flask import make_response
from fake_data import FakeDataGenerator, get_fake_data


class DeceptionModule:

    # ── Honey Token credentials (if attacker uses these, it's a strong IOC) ──
    HONEY_CREDENTIALS = {
        "admin":    "admin123",
        "root":     "root",
        "sa":       "sa",
        "test":     "test",
        "guest":    "guest",
    }

    # ── Fake SQL error messages (to look like a real vulnerable app) ──────────
    FAKE_SQL_ERRORS = [
        "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '' at line 1",
        "Warning: mysql_fetch_array() expects parameter 1 to be resource, boolean given in /var/www/html/login.php on line 47",
        "ORA-00933: SQL command not properly ended",
        "Microsoft OLE DB Provider for ODBC Drivers error '80040e14' [Microsoft][ODBC SQL Server Driver][SQL Server]Unclosed quotation mark after the character string",
        "Uncaught Error: SQLSTATE[42000]: Syntax error or access violation: 1064 You have an error in your SQL syntax",
    ]

    # ── Fake file/directory listings (for traversal attempts) ─────────────────
    FAKE_DIRECTORY_LISTING = """
<pre>
Index of /var/www/html/
[DIR]  admin/           12-Jan-2026  09:32
[DIR]  uploads/         08-Jan-2026  14:20
[DIR]  backup/          01-Jan-2026  00:00
[FILE] config.php       5.2K         03-Jan-2026
[FILE] db_backup.sql    2.1MB        01-Jan-2026
[FILE] .env             0.8K         15-Dec-2025
</pre>
"""

    # ── Throttle delays by threat level (seconds) ─────────────────────────────
    THROTTLE = {
        "NORMAL": 0,
        "LOW":    0.5,
        "MEDIUM": 1.5,
        "HIGH":   3.0,
    }

    # ─────────────────────────────────────────────────────────────────────────

    def _throttle(self, threat_level: str):
        """Apply response delay (tarpitting) based on threat level."""
        delay = self.THROTTLE.get(threat_level, 0)
        if delay > 0:
            # Add slight jitter so it doesn't look static
            jitter = random.uniform(0, delay * 0.3)
            time.sleep(delay + jitter)

    def _is_honey_credential(self, username: str, password: str) -> bool:
        """Check if attacker used a known honey token credential."""
        return self.HONEY_CREDENTIALS.get(username.lower()) == password

    # ─────────────────────────────────────────────────────────────────────────
    # LOGIN RESPONSES
    # ─────────────────────────────────────────────────────────────────────────

    def get_login_response(self, detection_result: dict) -> str:
        """
        Render the response chosen by DetectionEngine's
        _combine_severity_and_confidence(). This module does NOT re-decide
        anything — the tier (FULL/CAUTIOUS/LIGHT/LOG_ONLY) was already
        computed from CVSS severity x ML confidence in detection_engine.py.
        Re-deriving thresholds here was the cause of the CVSS/ML clash;
        this is the single place the decision is now made.
        """
        self._throttle(detection_result["threat_level"])

        attack_type = detection_result.get("attack_type", "NONE")
        tier        = detection_result.get("response_tier", "LOG_ONLY")

        # tier -> renderer, per attack type. Falls back to LOG_ONLY's
        # renderer for any tier not explicitly listed.
        routing = {
            "SQL_INJECTION": {
                "FULL":     self._login_sqli_response,      # fake DB error / honey
                "CAUTIOUS": self._login_sqli_response,       # still show it, just throttled harder upstream
                "LIGHT":    self._login_fail_with_hint,
                "LOG_ONLY": self._login_fail_normal,
            },
            "BRUTE_FORCE": {
                "FULL":     self._login_fake_success,        # honey trap
                "CAUTIOUS": self._login_account_locked,
                "LIGHT":    self._login_fail_normal,
                "LOG_ONLY": self._login_fail_normal,
            },
            "XSS": {
                "FULL":     self._login_xss_response,
                "CAUTIOUS": self._login_xss_response,
                "LIGHT":    self._login_xss_response,   # was _login_fail_normal - label said
                                                          # "Invalid Input Error" but rendered an
                                                          # indistinguishable normal-failure page,
                                                          # so a real XSS attempt at LIGHT tier gave
                                                          # zero visible signal anything was caught
                "LOG_ONLY": self._login_fail_normal,
            },
            "DIRECTORY_TRAVERSAL": {
                # handled by get_404_response normally, but login.html can
                # also receive traversal-flavoured payloads in the form body
                "FULL":     self._login_fail_with_hint,
                "CAUTIOUS": self._login_fail_with_hint,
                "LIGHT":    self._login_fail_normal,
                "LOG_ONLY": self._login_fail_normal,
            },
            "SCANNER": {
                # Always look normal to scanners — don't reveal honeypot
                "FULL":     self._login_fail_normal,
                "CAUTIOUS": self._login_fail_normal,
                "LIGHT":    self._login_fail_normal,
                "LOG_ONLY": self._login_fail_normal,
            },
        }

        renderer = routing.get(attack_type, {}).get(tier, self._login_fail_normal)
        return renderer()
    
    # ─────────────────────────────────────────────────────────────────────────
    # RESPONSE MATRIX: XSS
    # ─────────────────────────────────────────────────────────────────────────
    # HTML RENDERERS (called by routing table in get_login_response above)
    # ─────────────────────────────────────────────────────────────────────────

    def _login_fail_normal(self) -> str:
        return self._html_page(
            title="Nexus Corp — Employee Portal",
            body="""
            <div class="portal-box">
                <div class="logo">NEXUS CORP</div>
                <p class="subtitle">Employee Self-Service Portal</p>
                <div class="alert-error">Invalid username or password. Please try again.</div>
                <a href="/login" class="btn">Back to Login</a>
            </div>
            """
        )

    def _login_fail_with_hint(self) -> str:
        """Slightly deceptive — hints at existing users."""
        return self._html_page(
            title="Nexus Corp — Employee Portal",
            body="""
            <div class="portal-box">
                <div class="logo">NEXUS CORP</div>
                <p class="subtitle">Employee Self-Service Portal</p>
                <div class="alert-error">Account not found. Ensure you are using your employee ID (e.g. EMP00123) and company password.</div>
                <a href="/login" class="btn">Try Again</a>
            </div>
            """
        )

    def _login_sqli_response(self) -> str:
        """Fake SQL error — makes attacker think they found a real vulnerability."""
        error = random.choice(self.FAKE_SQL_ERRORS)
        return self._html_page(
            title="500 Internal Server Error",
            body=f"""
            <div class="portal-box error-box">
                <h2>Internal Server Error</h2>
                <p>The server encountered an unexpected condition. Database error:</p>
                <pre class="error-code">{error}</pre>
                <p><small>Error logged. Contact system administrator.</small></p>
            </div>
            """
        )

    def _login_fake_success(self) -> str:
        """Honey trap — fake successful login with DYNAMIC fake data."""
        # Generate random fake user data
        fake_user = get_fake_data("user")
        fake_credentials = get_fake_data("credentials")
        
        return self._html_page(
            title="Nexus Corp — Dashboard",
            body=f"""
            <div class="portal-box success-box">
                <div class="logo">NEXUS CORP</div>
                <p class="subtitle">Welcome back, <strong>{fake_user['first_name']}</strong></p>
                <div class="alert-success">Login successful. Dashboard loading...</div>
                <hr>
                <p><strong>Profile Information:</strong></p>
                <table style="width:100%; border-collapse: collapse;">
                    <tr><td><strong>Name:</strong></td><td>{fake_user['first_name']} {fake_user['last_name']}</td></tr>
                    <tr><td><strong>Department:</strong></td><td>{fake_user['department']}</td></tr>
                    <tr><td><strong>Title:</strong></td><td>{fake_user['title']}</td></tr>
                    <tr><td><strong>Email:</strong></td><td>{fake_user['email']}</td></tr>
                </table>
                <hr>
                <p><strong>Recent Activity:</strong></p>
                <ul>
                    <li>Last login: 2026-01-30 08:14:02 from 192.168.1.45</li>
                    <li>Pending emails: {random.randint(1, 5)}</li>
                    <li>System alerts: <span style="color:red">{random.randint(0, 3)} critical</span></li>
                    <li>Session token: {fake_credentials['token'][:20]}...</li>
                </ul>
                <a href="/admin" class="btn">Go to Admin Panel</a>
                <a href="/dashboard" class="btn">View Reports</a>
            </div>
            """
        )

    def _login_account_locked(self) -> str:
        """Moderate deception — account locked after failed attempts."""
        return self._html_page(
            title="Nexus Corp — Account Locked",
            body="""
            <div class="portal-box error-box">
                <div class="logo">NEXUS CORP</div>
                <p class="subtitle">Employee Self-Service Portal</p>
                <h2>Account Locked</h2>
                <p>Your account has been locked due to multiple failed login attempts.</p>
                <p>For security reasons, your account will automatically unlock in <strong>30 minutes</strong>.</p>
                <p>If you believe this is an error, please contact the Help Desk at ext. 5555.</p>
                <hr>
                <p><small>Lockout initiated: 2026-01-30 09:45:23</small></p>
                <p><small>This attempt has been logged and reported to security.</small></p>
                <a href="/help" class="btn">Contact Help Desk</a>
            </div>
            """
        )

    def _login_xss_response(self) -> str:
        """Return sanitised response — XSS payload is not reflected (security)."""
        return self._html_page(
            title="Nexus Corp — Error",
            body="""
            <div class="portal-box error-box">
                <h2>Invalid Input Detected</h2>
                <p>Your input contained invalid characters. This attempt has been logged.</p>
                <a href="/login" class="btn">Back to Login</a>
            </div>
            """
        )

    # ─────────────────────────────────────────────────────────────────────────
    # SEARCH RESPONSES
    # ─────────────────────────────────────────────────────────────────────────

    def get_search_response(self, detection_result: dict, query: str) -> str:
        """
        Render the response chosen by DetectionEngine's
        _combine_severity_and_confidence(), same as get_login_response().
        This was previously a SEPARATE decision path using threat_level +
        manual ml_confidence thresholds that had drifted out of sync with
        the centralized tier logic - meaning XSS payloads sent via /search
        (e.g. attribute-breakout style: " onmouseover="alert(1)) could be
        correctly detected (logged as XSS/MEDIUM) but rendered only a
        generic "Search Unavailable" message, identical to what any
        unrelated MEDIUM-severity event would show. Now uses the same
        tier the login route uses, so behaviour is consistent everywhere.
        """
        self._throttle(detection_result["threat_level"])

        attack_type = detection_result.get("attack_type", "NONE")
        tier        = detection_result.get("response_tier", "LOG_ONLY")

        routing = {
            "SQL_INJECTION": {
                "FULL":     self._search_sqli_honey,
                "CAUTIOUS": self._search_sqli_honey,
                "LIGHT":    self._search_fake_error,
                "LOG_ONLY": lambda: self._search_normal(query),
            },
            "XSS": {
                "FULL":     self._search_xss_response,
                "CAUTIOUS": self._search_xss_response,
                "LIGHT":    self._search_xss_response,
                "LOG_ONLY": lambda: self._search_normal(query),
            },
            "DIRECTORY_TRAVERSAL": {
                "FULL":     self._search_fake_error,
                "CAUTIOUS": self._search_fake_error,
                "LIGHT":    lambda: self._search_normal(query),
                "LOG_ONLY": lambda: self._search_normal(query),
            },
            "SCANNER": {
                "FULL":     lambda: self._search_normal(query),
                "CAUTIOUS": lambda: self._search_normal(query),
                "LIGHT":    lambda: self._search_normal(query),
                "LOG_ONLY": lambda: self._search_normal(query),
            },
        }

        renderer = routing.get(attack_type, {}).get(tier, lambda: self._search_normal(query))
        return renderer()

    def _search_xss_response(self) -> str:
        """XSS-specific search response - mirrors _login_xss_response so
        the same attack type gives a consistent signal regardless of
        which endpoint it was submitted through."""
        return self._html_page(
            title="Nexus Corp — Error",
            body="""
            <div class="portal-box error-box">
                <h2>Invalid Input Detected</h2>
                <p>Your search query contained invalid characters. This attempt has been logged.</p>
                <a href="/login" class="btn">Back</a>
            </div>
            """
        )

    def _search_normal(self, query: str) -> str:
        safe_query = query[:100].replace("<", "&lt;").replace(">", "&gt;")
        return self._html_page(
            title="Nexus Corp — Employee Directory",
            body=f"""
            <div class="portal-box">
                <div class="logo">NEXUS CORP</div>
                <p class="subtitle">Employee Directory Search</p>
                <p>Searching for: <strong>{safe_query}</strong></p>
                <div class="alert-error">No employees found matching your search.</div>
                <a href="/login" class="btn">Back</a>
            </div>
            """
        )

    def _search_fake_error(self) -> str:
        return self._html_page(
            title="Search Error",
            body="""
            <div class="portal-box error-box">
                <h2>Search Unavailable</h2>
                <p>The search service is temporarily unavailable. Please try again later.</p>
            </div>
            """
        )

    def _search_sqli_honey(self) -> str:
        """Fake SQL error on search - WITH dynamic fake database dump."""
        error = random.choice(self.FAKE_SQL_ERRORS)
        
        # Randomly show a fake database dump or just error
        if random.choice([True, False]):
            # Show fake database dump (high engagement)
            dump = get_fake_data("database")
            return self._html_page(
                title="Database Query Results",
                body=f"""
                <div class="portal-box">
                    <h2>Query Results</h2>
                    <pre class="error-code" style="max-height: 400px; overflow:auto;">
{dump}
                    </pre>
                </div>
                """
            )
        else:
            # Show SQL error
            return self._html_page(
                title="Database Error",
                body=f"""
                <div class="portal-box error-box">
                    <h2>Query Error</h2>
                    <pre class="error-code">{error}</pre>
                    <p><small>Query: SELECT * FROM employees WHERE name = '...'</small></p>
                </div>
                """
            )

    # ─────────────────────────────────────────────────────────────────────────
    # DIRECTORY TRAVERSAL RESPONSES
    # ─────────────────────────────────────────────────────────────────────────

    def _traversal_fake_listing(self) -> str:
        """Maximum deception: Show DYNAMIC fake directory listing."""
        # Randomly select a path for more variation
        fake_path = random.choice(["/var/www", "/home", "/etc"])
        listing = get_fake_data("files")  # This uses fake_path internally
        
        return self._html_page(
            title=f"Directory Listing - {fake_path}",
            body=f"""
            <pre style="background:#f0f0f0; padding:10px; overflow:auto; font-family:monospace; font-size:12px;">
{listing}
            </pre>
            <p><small>Generated at {random.randint(2024, 2026)}</small></p>
            """
        )

    def _traversal_forbidden(self) -> str:
        """Moderate deception: 403 Forbidden response."""
        return self._html_page(
            title="403 Forbidden",
            body="""
            <div class="portal-box error-box">
                <h2>403 — Access Forbidden</h2>
                <p>You do not have permission to access this resource.</p>
                <p><small>This attempt has been logged and reported to security.</small></p>
                <a href="/login" class="btn">Back to Login</a>
            </div>
            """
        )

    def _traversal_not_found(self) -> str:
        """Minimal deception: 404 Not Found response."""
        return self._html_page(
            title="404 Not Found",
            body="""
            <div class="portal-box error-box">
                <h2>404 — Not Found</h2>
                <p>The requested resource does not exist.</p>
                <a href="/login" class="btn">Back to Login</a>
            </div>
            """
        )

    # ─────────────────────────────────────────────────────────────────────────
    # ADMIN / TRAVERSAL RESPONSES
    # ─────────────────────────────────────────────────────────────────────────

    def get_admin_response(self, detection_result: dict) -> str:
        """Fake admin panel — honey trap."""
        self._throttle(detection_result["threat_level"])
        return self._html_page(
            title="Nexus Corp — Admin Panel",
            body="""
            <div class="portal-box">
                <div class="logo">NEXUS CORP — ADMIN</div>
                <p class="subtitle">System Administration Portal</p>
                <div class="alert-error">Session expired. Please log in with admin credentials.</div>
                <ul style="text-align:left;margin-top:1rem;">
                    <li><a href="/login">Employee Login</a></li>
                    <li><a href="/admin/users">User Management</a></li>
                    <li><a href="/admin/logs">System Logs</a></li>
                    <li><a href="/admin/config">Configuration</a></li>
                </ul>
            </div>
            """
        )

    def get_404_response(self, detection_result: dict) -> str:
        """Deceptive 404 — may reveal fake directory listing for traversal,
        gated on response_tier (FULL/CAUTIOUS) rather than re-checking
        threat_level directly, so this stays consistent with the
        CVSS x ML-confidence decision made once in detection_engine.py."""
        self._throttle(detection_result["threat_level"])
        attack_type = detection_result.get("attack_type", "")
        tier        = detection_result.get("response_tier", "LOG_ONLY")

        if attack_type == "DIRECTORY_TRAVERSAL" and tier in ("FULL", "CAUTIOUS"):
            # Serve fake directory listing to engage traversal attacker
            return self._html_page(
                title="Index of /",
                body=f"""
                <div class="portal-box">
                    <h2>Index of /</h2>
                    {self.FAKE_DIRECTORY_LISTING}
                    <p><small>Apache/2.4.51 Server at nexus-internal.local Port 80</small></p>
                </div>
                """
            )

        return self._html_page(
            title="404 Not Found",
            body="""
            <div class="portal-box error-box">
                <h2>404 — Page Not Found</h2>
                <p>The requested resource could not be located on this server.</p>
                <a href="/login" class="btn">Back to Portal</a>
            </div>
            """
        )

    # ─────────────────────────────────────────────────────────────────────────
    # HTML TEMPLATE HELPER
    # ─────────────────────────────────────────────────────────────────────────

    def _html_page(self, title: str, body: str) -> str:
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <link rel="stylesheet" href="/static/css/portal.css">
</head>
<body>
    <div class="container">
        {body}
    </div>
    <footer>
        &copy; 2026 Nexus Corporation Sdn Bhd &nbsp;|&nbsp; IT Department &nbsp;|&nbsp;
        <a href="/help">Help Desk</a>
    </footer>
</body>
</html>"""