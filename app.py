"""
Smart Web Honeypot - app.py (Web Routing Layer)
Project: FYP02-CS-2610-0463
Student: Dinesh Waren A/L Rajasingam


"""

from flask import Flask, request, render_template, jsonify, redirect, url_for, session, send_file
from detection_engine import DetectionEngine
from deception_module import DeceptionModule
from logger import InteractionLogger
import os
from functools import wraps
from io import BytesIO
from datetime import timedelta
import secrets

app = Flask(__name__)
# IMPORTANT: Use a random secret key on each restart to force fresh login
import secrets
app.secret_key = secrets.token_hex(32)  # Random key forces session invalidation on restart
app.config['SESSION_PERMANENT'] = False  # Session only valid during browser session
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)  # Max 1 hour if permanent

# Initialise core modules
detection_engine = DetectionEngine()
deception_module = DeceptionModule()
logger = InteractionLogger()

# Dashboard credentials (change in production!)
DASHBOARD_USERNAME = "admin"
DASHBOARD_PASSWORD = "honeypot2024!"


def login_required(f):
    """Decorator to protect dashboard routes with authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "admin_logged_in" not in session:
            return redirect(url_for("dashboard_login"))
        return f(*args, **kwargs)
    return decorated_function

# ─────────────────────────────────────────────
# HONEYPOT ROUTES (Employee Login Portal Facade)
# ─────────────────────────────────────────────

@app.route("/", methods=["GET"])
def index():
    """Redirect root to the login portal."""
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Fake employee login portal.
    GET  - Serve the deceptive login page.
    POST - Analyse credentials for attack patterns, respond adaptively.
    """
    if request.method == "GET":
        logger.log_request(request, "NORMAL", "Page visit")
        return render_template("login.html")

    # ── POST: Analyse submitted credentials ──
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    ip = request.remote_addr

    # Build a payload string for detection
    payload = f"{username} {password}"
    result = detection_engine.analyse(request, payload, ip)

    # Generate the deceptive response
    response_html = deception_module.get_login_response(result)

    # CVSS score was already computed per-request inside detection_engine.analyse()
    # (see cvss_score / cvss_severity / cvss_vector / cvss_modifiers on result) —
    # no need to recalculate it here.
    result["response_html"] = response_html[:500]  # Store truncated response

    logger.log_request(request, result["threat_level"], result["attack_type"],
                       payload=payload, detection_details=result)

    # Serve adaptive deceptive response
    return response_html


@app.route("/search", methods=["GET", "POST"])
def search():
    """
    Fake employee directory search - vulnerable-looking endpoint.
    Common SQLi target.
    """
    query = request.args.get("q", "") or request.form.get("q", "")
    ip = request.remote_addr
    payload = query

    result = detection_engine.analyse(request, payload, ip)
    
    # Generate the deceptive response
    response_html = deception_module.get_search_response(result, query)

    # CVSS already computed inside detection_engine.analyse() — see result dict
    result["response_html"] = response_html[:500]  # Store truncated response

    # Log the full request with response
    logger.log_request(request, result["threat_level"], result["attack_type"],
                       payload=payload, detection_details=result)

    return response_html


@app.route("/admin", methods=["GET"])
@app.route("/admin/", methods=["GET"])
@app.route("/admin/<path:subpath>", methods=["GET"])
def admin(subpath=""):
    """
    Fake admin panel - honeytrap for directory traversal & admin probing.
    """
    ip = request.remote_addr
    payload = request.full_path

    result = detection_engine.analyse(request, payload, ip)
    response_html = deception_module.get_admin_response(result)

    # CVSS already computed inside detection_engine.analyse() — see result dict
    result["response_html"] = response_html[:500]  # Store truncated response

    logger.log_request(request, result["threat_level"], result["attack_type"],
                       payload=payload, detection_details=result)

    return response_html


@app.route("/<path:path>", methods=["GET", "POST"])
def catch_all(path):
    """
    Catch-all route for any other probing (directory traversal, file access, etc.)
    """
    ip = request.remote_addr
    payload = f"/{path}?{request.query_string.decode()}"

    result = detection_engine.analyse(request, payload, ip)
    response_html = deception_module.get_404_response(result)
    
    # Calculate CVSS score
    # CVSS already computed inside detection_engine.analyse() — see result dict
    result["response_html"] = response_html[:500]  # Store truncated response

    logger.log_request(request, result["threat_level"], result["attack_type"],
                       payload=payload, detection_details=result)

    return response_html, 404


# ─────────────────────────────────────────────
# DASHBOARD AUTHENTICATION ROUTES
# ─────────────────────────────────────────────

@app.route("/dashboard/login", methods=["GET", "POST"])
def dashboard_login():
    """Dashboard login page."""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        if username == DASHBOARD_USERNAME and password == DASHBOARD_PASSWORD:
            session["admin_logged_in"] = True
            return redirect(url_for("dashboard"))
        else:
            return render_template("dashboard_login.html", error="Invalid credentials"), 401

    return render_template("dashboard_login.html")


@app.route("/dashboard/logout", methods=["GET"])
def dashboard_logout():
    """Logout from dashboard."""
    session.pop("admin_logged_in", None)
    return redirect(url_for("dashboard_login"))


# ─────────────────────────────────────────────
# MONITORING DASHBOARD ROUTES
# ─────────────────────────────────────────────

@app.route("/dashboard", methods=["GET"])
@login_required
def dashboard():
    """Security analyst monitoring dashboard."""
    return render_template("dashboard.html")


@app.route("/api/logs", methods=["GET"])
def api_logs():
    """API endpoint: return attack logs as JSON safely for dashboard display."""
    try:
        import html

        # Default to all logs (36500 days = ~100 years)
        days = request.args.get("days", 36500, type=int)
        threat_level = request.args.get("threat_level")
        attack_type = request.args.get("attack_type")

        # Get original logs (do not modify dataset)
        logs = logger.get_logs(
            limit=500,
            threat_level=threat_level,
            attack_type=attack_type,
            days=days
        )

        # Create sanitized copy for dashboard only
        safe_logs = []

        for log in logs:
            safe_log = {}

            for key, value in log.items():

                # Escape only text fields
                if isinstance(value, str):
                    safe_log[key] = html.escape(value)

                else:
                    safe_log[key] = value

            safe_logs.append(safe_log)


        stats = logger.get_stats(days=days)

        return jsonify({
            "logs": safe_logs,
            "stats": stats
        })

    except Exception as e:
        print(f"[!] API /logs Error: {e}")

        return jsonify({
            "logs": [],
            "stats": {},
            "error": str(e)
        }), 200

@app.route("/api/logs/export", methods=["GET"])
@login_required
def api_logs_export():
    """Export logs in JSON or CSV format."""
    format_type = request.args.get("format", "json").lower()
    days = request.args.get("days", 30, type=int)

    if format_type not in ["json", "csv"]:
        return jsonify({"error": "Invalid format"}), 400

    export_data = logger.export_logs(format=format_type, days=days)

    if format_type == "json":
        return send_file(
            BytesIO(export_data.encode()),
            mimetype="application/json",
            as_attachment=True,
            download_name="honeypot_logs.json"
        )
    else:
        return send_file(
            BytesIO(export_data.encode()),
            mimetype="text/csv",
            as_attachment=True,
            download_name="honeypot_logs.csv"
        )


@app.route("/api/ip-reputation/<ip>", methods=["GET"])
@login_required
def api_ip_reputation(ip):
    """Get reputation info for an IP address."""
    reputation = logger.get_ip_reputation(ip)
    if reputation:
        return jsonify(reputation)
    return jsonify({"error": "IP not found"}), 404


@app.route("/api/alerts", methods=["GET"])
@login_required
def api_alerts():
    """Get pending alerts."""
    try:
        alerts = logger.db.get_unsent_alerts()
        return jsonify({"alerts": alerts, "count": len(alerts)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/cleanup", methods=["POST"])
@login_required
def api_cleanup():
    """Clean up old logs (older than 90 days)."""
    try:
        deleted_count = logger.cleanup_old_logs(days=90)
        return jsonify({"status": "success", "deleted": deleted_count})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/ml-metrics", methods=["GET"])
def api_ml_metrics():
    """API endpoint: return ML model metrics and performance stats."""
    try:
        ml_model = detection_engine.ml_model if hasattr(detection_engine, 'ml_model') else None
        ml_enabled = detection_engine.ml_enabled
        
        metrics = {
            "ml_enabled": ml_enabled,
            "model_trained": ml_model.is_trained if ml_model else False,
            "ml_stats": logger.get_stats().get("ml_stats", {})
        }
        
        # Try to load pre-computed metrics if available
        try:
            import os
            import json
            metrics_file = os.path.join(
                os.path.dirname(__file__),
                "logs",
                "ml_metrics.json"
            )
            if os.path.exists(metrics_file):
                with open(metrics_file, "r") as f:
                    model_metrics = json.load(f)
                    metrics["model_metrics"] = model_metrics
        except:
            pass
        
        return jsonify(metrics)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/logs/clear", methods=["POST"])
def api_clear_logs():
    """Clear all logs (for testing purposes)."""
    logger.clear_logs()
    return jsonify({"status": "cleared"})


# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  Smart Web Honeypot")
    print("  Project: FYP02-CS-2610-0463")
    print("  Student: Dinesh Waren A/L Rajasingam")
    print("=" * 60)
    print("  Honeypot   -> http://127.0.0.1:5000/login")
    print("  Dashboard  -> http://127.0.0.1:5000/dashboard")
    print("=" * 60)
    app.run(debug=True, host="0.0.0.0", port=5000)