"""
logger.py  —  Interaction Logger / Data Storage Layer
Smart Web Honeypot | FYP01-CS-2530-0463

JSON file storage only:
  - Source IP, request headers, full payload, timestamps
  - Attack classification, matched rules
  - ML confidence and predictions
  - Adaptive responses
"""
import json
import os
from datetime import datetime, timedelta
from collections import defaultdict

LOG_FILE = os.path.join(os.path.dirname(__file__), "logs", "attack_logs.jsonl")


class InteractionLogger:

    def __init__(self):
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        if not os.path.exists(LOG_FILE):
            open(LOG_FILE, "a").close()

    def log_request(self, request, threat_level, attack_type,
                    payload="", detection_details=None):
        """
        Log request to JSON file.
        
        Args:
            request: Flask request object
            threat_level: HIGH/MEDIUM/LOW/NORMAL
            attack_type: Attack type classification
            payload: Request payload/data
            detection_details: Dict with ml_confidence, matched_rules, adaptive_response
        """
        if detection_details is None:
            detection_details = {}

        # Log to JSON file
        entry = {
            "timestamp": datetime.now().isoformat(),
            "ip": request.remote_addr,
            "method": request.method,
            "path": request.path,
            "query_string": request.query_string.decode(errors="replace"),
            "user_agent": request.headers.get("User-Agent", ""),
            "payload": payload[:2000],
            "payload_len": len(payload),
            "threat_level": threat_level,
            "attack_type": attack_type,
            "matched_rules": detection_details.get("matched_rules", []),
            "ml_prediction": detection_details.get("ml_result", {}).get("attack_type", "N/A"),
            "ml_confidence": detection_details.get("ml_confidence", 0),
            "ml_probabilities": detection_details.get("ml_result", {}).get("probabilities", {}),
            "adaptive_response": detection_details.get("adaptive_response", "None"),
            "response_html": detection_details.get("response_html", "")[:200],  # Honeypot response sent to attacker
            "cvss_score": detection_details.get("cvss_score", 0),
            "cvss_severity": detection_details.get("cvss_severity", "NONE"),
            "cvss_vector": detection_details.get("cvss_vector", "")
        }

        self._append_json(entry)

    def _append_json(self, entry):
        """Append entry to JSON file."""
        try:
            with open(LOG_FILE, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            print(f"Warning: Could not append to JSON log: {e}")

    def get_logs(self, limit=200, threat_level=None, attack_type=None, days=7):
        """Get logs from JSON file with optional filtering."""
        return self._get_logs_json(limit, threat_level, attack_type, days)

    def _get_logs_json(self, limit=200, threat_level=None, attack_type=None, days=7):
        """Get logs from JSON file with filtering."""
        try:
            with open(LOG_FILE, "r") as f:
                lines = f.readlines()
            
            logs = []
            cutoff_date = datetime.now() - timedelta(days=days)
            
            for line in lines:
                try:
                    entry = json.loads(line)
                    # Parse timestamp and filter by days
                    ts = datetime.fromisoformat(entry.get("timestamp", ""))
                    if ts < cutoff_date:
                        continue
                    
                    # Filter by threat level
                    if threat_level and entry.get("threat_level") != threat_level:
                        continue
                    
                    # Filter by attack type
                    if attack_type and entry.get("attack_type") != attack_type:
                        continue
                    
                    logs.append(entry)
                except (json.JSONDecodeError, ValueError):
                    continue
            
            # Return most recent first, limited to limit
            return list(reversed(logs))[:limit]
        except Exception as e:
            print(f"[!] Error reading JSON logs: {e}")
            return []

    def get_stats(self, days=7):
        """Get comprehensive statistics from JSON logs."""
        return self._get_stats_json(days)

    def _get_stats_json(self, days=7):
        """Calculate stats from JSON logs."""
        try:
            with open(LOG_FILE, "r") as f:
                lines = f.readlines()
            
            logs = []
            cutoff_date = datetime.now() - timedelta(days=days)
            
            for line in lines:
                try:
                    entry = json.loads(line)
                    ts = datetime.fromisoformat(entry.get("timestamp", ""))
                    if ts >= cutoff_date:
                        logs.append(entry)
                except (json.JSONDecodeError, ValueError):
                    continue
        except Exception:
            return {}

        threat_counts = defaultdict(int)
        attack_counts = defaultdict(int)
        ip_counts = defaultdict(int)
        ml_confidence_sum = 0
        ml_count = 0

        for entry in logs:
            threat_counts[entry.get("threat_level", "UNKNOWN")] += 1
            attack_counts[entry.get("attack_type", "NONE")] += 1
            ip_counts[entry.get("ip", "unknown")] += 1

            conf = entry.get("ml_confidence", 0)
            if conf > 0:
                ml_confidence_sum += conf
                ml_count += 1

        top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        avg_ml_confidence = ml_confidence_sum / ml_count if ml_count > 0 else 0

        return {
            "total": len(logs),
            "threat_counts": dict(threat_counts),
            "attack_counts": dict(attack_counts),
            "top_ips": top_ips,
            "ml_stats": {
                "avg_confidence": round(avg_ml_confidence, 4),
                "predictions_count": ml_count
            }
        }

    def get_ip_reputation(self, ip_address):
        """Get reputation info for an IP address."""
        try:
            return self.db.get_ip_reputation(ip_address)
        except Exception:
            return None

    def create_session(self, ip_address, attack_type=None):
        """Create a tracking session for multi-request interactions."""
        try:
            return self.db.create_session(ip_address, attack_type)
        except Exception:
            return None

    def get_session(self, session_token):
        """Get session information."""
        try:
            return self.db.get_session(session_token)
        except Exception:
            return None

    def update_session(self, session_token, **kwargs):
        """Update session state."""
        try:
            self.db.update_session(session_token, **kwargs)
        except Exception:
            pass

    def export_logs(self, format="json", days=30):
        """Export logs in JSON or CSV format."""
        try:
            return self.db.export_logs(format=format, days=days)
        except Exception:
            return ""

    def cleanup_old_logs(self, days=90):
        """Delete logs older than N days."""
        try:
            return self.db.cleanup_old_logs(days=days)
        except Exception:
            return 0

    def clear_logs(self):
        """Clear all logs (JSON file only, for safety)."""
        try:
            open(LOG_FILE, "w").close()
        except Exception:
            pass