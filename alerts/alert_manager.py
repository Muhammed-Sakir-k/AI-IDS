# ============================================================
# AI-IDS — Alert Manager (UPDATED)
# File: alerts/alert_manager.py
#
# Changes:
#   ✅ Auto-triggers AI analysis on CRITICAL alerts
#   ✅ Stores analysis in logs/ai_analyses.json
#   ✅ Sends email on CRITICAL
# ============================================================

import csv
import os
import json
import threading
from datetime import datetime, timedelta

ALERT_FILE    = "logs/alerts.csv"
ANALYSIS_FILE = "logs/ai_analyses.json"

# Create alert log if not exists
if not os.path.isfile(ALERT_FILE):
    with open(ALERT_FILE, mode="w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Timestamp", "Source_IP", "Threat_Type", "Severity"])

# Duplicate suppression
_last_alert = {}
ALERT_COOLDOWN = 60  # seconds


def _load_analyses():
    if not os.path.exists(ANALYSIS_FILE):
        return []
    try:
        with open(ANALYSIS_FILE) as f:
            return json.load(f)
    except:
        return []


def _save_analysis(alert_data, report):
    analyses = _load_analyses()
    analyses.insert(0, {
        "timestamp":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "alert":       alert_data,
        "report":      report,
    })
    # Keep only last 50 analyses
    analyses = analyses[:50]
    os.makedirs("logs", exist_ok=True)
    with open(ANALYSIS_FILE, "w") as f:
        json.dump(analyses, f, indent=2, default=str)


def _auto_analyze(alert_data):
    """Runs in background thread — calls Gemini and saves result"""
    try:
        from alerts.ai_analyst import analyze_threat
        print(f"[AUTO-ANALYZE] Analyzing CRITICAL alert from {alert_data.get('ip')}...")
        report = analyze_threat(alert_data)
        _save_analysis(alert_data, report)
        print(f"[AUTO-ANALYZE] Done — {report.get('mitre_technique', '—')}")
    except Exception as e:
        print(f"[AUTO-ANALYZE] Error: {e}")


def get_latest_analysis():
    """Returns the most recent auto-analysis — used by WebSocket"""
    analyses = _load_analyses()
    return analyses[0] if analyses else None


def save_alert(src_ip: str,
               threat_type: str,
               severity: str,
               packets_per_sec: float = 0,
               bytes_per_sec: float = 0,
               protocol: str = "TCP",
               dst_port: int = 0):

    now = datetime.now()
    key = f"{src_ip}_{threat_type}"

    # Suppress duplicates
    if key in _last_alert:
        if now - _last_alert[key] < timedelta(seconds=ALERT_COOLDOWN):
            return
    _last_alert[key] = now

    timestamp = now.strftime("%Y-%m-%d %H:%M:%S")

    # Save to CSV
    with open(ALERT_FILE, mode="a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([timestamp, src_ip, threat_type, severity])

    print(f"[ALERT] {severity} — {threat_type} from {src_ip}")

    # On CRITICAL: auto-analyze in background + send email
    if severity == "CRITICAL":
        alert_data = {
            "ip":              src_ip,
            "threat_type":     threat_type,
            "severity":        severity,
            "protocol":        protocol,
            "packets_per_sec": packets_per_sec,
            "bytes_per_sec":   bytes_per_sec,
            "dst_port":        dst_port,
            "timestamp":       timestamp,
        }

        # Background thread so it doesn't block the sniffer
        t = threading.Thread(target=_auto_analyze, args=(alert_data,), daemon=True)
        t.start()

        # Email alert
        try:
            from alerts.email_alerter import send_critical_alert
            send_critical_alert(src_ip, threat_type, severity,
                                packets_per_sec, bytes_per_sec, protocol)
        except Exception as e:
            print(f"[EMAIL] {e}")