from flask import Flask, render_template, jsonify, send_file, request, session, redirect, url_for
from flask_sock import Sock
import pandas as pd
import numpy as np
import os, json, sys, re
from datetime import datetime, timedelta
from collections import Counter

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from alerts.geo_ip import get_geo_bulk
from alerts.threat_intel import get_threat_intel
from alerts.ai_analyst import analyze_threat
from auth.admin_auth import verify_login, change_password, get_username
from scheduler.daily_reset import get_archive, start_scheduler, run_daily_reset

app  = Flask(__name__)
app.secret_key = "aidos-super-secret-key-change-this"
sock = Sock(app)

LOG_FILE     = "logs/network_logs.csv"
ALERT_FILE   = "logs/alerts.csv"
BLOCKED_FILE = "logs/blocked_ips.json"
REPORTS_DIR  = "reports"


# ─────────────────────────────────────────
# AUTH HELPERS
# ─────────────────────────────────────────
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated


# ─────────────────────────────────────────
# BLOCKED IPs HELPERS
# ─────────────────────────────────────────
def load_blocked():
    if not os.path.exists(BLOCKED_FILE):
        return []
    with open(BLOCKED_FILE) as f:
        return json.load(f)

def save_blocked(blocked):
    os.makedirs("logs", exist_ok=True)
    with open(BLOCKED_FILE, "w") as f:
        json.dump(blocked, f, indent=2)


# ─────────────────────────────────────────
# EMAIL CONFIG HELPER
# ─────────────────────────────────────────
def get_email_config():
    try:
        alerter_path = os.path.join(os.path.dirname(__file__), "..", "alerts", "email_alerter.py")
        with open(alerter_path) as f:
            content = f.read()
        sender   = re.search(r'SENDER_EMAIL\s*=\s*"(.*?)"',   content)
        receiver = re.search(r'RECEIVER_EMAIL\s*=\s*"(.*?)"', content)
        return {
            "sender":   sender.group(1)   if sender   else "",
            "receiver": receiver.group(1) if receiver else ""
        }
    except:
        return {"sender": "", "receiver": ""}


# ─────────────────────────────────────────
# RISK SCORE ENGINE
# ─────────────────────────────────────────
def compute_risk_scores(alert_df):
    if alert_df.empty:
        return []
    SEV_WEIGHT = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 10, "LOW": 3}
    scores = {}
    for ip, group in alert_df.groupby("Source_IP"):
        base  = min(len(group) * 5, 40)
        sev_s = min(sum(SEV_WEIGHT.get(s, 0) for s in group["Severity"]), 40)
        types = min(group["Threat_Type"].nunique() * 5, 20)
        total = min(base + sev_s + types, 100)
        scores[ip] = {
            "ip":         ip,
            "score":      int(total),
            "alerts":     len(group),
            "top_threat": group["Threat_Type"].value_counts().idxmax(),
            "level":      "CRITICAL" if total >= 80 else
                          "HIGH"     if total >= 60 else
                          "MEDIUM"   if total >= 30 else "LOW"
        }
    return sorted(scores.values(), key=lambda x: x["score"], reverse=True)[:10]


def compute_heatmap(alert_df):
    matrix = [[0]*24 for _ in range(7)]
    if alert_df.empty:
        return matrix
    try:
        df = alert_df.copy()
        df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="coerce")
        df = df.dropna(subset=["Timestamp"])
        df["dow"]  = df["Timestamp"].dt.dayofweek
        df["hour"] = df["Timestamp"].dt.hour
        for _, row in df.iterrows():
            matrix[int(row["dow"])][int(row["hour"])] += 1
    except Exception as e:
        print(f"[HEATMAP] {e}")
    return matrix


def compute_topology(packet_df, alert_df):
    nodes, edges = {}, {}
    if packet_df is not None and not packet_df.empty:
        sample = packet_df.tail(300)
        for _, row in sample.iterrows():
            src = str(row.get("Source_IP", ""))
            dst = str(row.get("Destination_IP", ""))
            if not src or not dst:
                continue
            for ip in [src, dst]:
                if ip not in nodes:
                    nodes[ip] = {"id": ip, "type": "normal", "connections": 0}
                nodes[ip]["connections"] += 1
            key = f"{src}|{dst}"
            edges[key] = edges.get(key, 0) + 1
    if alert_df is not None and not alert_df.empty:
        for ip in alert_df["Source_IP"].unique():
            if ip in nodes:
                nodes[ip]["type"] = "attacker"
            else:
                nodes[ip] = {"id": ip, "type": "attacker", "connections": 1}
    top_nodes = sorted(nodes.values(), key=lambda x: x["connections"], reverse=True)[:30]
    top_ids   = {n["id"] for n in top_nodes}
    edge_list = [{"source": s, "target": t, "count": c}
                 for k, c in edges.items()
                 for s, t in [k.split("|")]
                 if s in top_ids and t in top_ids]
    return {"nodes": top_nodes, "edges": edge_list}


SUSPICIOUS_PORTS = {
    22: "SSH", 23: "Telnet", 445: "SMB", 3389: "RDP",
    1433: "MSSQL", 3306: "MySQL", 6379: "Redis",
    4444: "Metasploit", 5900: "VNC", 8080: "Alt-HTTP"
}

def compute_port_analysis(packet_df):
    if packet_df is None or packet_df.empty:
        return {"top_ports": [], "suspicious": []}
    try:
        ports = packet_df["Destination_Port"].dropna().astype(int)
        top   = Counter(ports).most_common(10)
        top_ports  = [{"port": int(p), "count": int(c),
                       "service": SUSPICIOUS_PORTS.get(int(p), "—")} for p, c in top]
        suspicious = [{"port": int(p), "count": int(c),
                       "service": SUSPICIOUS_PORTS[int(p)]}
                      for p, c in top if int(p) in SUSPICIOUS_PORTS]
        return {"top_ports": top_ports, "suspicious": suspicious}
    except Exception as e:
        print(f"[PORTS] {e}")
        return {"top_ports": [], "suspicious": []}


# ─────────────────────────────────────────
# MAIN STATS
# ─────────────────────────────────────────
def get_stats():
    packets = []; alerts = []
    total_packets = tcp_count = udp_count = attack_count = 0
    top_threat_ip = top_threat_type = highest_severity = "—"
    threats_today = 0
    hourly_labels = []; hourly_counts = []
    geo_data = []; risk_scores = []
    heatmap  = [[0]*24 for _ in range(7)]
    topology = {"nodes": [], "edges": []}
    port_analysis = {"top_ports": [], "suspicious": []}
    packet_df = None
    alert_df  = pd.DataFrame()

    if os.path.exists(LOG_FILE):
        try:
            packet_df     = pd.read_csv(LOG_FILE)
            packet_df.columns = packet_df.columns.str.strip()
            packets       = packet_df.tail(50).to_dict(orient="records")
            total_packets = len(packet_df)
            tcp_count     = len(packet_df[packet_df["Protocol"] == "TCP"])
            udp_count     = len(packet_df[packet_df["Protocol"] == "UDP"])
            port_analysis = compute_port_analysis(packet_df)
        except Exception as e:
            print(f"[DASHBOARD] Packet log error: {e}")

    if os.path.exists(ALERT_FILE):
        try:
            alert_df = pd.read_csv(ALERT_FILE)
            alert_df.columns = alert_df.columns.str.strip()
            required = {"Timestamp", "Source_IP", "Threat_Type", "Severity"}
            if not required.issubset(set(alert_df.columns)):
                raise ValueError(f"Missing columns: {required - set(alert_df.columns)}")
            if not alert_df.empty:
                alerts        = alert_df.tail(20).to_dict(orient="records")
                attack_count  = len(alert_df)
                top_threat_ip   = alert_df["Source_IP"].value_counts().idxmax()
                top_threat_type = alert_df["Threat_Type"].value_counts().idxmax()
                alert_df["Timestamp"] = pd.to_datetime(alert_df["Timestamp"], errors="coerce")
                today = datetime.now().date()
                threats_today = len(alert_df[alert_df["Timestamp"].dt.date == today])
                for s in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
                    if s in alert_df["Severity"].unique():
                        highest_severity = s
                now = datetime.now()
                hourly_labels = []; hourly_counts = []
                for i in range(11, -1, -1):
                    h_start = now - timedelta(hours=i + 1)
                    h_end   = now - timedelta(hours=i)
                    hourly_labels.append(h_end.strftime("%H:00"))
                    hourly_counts.append(int(len(alert_df[
                        (alert_df["Timestamp"] >= h_start) &
                        (alert_df["Timestamp"] <  h_end)
                    ])))
                unique_ips  = alert_df["Source_IP"].unique().tolist()
                geo_data    = get_geo_bulk(unique_ips)
                risk_scores = compute_risk_scores(alert_df)
                heatmap     = compute_heatmap(alert_df)
        except Exception as e:
            print(f"[DASHBOARD] Alert error: {e}")

    topology = compute_topology(packet_df, alert_df if not alert_df.empty else None)

    return {
        "packets": packets, "alerts": alerts,
        "total_packets": total_packets, "tcp_count": tcp_count,
        "udp_count": udp_count, "attack_count": attack_count,
        "top_threat_ip": top_threat_ip, "top_threat_type": top_threat_type,
        "threats_today": threats_today, "highest_severity": highest_severity,
        "hourly_labels": hourly_labels, "hourly_counts": hourly_counts,
        "geo_data": geo_data, "risk_scores": risk_scores,
        "heatmap": heatmap, "topology": topology,
        "port_analysis": port_analysis,
    }


# ─────────────────────────────────────────
# AUTH ROUTES
# ─────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if verify_login(username, password):
            session["logged_in"] = True
            session["username"]  = username
            return redirect(url_for("dashboard"))
        return render_template("login.html", error="Invalid username or password")
    return render_template("login.html", error=None)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))


# ─────────────────────────────────────────
# MAIN DASHBOARD
# ─────────────────────────────────────────
@app.route("/")
@login_required
def dashboard():
    return render_template("index.html", **get_stats())

@app.route("/api/stats")
@login_required
def api_stats():
    return jsonify(get_stats())


# ─────────────────────────────────────────
# ADMIN PANEL
# ─────────────────────────────────────────
@app.route("/admin")
@login_required
def admin_panel():
    return render_template("admin.html",
        username=session.get("username", "admin"),
        archive=get_archive(),
        email_config=get_email_config()
    )

@app.route("/api/admin/health")
@login_required
def admin_health():
    stats = get_stats()
    alerter_path = os.path.join(os.path.dirname(__file__), "..", "alerts", "email_alerter.py")
    analyst_path = os.path.join(os.path.dirname(__file__), "..", "alerts", "ai_analyst.py")

    email_ok = False
    try:
        with open(alerter_path) as f:
            c = f.read()
        email_ok = "your_gmail" not in c and "SENDER_EMAIL" in c
    except: pass

    api_ok = False
    try:
        with open(analyst_path) as f:
            c = f.read()
        api_ok = "paste-your" not in c and "GEMINI_API_KEY" in c
    except: pass

    return jsonify({
        **stats,
        "logs_ok":      os.path.exists(LOG_FILE),
        "alerts_ok":    os.path.exists(ALERT_FILE),
        "api_key_set":  api_ok,
        "scheduler_ok": True,
        "email_ok":     email_ok,
    })

@app.route("/api/admin/alerts")
@login_required
def admin_alerts():
    if not os.path.exists(ALERT_FILE):
        return jsonify({"alerts": []})
    try:
        df = pd.read_csv(ALERT_FILE)
        return jsonify({"alerts": df.to_dict(orient="records")})
    except:
        return jsonify({"alerts": []})

@app.route("/api/admin/delete-alert", methods=["POST"])
@login_required
def admin_delete_alert():
    index = request.get_json().get("index")
    try:
        df = pd.read_csv(ALERT_FILE)
        df = df.drop(df.index[index]).reset_index(drop=True)
        df.to_csv(ALERT_FILE, index=False)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route("/api/admin/clear-alerts", methods=["POST"])
@login_required
def admin_clear_alerts():
    try:
        with open(ALERT_FILE, "w") as f:
            f.write("Timestamp,Source_IP,Threat_Type,Severity\n")
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route("/api/admin/blocked-ips")
@login_required
def admin_blocked_ips():
    return jsonify({"blocked": load_blocked()})

@app.route("/api/admin/block-ip", methods=["POST"])
@login_required
def admin_block_ip():
    data   = request.get_json()
    ip     = data.get("ip", "").strip()
    reason = data.get("reason", "Manual block")
    if not ip:
        return jsonify({"success": False, "error": "No IP provided"})
    blocked = load_blocked()
    if any(b["ip"] == ip for b in blocked):
        return jsonify({"success": False, "error": "IP already blocked"})
    blocked.append({
        "ip": ip,
        "reason": reason,
        "blocked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "blocked_by": session.get("username", "admin")
    })
    save_blocked(blocked)
    return jsonify({"success": True})

@app.route("/api/admin/unblock-ip", methods=["POST"])
@login_required
def admin_unblock_ip():
    ip      = request.get_json().get("ip", "")
    blocked = [b for b in load_blocked() if b["ip"] != ip]
    save_blocked(blocked)
    return jsonify({"success": True})

@app.route("/api/admin/change-password", methods=["POST"])
@login_required
def admin_change_password():
    data = request.get_json()
    ok, msg = change_password(data.get("old_password",""), data.get("new_password",""))
    return jsonify({"success": ok, "error": msg if not ok else None})

@app.route("/api/admin/save-api-key", methods=["POST"])
@login_required
def admin_save_api_key():
    key = request.get_json().get("api_key", "").strip()
    if not key:
        return jsonify({"success": False, "error": "No key provided"})
    analyst_path = os.path.join(os.path.dirname(__file__), "..", "alerts", "ai_analyst.py")
    try:
        with open(analyst_path) as f:
            content = f.read()
        content = re.sub(r'GEMINI_API_KEY\s*=\s*".*?"',
                         f'GEMINI_API_KEY = "{key}"', content)
        with open(analyst_path, "w") as f:
            f.write(content)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route("/api/admin/manual-reset", methods=["POST"])
@login_required
def admin_manual_reset():
    try:
        from dashboard.report_generator import generate_pdf_report
        run_daily_reset(get_stats, generate_pdf_report)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route("/admin/reports/download/<filename>")
@login_required
def download_report_file(filename):
    path = os.path.join(REPORTS_DIR, filename)
    if not os.path.exists(path):
        return "File not found", 404
    return send_file(os.path.abspath(path), as_attachment=True,
                     download_name=filename)


# ─────────────────────────────────────────
# EXISTING ROUTES
# ─────────────────────────────────────────
@app.route("/download/alerts")
@login_required
def download_alerts():
    if os.path.exists(ALERT_FILE):
        return send_file(os.path.abspath(ALERT_FILE), mimetype="text/csv",
                         as_attachment=True,
                         download_name=f"alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
    return "No alerts file found", 404

@app.route("/download/report")
@login_required
def download_report():
    from dashboard.report_generator import generate_pdf_report
    import io
    s = get_stats()
    ai = None
    if s["alerts"]:
        sev_rank = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        worst = max(s["alerts"],
                    key=lambda a: sev_rank.index(a.get("Severity", "LOW")))
        ai = analyze_threat({
            "ip": worst.get("Source_IP"), "threat_type": worst.get("Threat_Type"),
            "severity": worst.get("Severity"), "timestamp": worst.get("Timestamp"),
        })
    pdf_bytes = generate_pdf_report(s, ai)
    return send_file(io.BytesIO(pdf_bytes), mimetype="application/pdf",
                     as_attachment=True,
                     download_name=f"IDS_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")

@app.route("/api/threat-intel/<path:threat_type>")
@login_required
def threat_intel(threat_type):
    return jsonify(get_threat_intel(threat_type))

@app.route("/api/analyze-threat", methods=["POST"])
@login_required
def analyze_threat_route():
    data = request.get_json()
    try:
        from alerts.geo_ip import get_geo
        geo = get_geo(data.get("ip", ""))
        if geo:
            data["country"] = geo.get("country", "Unknown")
            data["isp"]     = geo.get("isp", "Unknown")
    except: pass
    return jsonify(analyze_threat(data))

@app.route("/api/save-email-settings", methods=["POST"])
@login_required
def save_email_settings():
    data     = request.get_json()
    receiver = data.get("receiver", "").strip()
    sender   = data.get("sender", "").strip()
    password = data.get("password", "").strip()
    if not receiver or not sender or not password:
        return jsonify({"success": False, "error": "Missing fields"})
    alerter_path = os.path.join(os.path.dirname(__file__), "..", "alerts", "email_alerter.py")
    try:
        with open(alerter_path) as f:
            content = f.read()
        content = re.sub(r'SENDER_EMAIL\s*=\s*".*?"',   f'SENDER_EMAIL    = "{sender}"',   content)
        content = re.sub(r'SENDER_PASSWORD\s*=\s*".*?"',f'SENDER_PASSWORD = "{password}"', content)
        content = re.sub(r'RECEIVER_EMAIL\s*=\s*".*?"', f'RECEIVER_EMAIL  = "{receiver}"', content)
        with open(alerter_path, "w") as f:
            f.write(content)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route("/api/test-email", methods=["POST"])
@login_required
def test_email():
    import smtplib
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    data     = request.get_json()
    sender   = data.get("sender", "")
    password = data.get("password", "")
    receiver = data.get("receiver", "")
    html = """<html><body style="font-family:Arial;padding:30px;background:#f1f5f9;">
      <div style="max-width:500px;margin:auto;background:#0f172a;border-radius:12px;padding:28px;color:#e2e8f0;">
        <h2 style="color:#6366f1;">🛡 AI-IDS Test Email</h2>
        <p style="color:#94a3b8;">Email configuration is working. CRITICAL alerts will be sent here.</p>
        <div style="background:rgba(99,102,241,0.1);border-radius:8px;padding:14px;color:#818cf8;">✅ Configuration verified</div>
      </div></body></html>"""
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "✅ AI-IDS Email Test — Working"
        msg["From"]    = sender; msg["To"] = receiver
        msg.attach(MIMEText(html, "html"))
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(sender, password)
            server.sendmail(sender, receiver, msg.as_string())
        return jsonify({"success": True})
    except smtplib.SMTPAuthenticationError:
        return jsonify({"success": False, "error": "Wrong App Password"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@sock.route("/ws/stats")
def ws_stats(ws):
    import time
    last_analysis_ts = None
    prediction_counter = 0

    while True:
        try:
            data = get_stats()

            # Check for new auto-analysis
            from alerts.alert_manager import get_latest_analysis
            latest = get_latest_analysis()
            if latest and latest.get("timestamp") != last_analysis_ts:
                last_analysis_ts = latest.get("timestamp")
                data["auto_analysis"] = latest

            # Only run prediction every 10 minutes — not every 3 seconds
            prediction_counter += 1
            if prediction_counter >= 200:  # 200 x 3 seconds = 10 minutes
                prediction_counter = 0
                if data.get("alerts"):
                    try:
                        from alerts.ai_analyst import predict_next_attack
                        data["prediction"] = predict_next_attack(data["alerts"])
                    except:
                        pass

            ws.send(json.dumps(data, default=str))
            time.sleep(3)
        except:
            break


@app.route("/api/chat", methods=["POST"])
@login_required
def ids_chat():
    """Natural language chat with the IDS using live data"""
    from alerts.ai_analyst import _call_gemini
    import json

    user_message = request.get_json().get("message", "").strip()
    if not user_message:
        return jsonify({"reply": "Please ask a question."})

    # Get live stats to give Gemini full context
    stats = get_stats()

    # Build a rich context summary
    alerts_summary = "\n".join([
        f"  - {a.get('Threat_Type','?')} from {a.get('Source_IP','?')} [{a.get('Severity','?')}] at {a.get('Timestamp','?')}"
        for a in stats.get("alerts", [])[-15:]
    ]) or "  No alerts yet."

    risk_summary = "\n".join([
        f"  - {r['ip']} → Score:{r['score']} Level:{r['level']} Alerts:{r['alerts']} TopThreat:{r['top_threat']}"
        for r in stats.get("risk_scores", [])[:5]
    ]) or "  No risk data yet."

    blocked = load_blocked()
    blocked_summary = ", ".join([b["ip"] for b in blocked]) or "None"

    prompt = f"""You are an AI security analyst assistant embedded inside a real-time 
Intrusion Detection System called AI-IDS. You have full access to the live network data below.
Answer the user's question conversationally but with expert precision.
Be specific — use the actual IPs, numbers, and threat types from the data.
Keep your answer concise but complete. Use bullet points when listing multiple items.
Do NOT say you don't have access to data — you do, it's below.

=== LIVE SYSTEM DATA ===

TRAFFIC OVERVIEW:
- Total Packets Captured: {stats.get('total_packets', 0)}
- TCP Packets: {stats.get('tcp_count', 0)}
- UDP Packets: {stats.get('udp_count', 0)}
- Total Alerts: {stats.get('attack_count', 0)}
- Threats Today: {stats.get('threats_today', 0)}
- Highest Severity: {stats.get('highest_severity', '—')}
- Top Threat IP: {stats.get('top_threat_ip', '—')}
- Top Threat Type: {stats.get('top_threat_type', '—')}

RECENT ALERTS (last 15):
{alerts_summary}

TOP RISK SCORES:
{risk_summary}

BLOCKED IPs:
{blocked_summary}

=== USER QUESTION ===
{user_message}

Answer as a cybersecurity expert analyst. Be direct and specific."""

    try:
        reply = _call_gemini(prompt)
        return jsonify({"reply": reply, "success": True})
    except Exception as e:
        return jsonify({"reply": f"AI unavailable: {str(e)}", "success": False})

# ─────────────────────────────────────────
# START
# ─────────────────────────────────────────
if __name__ == "__main__":
    # Start daily reset scheduler
    try:
        from dashboard.report_generator import generate_pdf_report
        start_scheduler(get_stats, generate_pdf_report)
    except Exception as e:
        print(f"[SCHEDULER] Could not start: {e}")

    os.makedirs("logs", exist_ok=True)
    os.makedirs("reports", exist_ok=True)
    os.makedirs("auth", exist_ok=True)

    app.run(debug=True)