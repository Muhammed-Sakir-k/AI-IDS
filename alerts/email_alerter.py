# ============================================================
# AI-IDS  —  Email Alerter
# File: alerts/email_alerter.py
#
# SETUP:
#   1. Go to your Google account → Security → App Passwords
#   2. Generate a 16-character App Password
#   3. Paste it below (NOT your normal Gmail password)
# ============================================================

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime

SENDER_EMAIL    = "your_gmail@gmail.com"        # ← change this
SENDER_PASSWORD = "xxxx xxxx xxxx xxxx"         # ← 16-char App Password
RECEIVER_EMAIL  = "your_email@gmail.com"        # ← where alerts go

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587


def send_critical_alert(src_ip, threat_type, severity,
                        packets_per_sec=0, bytes_per_sec=0, protocol="TCP"):

    if not SENDER_EMAIL or not SENDER_PASSWORD:
        print("[EMAIL] Not configured — skipping.")
        return

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    subject   = f"🚨 AI-IDS CRITICAL ALERT — {threat_type} from {src_ip}"

    html = f"""
    <html><body style="font-family:Arial,sans-serif;background:#f1f5f9;margin:0;padding:0;">
      <table width="100%" style="max-width:600px;margin:30px auto;">
        <tr><td style="background:#0f172a;padding:24px 28px;border-radius:10px 10px 0 0;">
          <h1 style="margin:0;color:#fff;font-size:20px;">🛡 AI-IDS — Critical Alert</h1>
          <p style="margin:4px 0 0;color:#94a3b8;font-size:12px;">
            Intrusion Detection System — Automated Notification</p>
        </td></tr>
        <tr><td style="background:#ef4444;padding:12px 28px;">
          <p style="margin:0;color:#fff;font-size:15px;font-weight:bold;">
            ⚠ CRITICAL SEVERITY THREAT DETECTED</p>
        </td></tr>
        <tr><td style="background:#fff;padding:24px 28px;">
          <table width="100%" cellspacing="8">
            <tr>
              <td style="background:#f8fafc;border-radius:8px;padding:14px;width:48%;">
                <p style="margin:0 0 4px;color:#64748b;font-size:11px;
                   text-transform:uppercase;">Source IP</p>
                <p style="margin:0;color:#0f172a;font-size:18px;
                   font-weight:bold;font-family:monospace;">{src_ip}</p>
              </td>
              <td style="background:#f8fafc;border-radius:8px;padding:14px;width:48%;">
                <p style="margin:0 0 4px;color:#64748b;font-size:11px;
                   text-transform:uppercase;">Threat Type</p>
                <p style="margin:0;color:#ef4444;font-size:18px;font-weight:bold;">
                  {threat_type}</p>
              </td>
            </tr>
            <tr>
              <td style="background:#f8fafc;border-radius:8px;padding:14px;">
                <p style="margin:0 0 4px;color:#64748b;font-size:11px;
                   text-transform:uppercase;">Protocol</p>
                <p style="margin:0;color:#0f172a;font-size:16px;font-weight:bold;">
                  {protocol}</p>
              </td>
              <td style="background:#f8fafc;border-radius:8px;padding:14px;">
                <p style="margin:0 0 4px;color:#64748b;font-size:11px;
                   text-transform:uppercase;">Detected At</p>
                <p style="margin:0;color:#0f172a;font-size:14px;font-weight:bold;">
                  {timestamp}</p>
              </td>
            </tr>
          </table>
          <div style="background:#fef2f2;border-left:4px solid #ef4444;
                      border-radius:4px;padding:12px 16px;margin:16px 0;">
            <p style="margin:0 0 6px;color:#7f1d1d;font-size:11px;font-weight:bold;
               text-transform:uppercase;">Traffic Stats</p>
            <p style="margin:0;color:#450a0a;font-size:13px;">
              📦 Packets/sec: <b>{packets_per_sec:.1f}</b> &nbsp;&nbsp;
              📊 Bytes/sec: <b>{bytes_per_sec:.0f}</b></p>
          </div>
          <div style="background:#fff7ed;border-left:4px solid #f97316;
                      border-radius:4px;padding:12px 16px;">
            <p style="margin:0 0 6px;color:#7c2d12;font-size:11px;font-weight:bold;
               text-transform:uppercase;">Immediate Actions</p>
            <ul style="margin:0;padding-left:16px;color:#431407;font-size:13px;">
              <li>Block <b>{src_ip}</b> in your firewall immediately</li>
              <li>Review recent connections from this IP in dashboard</li>
              <li>Check for lateral movement in internal logs</li>
            </ul>
          </div>
        </td></tr>
        <tr><td style="background:#0f172a;padding:14px 28px;border-radius:0 0 10px 10px;">
          <p style="margin:0;color:#475569;font-size:11px;text-align:center;">
            AI-IDS · {timestamp}</p>
        </td></tr>
      </table>
    </body></html>
    """

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = SENDER_EMAIL
        msg["To"]      = RECEIVER_EMAIL
        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())

        print(f"[EMAIL] ✅ Alert sent → {RECEIVER_EMAIL}")

    except smtplib.SMTPAuthenticationError:
        print("[EMAIL] ❌ Wrong App Password — check your Gmail App Passwords.")
    except Exception as e:
        print(f"[EMAIL] ❌ Error: {e}")