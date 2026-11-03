# ============================================================
# AI-IDS — Daily Reset Scheduler
# File: scheduler/daily_reset.py
#
# Runs at midnight every day:
#   1. Generates PDF report for the day
#   2. Saves JSON snapshot
#   3. Clears logs/alerts.csv and logs/network_logs.csv
# ============================================================

import os
import json
import shutil
import pandas as pd
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler

ALERT_FILE   = "logs/alerts.csv"
LOG_FILE     = "logs/network_logs.csv"
REPORTS_DIR  = "reports"
ARCHIVE_FILE = "reports/archive.json"


def _ensure_dirs():
    os.makedirs(REPORTS_DIR, exist_ok=True)
    os.makedirs("logs", exist_ok=True)


def _load_archive():
    if not os.path.exists(ARCHIVE_FILE):
        return []
    with open(ARCHIVE_FILE, "r") as f:
        return json.load(f)


def _save_archive(archive):
    with open(ARCHIVE_FILE, "w") as f:
        json.dump(archive, f, indent=2)


def get_archive():
    """Returns list of all past daily reports — used by admin panel"""
    return _load_archive()


def run_daily_reset(get_stats_fn, generate_pdf_fn):
    """
    Called at midnight. Saves report, then resets logs.
    get_stats_fn    — pass dashboard's get_stats function
    generate_pdf_fn — pass report_generator's generate_pdf_report
    """
    _ensure_dirs()
    today     = datetime.now().strftime("%Y-%m-%d")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"[SCHEDULER] Daily reset starting for {today}...")

    # ── 1. Snapshot current stats ────────────────────────────
    try:
        stats = get_stats_fn()
    except Exception as e:
        print(f"[SCHEDULER] Stats error: {e}")
        stats = {}

    # ── 2. Save JSON snapshot ────────────────────────────────
    json_path = os.path.join(REPORTS_DIR, f"report_{today}.json")
    try:
        with open(json_path, "w") as f:
            json.dump({
                "date":       today,
                "generated":  timestamp,
                "stats":      stats
            }, f, indent=2, default=str)
        print(f"[SCHEDULER] JSON saved: {json_path}")
    except Exception as e:
        print(f"[SCHEDULER] JSON save error: {e}")

    # ── 3. Save PDF report ───────────────────────────────────
    pdf_path = os.path.join(REPORTS_DIR, f"report_{today}.pdf")
    try:
        pdf_bytes = generate_pdf_fn(stats)
        with open(pdf_path, "wb") as f:
            f.write(pdf_bytes)
        print(f"[SCHEDULER] PDF saved: {pdf_path}")
    except Exception as e:
        print(f"[SCHEDULER] PDF save error: {e}")
        pdf_path = None

    # ── 4. Update archive index ──────────────────────────────
    archive = _load_archive()
    archive.insert(0, {
        "date":          today,
        "generated":     timestamp,
        "total_packets": stats.get("total_packets", 0),
        "total_alerts":  stats.get("attack_count", 0),
        "threats_today": stats.get("threats_today", 0),
        "highest_severity": stats.get("highest_severity", "—"),
        "pdf_file":      f"report_{today}.pdf" if pdf_path else None,
        "json_file":     f"report_{today}.json",
    })
    _save_archive(archive)

    # ── 5. Reset logs ────────────────────────────────────────
    try:
        if os.path.exists(ALERT_FILE):
            with open(ALERT_FILE, "w") as f:
                f.write("Timestamp,Source_IP,Threat_Type,Severity\n")
            print(f"[SCHEDULER] Alerts log reset.")

        if os.path.exists(LOG_FILE):
            # Keep only the header row
            df = pd.read_csv(LOG_FILE, nrows=0)
            df.to_csv(LOG_FILE, index=False)
            print(f"[SCHEDULER] Network log reset.")
    except Exception as e:
        print(f"[SCHEDULER] Reset error: {e}")

    print(f"[SCHEDULER] Daily reset complete for {today}.")


def _check_missed_reset(get_stats_fn, generate_pdf_fn):
    """
    On startup, checks if today's report already exists.
    If not, runs the reset — catches any missed midnight resets.
    """
    _ensure_dirs()
    today     = datetime.now().strftime("%Y-%m-%d")
    yesterday = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")

    archive = _load_archive()
    dates_done = [r["date"] for r in archive]

    # If yesterday's report is missing, generate it now
    if yesterday not in dates_done:
        print(f"[SCHEDULER] Missed reset for {yesterday} — running now...")
        run_daily_reset(get_stats_fn, generate_pdf_fn)
    else:
        print(f"[SCHEDULER] Reset for {yesterday} already done. ✅")


def start_scheduler(get_stats_fn, generate_pdf_fn):
    """Start the APScheduler background job + catch missed resets on startup"""

    # Only check for missed reset on startup — not repeatedly
    _check_missed_reset(get_stats_fn, generate_pdf_fn)

    scheduler = BackgroundScheduler()

    # Midnight reset ONLY — once per day at 00:00
    scheduler.add_job(
        func=lambda: run_daily_reset(get_stats_fn, generate_pdf_fn),
        trigger="cron",
        hour=0, minute=0,
        id="daily_reset",
        replace_existing=True
    )

    scheduler.start()
    print("[SCHEDULER] Scheduler started — resets at midnight only.")
    return scheduler