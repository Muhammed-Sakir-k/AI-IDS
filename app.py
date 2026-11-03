"""Main entry point for the AI-IDS application."""

from pathlib import Path
import os
import sys


PROJECT_ROOT = Path(__file__).resolve().parent
os.chdir(PROJECT_ROOT)

# Prevent Windows consoles from crashing on Unicode scheduler messages.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from dashboard.app import app, get_stats
from dashboard.report_generator import generate_pdf_report
from scheduler.daily_reset import start_scheduler


def main():
    """Start background jobs and serve the dashboard."""
    for directory in ("logs", "reports", "auth"):
        (PROJECT_ROOT / directory).mkdir(exist_ok=True)

    try:
        start_scheduler(get_stats, generate_pdf_report)
    except Exception as exc:
        print(f"[SCHEDULER] Could not start: {exc}")

    # The reloader is disabled because it would start the scheduler twice.
    app.run(
        host=os.environ.get("AI_IDS_HOST", "127.0.0.1"),
        port=int(os.environ.get("AI_IDS_PORT", "5000")),
        debug=os.environ.get("AI_IDS_DEBUG", "").lower() in {"1", "true", "yes"},
        use_reloader=False,
    )


if __name__ == "__main__":
    main()
