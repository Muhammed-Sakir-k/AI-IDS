from collections import defaultdict
from datetime import datetime, timedelta
from alerts.alert_manager import save_alert

port_tracker = defaultdict(lambda: {"ports": set(), "timestamps": []})

UNIQUE_PORT_THRESHOLD = 4
TIME_WINDOW = 30


def detect_port_scan(src_ip, dst_port):

    current_time = datetime.now()
    tracker = port_tracker[src_ip]

    tracker["ports"].add(dst_port)
    tracker["timestamps"].append(current_time)

    # Remove timestamps older than TIME_WINDOW
    tracker["timestamps"] = [
        t for t in tracker["timestamps"]
        if current_time - t < timedelta(seconds=TIME_WINDOW)
    ]

    # If the time window expired, reset ports too
    if len(tracker["timestamps"]) == 0:
        tracker["ports"].clear()
        return

    unique_ports = len(tracker["ports"])

    if unique_ports >= UNIQUE_PORT_THRESHOLD:

        print(f"""
====================================
⚠  ALERT: Port Scan Detected
====================================
Time      : {current_time.strftime("%Y-%m-%d %H:%M:%S")}
Source IP : {src_ip}
Ports Hit : {unique_ports} unique ports in {TIME_WINDOW}s
Verdict   : Reconnaissance / Service Enumeration
====================================
""")

        # ✅ FIX: Save to alerts CSV so dashboard shows it
        save_alert(src_ip, "Port Scan", "MEDIUM")

        # Reset so we don't spam
        tracker["ports"].clear()
        tracker["timestamps"].clear()