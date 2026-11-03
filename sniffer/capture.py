from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from datetime import datetime

from alerts.notifier import detect_port_scan
from alerts.alert_manager import save_alert
from alerts.trusted_ips import TRUSTED_IPS
from alerts.threat_classifier import classify_threat
from alerts.severity import get_severity

from ml.detect import predict_traffic
from ml.flow_analyzer import update_flow

import csv
import os

import sys
INTERFACE = sys.argv[1] if len(sys.argv) > 1 else "Wi-Fi"

# -----------------------------
# LOG SETUP
# -----------------------------

os.makedirs("logs", exist_ok=True)

LOG_FILE = "logs/network_logs.csv"

if not os.path.isfile(LOG_FILE):

    with open(LOG_FILE, mode="w", newline="") as file:

        writer = csv.writer(file)

        writer.writerow([
            "Timestamp",
            "Protocol",
            "Source_IP",
            "Source_Port",
            "Destination_IP",
            "Destination_Port"
        ])


# -----------------------------
# PACKET PROCESSING
# -----------------------------

def process_packet(packet):

    if not packet.haslayer(IP):
        return

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    # Ignore trusted IPs
    trusted = any(
        src_ip.startswith(ip)
        for ip in TRUSTED_IPS
    )

    if trusted:
        return

    protocol = "OTHER"
    src_port = 0
    dst_port = 0

    # -----------------------------
    # TCP
    # -----------------------------

    if packet.haslayer(TCP):

        protocol = "TCP"

        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        # SYN Detection
        if packet[TCP].flags == "S":

            

            detect_port_scan(
                src_ip,
                dst_port
            )

    # -----------------------------
    # UDP
    # -----------------------------

    elif packet.haslayer(UDP):

        protocol = "UDP"

        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    # -----------------------------
    # FLOW ANALYSIS
    # -----------------------------

    # Detect if this is return/backward traffic
    # backward = packet coming TO a local/private IP
    is_backward = dst_ip.startswith("192.168.") or dst_ip.startswith("10.")

    features = update_flow(
        src_ip,
        len(packet),
        is_backward=is_backward
    )

    # -----------------------------
    # BEHAVIORAL ANALYSIS
    # -----------------------------

    if features["suspicious"]:

        threat_type = classify_threat(
            protocol,
            features["flow_packets_per_sec"],
            features["flow_bytes_per_sec"]
        )

        severity = get_severity(
            features["flow_packets_per_sec"]
        )

        print(f"""
====================================
🚨 THREAT DETECTED
====================================
Source IP: {src_ip}

Threat Type: {threat_type}
Severity: {severity}

Packets/sec: {features['flow_packets_per_sec']:.2f}
Bytes/sec: {features['flow_bytes_per_sec']:.2f}
====================================
""")

        save_alert(
            src_ip,
            threat_type,
            severity
        )

        print("[DEBUG] ALERT SAVED")

    # -----------------------------
    # AI THREAT INTELLIGENCE
    # -----------------------------

    prediction = predict_traffic(
        features["flow_duration"],
        features["total_fwd_packets"],
        features["total_backward_packets"],
        features["flow_bytes_per_sec"],
        features["flow_packets_per_sec"]
    )

    if prediction != "BENIGN":

        save_alert(
            src_ip,
            f"AI: {prediction}",   # now says "AI: DDoS" or "AI: PortScan"
            "HIGH"
        )

        print(f"""
====================================
🤖 AI ALERT
====================================
Source IP: {src_ip}

Prediction: {prediction}
====================================
""")

    # -----------------------------
    # LIVE PACKET DISPLAY
    # -----------------------------

    print(f"""
[{timestamp}]
Protocol     : {protocol}
Source IP    : {src_ip}:{src_port}
Destination  : {dst_ip}:{dst_port}
-----------------------------------------
""")

    # -----------------------------
    # SAVE TO CSV
    # -----------------------------

    with open(
        LOG_FILE,
        mode="a",
        newline=""
    ) as file:

        writer = csv.writer(file)

        writer.writerow([
            timestamp,
            protocol,
            src_ip,
            src_port,
            dst_ip,
            dst_port
        ])


# -----------------------------
# START SNIFFER
# -----------------------------

print(
    f"Listening on interface: {INTERFACE}"
)

sniff(
    iface=INTERFACE,
    filter="ip",
    prn=process_packet,
    store=False
)