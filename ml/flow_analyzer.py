from collections import defaultdict
from datetime import datetime

# Store traffic statistics per IP
traffic_stats = defaultdict(lambda: {
    "packet_count": 0,
    "byte_count": 0,
    "backward_packets": 0,
    "start_time": datetime.now()
})


def update_flow(src_ip, packet_size, is_backward=False):

    flow = traffic_stats[src_ip]

    # Update counters
    flow["packet_count"] += 1
    flow["byte_count"] += packet_size

    # Track backward (return) packets separately
    if is_backward:
        flow["backward_packets"] += 1

    # Calculate duration
    duration = (
        datetime.now() - flow["start_time"]
    ).total_seconds()

    # Reset flow window every 10 seconds
    if duration > 10:
        flow["packet_count"] = 1
        flow["byte_count"] = packet_size
        flow["backward_packets"] = 0
        flow["start_time"] = datetime.now()
        duration = 1

    if duration < 1:
        duration = 1

    # Calculate rates
    packets_per_sec = flow["packet_count"] / duration
    bytes_per_sec = flow["byte_count"] / duration

    print(f"[FLOW] {src_ip} — {packets_per_sec:.1f} pkt/s  {bytes_per_sec:.0f} B/s")

    # -----------------------------
    # THREAT DETECTION
    # THIS was the broken section —
    # indentation is now correct
    # -----------------------------

    suspicious = False

    # Ignore very small flows (not enough data yet)
    if flow["packet_count"] < 10:
        suspicious = False

    else:
        if packets_per_sec > 10:
            suspicious = True

        if bytes_per_sec > 50_000:
            suspicious = True

    return {
        "suspicious": suspicious,
        "flow_duration": duration,
        "total_fwd_packets": flow["packet_count"],
        "total_backward_packets": flow["backward_packets"],  # NOW REAL, not 0
        "flow_bytes_per_sec": bytes_per_sec,
        "flow_packets_per_sec": packets_per_sec
    }