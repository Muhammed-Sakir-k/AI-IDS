def classify_threat(protocol, packets_per_sec, bytes_per_sec):

    # Port Scan — TCP with high packet rate
    if protocol == "TCP" and packets_per_sec > 20:
        return "Port Scan"

    # UDP Flood
    elif protocol == "UDP" and packets_per_sec > 15:
        return "UDP Flood"

    # Suspicious Data Transfer — check bytes BEFORE generic burst
    elif bytes_per_sec > 50_000:
        return "Suspicious Data Transfer"

    # Traffic Burst — any protocol
    elif packets_per_sec > 10:
        return "Traffic Burst"

    return "Behavioral Anomaly"