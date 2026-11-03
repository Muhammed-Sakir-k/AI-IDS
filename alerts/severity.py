def get_severity(packets_per_sec):

    if packets_per_sec > 500:
        return "CRITICAL"

    elif packets_per_sec > 250:
        return "HIGH"

    elif packets_per_sec > 100:
        return "MEDIUM"

    return "LOW"