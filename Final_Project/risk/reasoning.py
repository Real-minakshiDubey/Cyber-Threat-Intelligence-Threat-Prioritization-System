def generate_reasoning(open_ports, malicious, suspicious):
    reasons = []

    if open_ports > 3:
        reasons.append("Multiple open ports increase attack surface")

    if malicious > 0:
        reasons.append("IP flagged as malicious by threat intelligence")

    if suspicious > 0:
        reasons.append("Suspicious behavior detected")

    if not reasons:
        reasons.append("No significant threats detected")

    return reasons