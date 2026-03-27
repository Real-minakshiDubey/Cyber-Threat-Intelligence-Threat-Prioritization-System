def extract_features(open_ports, malicious, suspicious, abuse_score):

    return {
        "port_count": len(open_ports),

        "has_ssh": 1 if 22 in open_ports else 0,
        "has_http": 1 if 80 in open_ports else 0,

        "malicious": malicious,
        "suspicious": suspicious,
        "abuse_score": abuse_score,

        # 🔥 NEW FEATURES (from notebook thinking)
        "internet_exposed": 1 if len(open_ports) > 0 else 0,
        "high_risk_ports": 1 if any(p in [22, 3389, 21] for p in open_ports) else 0,

        "exploit_available": 1 if malicious > 2 else 0,
        "patch_available": 0 if malicious > 0 else 1
    }