def normalize(value, min_val, max_val):
    if max_val == min_val:
        return 0
    return (value - min_val) / (max_val - min_val)


def normalize_features(features):

    return {
        "port_score": normalize(features["port_count"], 0, 10),
        "malicious_score": normalize(features["malicious"], 0, 20),
        "suspicious_score": normalize(features["suspicious"], 0, 20),
        "abuse_score": normalize(features["abuse_score"], 0, 100)
    }