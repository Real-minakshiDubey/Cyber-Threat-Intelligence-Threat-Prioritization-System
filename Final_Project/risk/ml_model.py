from risk.normalization import normalize_features

def predict_risk(features):

    norm = normalize_features(features)

    score = (
        norm["port_score"] * 15 +
        norm["malicious_score"] * 30 +
        norm["suspicious_score"] * 15 +
        norm["abuse_score"] * 10 +
        
        features["internet_exposed"] * 5 +
        features["high_risk_ports"] * 10 +
        features["exploit_available"] * 10 +
        (1 - features["patch_available"]) * 5
    )

    if score > 70:
        level = "HIGH"
    elif score > 40:
        level = "MEDIUM"
    else:
        level = "LOW"

    return level, round(score, 2)


def confidence_score(score):
    return min(100, int(score))