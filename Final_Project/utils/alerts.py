def generate_alert(level, ip, score):
    if level == "HIGH":
        return {
            "message": f"🚨 High Risk on {ip}",
            "severity": "critical"
        }
    elif level == "MEDIUM":
        return {
            "message": f"⚠️ Medium Risk on {ip}",
            "severity": "warning"
        }
    return None