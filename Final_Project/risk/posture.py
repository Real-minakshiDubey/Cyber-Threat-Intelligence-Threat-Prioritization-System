def calculate_posture(history):
    if not history:
        return "UNKNOWN"

    avg_score = sum(h["score"] for h in history) / len(history)

    if avg_score > 50:
        return "POOR"
    elif avg_score > 25:
        return "MODERATE"
    else:
        return "GOOD"