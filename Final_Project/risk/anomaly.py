def detect_anomaly(history):
    if len(history) < 3:
        return None

    last = history[-1]["score"]
    prev = history[-2]["score"]

    if last > prev + 20:
        return "⚠️ Sudden Risk Spike Detected"

    return None

