def risk_trend_analysis(history):
    if len(history) < 2:
        return "Not enough data"

    if history[-1]["score"] > history[-2]["score"]:
        return "Risk Increasing 📈"
    elif history[-1]["score"] < history[-2]["score"]:
        return "Risk Decreasing 📉"
    else:
        return "Stable Risk ➖"