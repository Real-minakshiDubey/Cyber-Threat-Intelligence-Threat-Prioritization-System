def explain_prediction(features):

    explanations = []

    if features["malicious"] > 0:
        explanations.append("Malicious activity strongly influenced risk")

    if features["port_count"] > 3:
        explanations.append("Large number of open ports increased exposure")

    if features["abuse_score"] > 50:
        explanations.append("High abuse score indicates suspicious behavior")

    return explanations