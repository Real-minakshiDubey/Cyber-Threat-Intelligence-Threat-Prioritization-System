def calculate_cvss_v3_1(base_metrics: dict) -> float:
    """
    Simulates a standard CVSS v3.1 base score calculation.
    Expected metrics: AV (Attack Vector), AC (Complexity), PR (Privileges),
    UI (User Interaction), S (Scope), C/I/A (Conf, Integ, Avail Impacts).
    """
    
    # Standard CVSS v3.1 weights (simplified for project demonstration)
    weights = {
        'AV': {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.20},
        'AC': {'L': 0.77, 'H': 0.44},
        'PR': {'N': 0.85, 'L': 0.62, 'H': 0.27},
        'UI': {'N': 0.85, 'R': 0.62},
        'C':  {'H': 0.56, 'L': 0.22, 'N': 0.00},
        'I':  {'H': 0.56, 'L': 0.22, 'N': 0.00},
        'A':  {'H': 0.56, 'L': 0.22, 'N': 0.00}
    }
    
    # Impact Subscore (ISS)
    iss = 1 - (
        (1 - weights['C'].get(base_metrics.get('C', 'N'), 0)) *
        (1 - weights['I'].get(base_metrics.get('I', 'N'), 0)) *
        (1 - weights['A'].get(base_metrics.get('A', 'N'), 0))
    )
    
    impact = 6.42 * iss
    if base_metrics.get('S', 'U') == 'C':
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    exploitability = 8.22 * \
        weights['AV'].get(base_metrics.get('AV', 'N'), 0.85) * \
        weights['AC'].get(base_metrics.get('AC', 'L'), 0.77) * \
        weights['PR'].get(base_metrics.get('PR', 'N'), 0.85) * \
        weights['UI'].get(base_metrics.get('UI', 'N'), 0.85)
        
    if impact <= 0:
        return 0.0

    if base_metrics.get('S', 'U') == 'U':
        score = min((impact + exploitability), 10.0)
    else:
        score = min(1.08 * (impact + exploitability), 10.0)
        
    return round(score, 1)


def calculate_risk(open_ports: int, malicious: int, suspicious: int) -> tuple:
    """
    Implements a Three-Dimensional Risk Matrix (Exposure, Threat, Context)
    based on the mentor's notebook logic, scaled to a 100-point system.
    """
    
    # 1. Exposure Score (40% weight) - derived from open port surface
    # Based on mentor logic: higher exposure means more ports open. Let's cap at 20.
    exposure_base = min(open_ports * 5, 100)
    exposure_score = exposure_base * 0.40
    
    # 2. Threat Score (40% weight) - derived from VT malicious/suspicious hits
    # Mentor logic: Malicious count is a heavy multiplier
    threat_base = min((malicious * 15) + (suspicious * 5), 100)
    threat_score = threat_base * 0.40
    
    # 3. Context Score (20% weight) 
    # Simulated context based on the combination of exposure + threat establishing synergy limit
    if malicious > 0 and open_ports > 3:
        context_base = 85 # High context risk due to correlation
    elif suspicious > 0 or open_ports > 5:
        context_base = 50 # Medium correlation
    else:
        context_base = 10 # Low context
    context_score = context_base * 0.20
    
    # Final Risk Score Compilation
    score = round(exposure_score + threat_score + context_score, 2)
    
    # Level thresholds mapped to CVSS standard severity rating distributions
    if score >= 70:
        level = "HIGH"
    elif score >= 40:
        level = "MEDIUM"
    else:
        level = "LOW"
        
    return score, level