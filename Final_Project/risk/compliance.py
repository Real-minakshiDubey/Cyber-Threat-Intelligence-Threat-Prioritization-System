"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  FILE     : risk/compliance.py                                              ║
║  PURPOSE  : Map detected threats to OWASP Top 10 and NIST CSF categories   ║
║  USED BY  : app.py (Scan page), report.py (PDF export)                     ║
╚══════════════════════════════════════════════════════════════════════════════╝

FRAMEWORKS COVERED:
  • OWASP Top 10 (2021 edition) — web/application security categories
  • NIST Cybersecurity Framework (CSF) — 5 core functions with subcategories

HOW IT WORKS:
  get_compliance_mapping(open_ports, malicious, suspicious, vulns)
      │
      ├─► checks each risk signal against OWASP rules
      ├─► checks each risk signal against NIST rules
      └─► returns deduplicated list of matched compliance items
"""

from typing import List


# ─────────────────────────────────────────────────────────────────────────────
# OWASP TOP 10 (2021) — mapping rules
# Each rule: (condition_fn, owasp_id, title, description)
# ─────────────────────────────────────────────────────────────────────────────

OWASP_RULES = [
    {
        "id":          "A01:2021",
        "title":       "Broken Access Control",
        "description": "Open administrative ports (22, 3389, 5900) expose direct system access.",
        "trigger":     lambda ports, mal, sus, vulns: any(p in ports for p in [22, 3389, 5900, 2222])
    },
    {
        "id":          "A02:2021",
        "title":       "Cryptographic Failures",
        "description": "Unencrypted services detected (FTP:21, Telnet:23, HTTP:80) — data in transit is at risk.",
        "trigger":     lambda ports, mal, sus, vulns: any(p in ports for p in [21, 23, 80, 8080])
    },
    {
        "id":          "A05:2021",
        "title":       "Security Misconfiguration",
        "description": "Multiple unnecessary open ports increase attack surface — principle of least privilege violated.",
        "trigger":     lambda ports, mal, sus, vulns: len(ports) > 3
    },
    {
        "id":          "A06:2021",
        "title":       "Vulnerable and Outdated Components",
        "description": "CVEs detected by Shodan suggest unpatched software components are running.",
        "trigger":     lambda ports, mal, sus, vulns: len(vulns) > 0
    },
    {
        "id":          "A07:2021",
        "title":       "Identification and Authentication Failures",
        "description": "IP flagged as malicious — may indicate credential stuffing, brute force, or account takeover activity.",
        "trigger":     lambda ports, mal, sus, vulns: mal > 0
    },
    {
        "id":          "A09:2021",
        "title":       "Security Logging and Monitoring Failures",
        "description": "Suspicious activity detected with no evidence of active monitoring or incident response.",
        "trigger":     lambda ports, mal, sus, vulns: sus > 0
    },
    {
        "id":          "A08:2021",
        "title":       "Software and Data Integrity Failures",
        "description": "Database port (3306, 5432, 1433) exposed — risk of unauthorised data manipulation.",
        "trigger":     lambda ports, mal, sus, vulns: any(p in ports for p in [3306, 5432, 1433, 27017])
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# NIST CSF — mapping rules
# Framework functions: Identify, Protect, Detect, Respond, Recover
# ─────────────────────────────────────────────────────────────────────────────

NIST_RULES = [
    {
        "function":    "IDENTIFY",
        "id":          "ID.RA-3",
        "title":       "Threat identification",
        "description": "Threats (internal + external) are identified and documented. IP has known malicious activity.",
        "trigger":     lambda ports, mal, sus, vulns: mal > 0 or sus > 0
    },
    {
        "function":    "IDENTIFY",
        "id":          "ID.RA-1",
        "title":       "Asset vulnerability identification",
        "description": "CVEs linked to this host. Asset vulnerabilities should be identified and documented.",
        "trigger":     lambda ports, mal, sus, vulns: len(vulns) > 0
    },
    {
        "function":    "PROTECT",
        "id":          "PR.AC-3",
        "title":       "Remote access management",
        "description": "SSH (22) or RDP (3389) is open. Remote access should be managed and restricted.",
        "trigger":     lambda ports, mal, sus, vulns: any(p in ports for p in [22, 3389, 5900])
    },
    {
        "function":    "PROTECT",
        "id":          "PR.DS-2",
        "title":       "Data-in-transit protection",
        "description": "Unencrypted service ports open. Data in transit must be protected.",
        "trigger":     lambda ports, mal, sus, vulns: any(p in ports for p in [21, 23, 80, 8080])
    },
    {
        "function":    "PROTECT",
        "id":          "PR.IP-1",
        "title":       "Baseline configuration",
        "description": "Excess open ports indicate deviation from a hardened baseline configuration.",
        "trigger":     lambda ports, mal, sus, vulns: len(ports) > 3
    },
    {
        "function":    "DETECT",
        "id":          "DE.CM-1",
        "title":       "Network monitoring",
        "description": "Network is monitored to detect potential cybersecurity events — malicious IP detected.",
        "trigger":     lambda ports, mal, sus, vulns: mal > 0
    },
    {
        "function":    "RESPOND",
        "id":          "RS.RP-1",
        "title":       "Response plan execution",
        "description": "A response plan should be executed for detected malicious or suspicious activity.",
        "trigger":     lambda ports, mal, sus, vulns: mal > 0 or sus > 1
    },
    {
        "function":    "RECOVER",
        "id":          "RC.RP-1",
        "title":       "Recovery plan execution",
        "description": "Recovery plan should be initiated if CVEs indicate exploitable vulnerabilities.",
        "trigger":     lambda ports, mal, sus, vulns: len(vulns) > 0
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# PUBLIC API
# ─────────────────────────────────────────────────────────────────────────────

def get_compliance_mapping(
    open_ports: List[int],
    malicious:  int,
    suspicious: int,
    vulns:      List[str] = None
) -> dict:
    """
    Evaluate risk signals against OWASP Top 10 and NIST CSF rules.

    Args:
        open_ports  : list of open port numbers  e.g. [22, 80, 443]
        malicious   : VirusTotal malicious count
        suspicious  : VirusTotal suspicious count
        vulns       : list of CVE IDs from Shodan  e.g. ["CVE-2021-44228"]

    Returns:
        {
            "owasp": [ {"id": "A05:2021", "title": "...", "description": "..."}, ... ],
            "nist":  [ {"function": "PROTECT", "id": "PR.AC-3", "title": "...", "description": "..."}, ... ],
            "summary": {
                "total_owasp_hits": int,
                "total_nist_hits":  int,
                "nist_functions":   list of triggered NIST function names
            }
        }
    """

    if vulns is None:
        vulns = []

    matched_owasp = []
    matched_nist  = []

    # ── Evaluate OWASP rules ──────────────────────────────────────────────
    for rule in OWASP_RULES:
        try:
            if rule["trigger"](open_ports, malicious, suspicious, vulns):
                matched_owasp.append({
                    "id":          rule["id"],
                    "title":       rule["title"],
                    "description": rule["description"]
                })
        except Exception:
            continue

    # ── Evaluate NIST rules ───────────────────────────────────────────────
    for rule in NIST_RULES:
        try:
            if rule["trigger"](open_ports, malicious, suspicious, vulns):
                matched_nist.append({
                    "function":    rule["function"],
                    "id":          rule["id"],
                    "title":       rule["title"],
                    "description": rule["description"]
                })
        except Exception:
            continue

    # ── Summary ───────────────────────────────────────────────────────────
    triggered_functions = list(dict.fromkeys(r["function"] for r in matched_nist))

    return {
        "owasp": matched_owasp,
        "nist":  matched_nist,
        "summary": {
            "total_owasp_hits": len(matched_owasp),
            "total_nist_hits":  len(matched_nist),
            "nist_functions":   triggered_functions
        }
    }


def format_compliance_for_display(compliance: dict) -> str:
    """
    Returns a plain-text summary for use in terminals, PDF, or email alerts.

    Args:
        compliance: dict returned by get_compliance_mapping()

    Returns:
        Formatted multi-line string
    """

    lines = []

    lines.append("=== OWASP Top 10 (2021) Violations ===")
    if compliance["owasp"]:
        for item in compliance["owasp"]:
            lines.append(f"  [{item['id']}] {item['title']}")
            lines.append(f"       → {item['description']}")
    else:
        lines.append("  No OWASP violations detected.")

    lines.append("")
    lines.append("=== NIST CSF Gaps ===")
    if compliance["nist"]:
        for item in compliance["nist"]:
            lines.append(f"  [{item['function']} — {item['id']}] {item['title']}")
            lines.append(f"       → {item['description']}")
    else:
        lines.append("  No NIST CSF gaps detected.")

    lines.append("")
    s = compliance["summary"]
    lines.append(f"Total: {s['total_owasp_hits']} OWASP hits | "
                 f"{s['total_nist_hits']} NIST gaps | "
                 f"Functions affected: {', '.join(s['nist_functions']) or 'None'}")

    return "\n".join(lines)