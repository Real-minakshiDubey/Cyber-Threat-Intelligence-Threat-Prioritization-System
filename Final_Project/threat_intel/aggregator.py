"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  FILE     : threat_intel/aggregator.py                                      ║
║  PURPOSE  : Combine VirusTotal + AbuseIPDB + Shodan into one threat dict   ║
║  USED BY  : app.py  →  get_combined_threat_data(ip)                        ║
╚══════════════════════════════════════════════════════════════════════════════╝

DATA FLOW:
  get_combined_threat_data(ip)
      │
      ├─► virustotal.get_ip_report(ip)   →  malicious, suspicious, harmless
      ├─► abuseipdb.get_abuse_data(ip)   →  abuse_score
      └─► shodan.get_shodan_data(ip)     →  ports, vulns, org, country, tags
          │
          └─► merged dict returned to app.py / ml_model pipeline
"""

from threat_intel.virustotal import get_ip_report
from threat_intel.abuseipdb import get_abuse_data
from threat_intel.shodan import get_shodan_data
from threat_intel.nessus import NessusClient
from scanner.openvas import OpenVASScanner


def get_combined_threat_data(ip: str) -> dict:
    """
    Query all three threat intelligence sources and merge results.

    Args:
        ip (str): Target IP address

    Returns:
        dict with keys:
            malicious, suspicious, harmless   ← from VirusTotal
            abuse_score                        ← from AbuseIPDB
            shodan_ports, shodan_vulns,
            shodan_org, shodan_country,
            shodan_hostnames, shodan_tags,
            shodan_banners                     ← from Shodan
    """

    # ── Source 1: VirusTotal ──────────────────────────────────────────────
    vt = get_ip_report(ip) or {}

    # ── Source 2: AbuseIPDB ───────────────────────────────────────────────
    abuse = get_abuse_data(ip) or {}

    # ── Source 3: Shodan ──────────────────────────────────────────────────
    shodan = get_shodan_data(ip)

    # ── Enterprise Scanner Integrations (Scaffolding) ─────────────────────
    nessus_status = "Offline (Requires live instance)"
    openvas_status = "Offline (Requires live gvmd)"
    
    try:
        nessus = NessusClient()
        nessus_status = "Configured" if nessus.url else "Offline"
    except Exception:
        pass
        
    try:
        openvas = OpenVASScanner()
        openvas_status = "Configured"
    except Exception:
        pass

    # ── Merge all ─────────────────────────────────────────────────────────
    return {
        # VirusTotal fields
        "malicious":        vt.get("malicious", 0),
        "suspicious":       vt.get("suspicious", 0),
        "harmless":         vt.get("harmless", 0),

        # AbuseIPDB fields
        "abuse_score":      abuse.get("abuse_score", 0),

        # Shodan fields
        "shodan_ports":     shodan.get("ports", []),
        "shodan_vulns":     shodan.get("vulns", []),          # CVE IDs
        "shodan_org":       shodan.get("org", "Unknown"),
        "shodan_country":   shodan.get("country", "Unknown"),
        "shodan_hostnames": shodan.get("hostnames", []),
        "shodan_tags":      shodan.get("tags", []),
        "shodan_banners":   shodan.get("banners", []),
        
        # Enterprise Integrations
        "nessus_status":    nessus_status,
        "openvas_status":   openvas_status,
    }