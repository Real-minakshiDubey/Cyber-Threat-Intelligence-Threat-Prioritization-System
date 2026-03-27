"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  FILE     : utils/report.py                                                 ║
║  PURPOSE  : Generate a complete, audit-ready PDF security report            ║
║  USED BY  : app.py  →  Reports page  →  "Generate PDF" button              ║
║  REQUIRES : fpdf2  (pip install fpdf2)                                      ║
╚══════════════════════════════════════════════════════════════════════════════╝

REPORT SECTIONS:
  1. Cover — title, target IP, generated timestamp, overall risk badge
  2. Executive Summary — risk score, level, confidence, posture
  3. Open Ports — table of port / service / priority
  4. Threat Intelligence — VirusTotal, AbuseIPDB, Shodan summary
  5. OWASP Top 10 Violations — matched categories with descriptions
  6. NIST CSF Gaps — matched framework controls with descriptions
  7. Recommendations — auto-generated action items based on risk level
"""

from fpdf import FPDF
from datetime import datetime
from typing import List


# ─────────────────────────────────────────────────────────────────────────────
# Colour constants  (R, G, B)
# ─────────────────────────────────────────────────────────────────────────────
C_RED    = (180, 40,  40)
C_ORANGE = (200, 100, 20)
C_GREEN  = (40,  130, 60)
C_DARK   = (30,  30,  30)
C_GRAY   = (100, 100, 100)
C_LGRAY  = (230, 230, 230)
C_WHITE  = (255, 255, 255)
C_HEADER = (20,  40,  80)        # dark navy for section headers


def clean_text(text) -> str:
    """Sanitize text for FPDF latin-1 encoding."""
    if text is None:
        return ""
    text = str(text)
    text = text.replace("—", "-").replace("–", "-").replace("“", '"').replace("”", '"').replace("‘", "'").replace("’", "'")
    return text.encode('latin-1', 'replace').decode('latin-1')


def _risk_colour(level: str):
    """Return RGB tuple matching risk level."""
    return {"HIGH": C_RED, "MEDIUM": C_ORANGE, "LOW": C_GREEN}.get(level, C_GRAY)


class SecurityReport(FPDF):
    """Custom FPDF subclass with shared header/footer and helper methods."""

    def __init__(self, target_ip: str):
        super().__init__()
        self.target_ip  = clean_text(target_ip)
        self.generated  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.set_auto_page_break(auto=True, margin=20)
        self.set_margins(20, 20, 20)

    # ── Page header (auto-called by fpdf2) ────────────────────────────────
    def header(self):
        if self.page_no() == 1:
            return                              # cover page has its own header
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*C_GRAY)
        self.cell(0, 8, f"Cyber Risk Assessment Report  |  Target: {self.target_ip}", align="L")
        self.ln(2)
        self.set_draw_color(*C_LGRAY)
        self.line(20, self.get_y(), 190, self.get_y())
        self.ln(4)
        self.set_text_color(*C_DARK)

    # ── Page footer ───────────────────────────────────────────────────────
    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(*C_GRAY)
        self.cell(0, 8, f"Page {self.page_no()}  |  Generated {self.generated}  |  CONFIDENTIAL", align="C")

    # ── Section heading ───────────────────────────────────────────────────
    def section_title(self, text: str):
        self.ln(4)
        self.set_fill_color(*C_HEADER)
        self.set_text_color(*C_WHITE)
        self.set_font("Helvetica", "B", 11)
        self.cell(0, 9, f"  {clean_text(text)}", fill=True, ln=True)
        self.set_text_color(*C_DARK)
        self.ln(3)

    # ── Key-value row ─────────────────────────────────────────────────────
    def kv_row(self, label: str, value: str, value_color=None):
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*C_GRAY)
        self.cell(55, 7, clean_text(label), ln=False)
        self.set_font("Helvetica", "", 9)
        if value_color:
            self.set_text_color(*value_color)
        else:
            self.set_text_color(*C_DARK)
        self.cell(0, 7, clean_text(str(value)), ln=True)
        self.set_text_color(*C_DARK)

    # ── Table header row ──────────────────────────────────────────────────
    def table_header(self, cols: list, widths: list):
        self.set_fill_color(*C_LGRAY)
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*C_DARK)
        for col, w in zip(cols, widths):
            self.cell(w, 8, clean_text(col), border=1, fill=True, align="C")
        self.ln()

    # ── Table data row ────────────────────────────────────────────────────
    def table_row(self, values: list, widths: list, color=None):
        self.set_font("Helvetica", "", 9)
        if color:
            self.set_text_color(*color)
        else:
            self.set_text_color(*C_DARK)
        for val, w in zip(values, widths):
            self.cell(w, 7, clean_text(str(val)), border=1, align="C")
        self.ln()
        self.set_text_color(*C_DARK)

    # ── Bullet point ──────────────────────────────────────────────────────
    def bullet(self, text: str, indent: int = 5):
        self.set_font("Helvetica", "", 9)
        self.set_x(20 + indent)
        self.cell(5, 6, chr(149))           # bullet character
        self.set_x(30 + indent)
        self.multi_cell(0, 6, clean_text(text))

    # ── Compliance item ───────────────────────────────────────────────────
    def compliance_item(self, badge_text: str, title: str, description: str, badge_color):
        self.set_fill_color(*badge_color)
        self.set_text_color(*C_WHITE)
        self.set_font("Helvetica", "B", 8)
        self.cell(30, 7, clean_text(badge_text), fill=True, align="C")
        self.set_text_color(*C_DARK)
        self.set_font("Helvetica", "B", 9)
        self.cell(0, 7, f"  {clean_text(title)}", ln=True)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(*C_GRAY)
        self.set_x(25)
        self.multi_cell(0, 5, clean_text(description))
        self.set_text_color(*C_DARK)
        self.ln(1)


# ─────────────────────────────────────────────────────────────────────────────
# PUBLIC FUNCTION
# ─────────────────────────────────────────────────────────────────────────────

def generate_pdf(
    ip:          str,
    score:       float,
    level:       str,
    open_ports:  List[dict] = None,
    threat_data: dict       = None,
    compliance:  dict       = None,
    output_path: str        = "report.pdf"
) -> str:
    """
    Generate a full audit-ready security report as a PDF.

    Args:
        ip          : Target IP address
        score       : Numeric risk score  (0-100)
        level       : "LOW" | "MEDIUM" | "HIGH"
        open_ports  : list of {"port": int, "service": str, "priority": str}
        threat_data : dict from aggregator.get_combined_threat_data(ip)
        compliance  : dict from compliance.get_compliance_mapping(...)
        output_path : where to save the PDF file

    Returns:
        output_path (str)  — path to the generated file
    """

    # ── Defaults for optional args ─────────────────────────────────────────
    if open_ports  is None: open_ports  = []
    if threat_data is None: threat_data = {}
    if compliance  is None: compliance  = {"owasp": [], "nist": [], "summary": {}}

    pdf = SecurityReport(target_ip=ip)

    # ═══════════════════════════════════════════════════════════════════════
    # PAGE 1 — COVER
    # ═══════════════════════════════════════════════════════════════════════
    pdf.add_page()

    # Title block
    pdf.set_font("Helvetica", "B", 22)
    pdf.set_text_color(*C_HEADER)
    pdf.ln(20)
    pdf.cell(0, 12, "Cyber Risk Assessment Report", ln=True, align="C")

    pdf.set_font("Helvetica", "", 12)
    pdf.set_text_color(*C_GRAY)
    pdf.cell(0, 8, "Automated Threat Intelligence & Compliance Analysis", ln=True, align="C")
    pdf.ln(8)

    # Divider
    pdf.set_draw_color(*C_HEADER)
    pdf.set_line_width(0.8)
    pdf.line(40, pdf.get_y(), 170, pdf.get_y())
    pdf.set_line_width(0.2)
    pdf.ln(12)

    # Risk badge
    risk_color = _risk_colour(level)
    pdf.set_fill_color(*risk_color)
    pdf.set_text_color(*C_WHITE)
    pdf.set_font("Helvetica", "B", 28)
    pdf.cell(0, 18, f"{level} RISK", fill=True, ln=True, align="C")
    pdf.ln(4)

    # Score row
    pdf.set_text_color(*C_DARK)
    pdf.set_font("Helvetica", "", 14)
    pdf.cell(0, 10, f"Risk Score: {score} / 100", ln=True, align="C")
    pdf.ln(10)

    # Metadata block
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(*C_GRAY)
    pdf.cell(0, 7, f"Target IP:    {ip}", ln=True, align="C")
    pdf.cell(0, 7, f"Generated:    {pdf.generated}", ln=True, align="C")
    pdf.cell(0, 7, "Classification:  CONFIDENTIAL", ln=True, align="C")

    # ═══════════════════════════════════════════════════════════════════════
    # PAGE 2 — DETAILED ANALYSIS
    # ═══════════════════════════════════════════════════════════════════════
    pdf.add_page()

    # ── Section 1: Executive Summary ──────────────────────────────────────
    pdf.section_title("1.  Executive Summary")
    pdf.kv_row("Target IP:",    ip)
    pdf.kv_row("Risk Score:",   f"{score} / 100", value_color=_risk_colour(level))
    pdf.kv_row("Risk Level:",   level,             value_color=_risk_colour(level))
    pdf.kv_row("Open Ports:",   len(open_ports))
    pdf.kv_row("Scan Time:",    pdf.generated)

    # ── Section 2: Open Ports ─────────────────────────────────────────────
    pdf.section_title("2.  Open Ports")

    if open_ports:
        pdf.table_header(["Port", "Service", "Priority"], [40, 80, 50])

        for p in open_ports:
            port_num  = str(p.get("port", ""))
            service   = str(p.get("service", "unknown"))
            priority  = str(p.get("priority", "LOW"))
            row_color = C_RED if priority == "HIGH" else C_DARK
            pdf.table_row([port_num, service, priority], [40, 80, 50], color=row_color)

        pdf.ln(3)
    else:
        pdf.set_font("Helvetica", "I", 9)
        pdf.set_text_color(*C_GRAY)
        pdf.cell(0, 7, "No open ports detected.", ln=True)
        pdf.set_text_color(*C_DARK)

    # ── Section 3: Threat Intelligence ────────────────────────────────────
    pdf.section_title("3.  Threat Intelligence Summary")

    pdf.kv_row("VirusTotal Malicious:",  threat_data.get("malicious",  0), value_color=C_RED if threat_data.get("malicious", 0) > 0 else C_GREEN)
    pdf.kv_row("VirusTotal Suspicious:", threat_data.get("suspicious", 0))
    pdf.kv_row("VirusTotal Harmless:",   threat_data.get("harmless",   0))
    pdf.kv_row("AbuseIPDB Score:",       f"{threat_data.get('abuse_score', 0)} / 100")
    pdf.kv_row("Shodan Organisation:",   threat_data.get("shodan_org",     "N/A"))
    pdf.kv_row("Shodan Country:",        threat_data.get("shodan_country", "N/A"))

    shodan_ports = threat_data.get("shodan_ports", [])
    pdf.kv_row("Shodan Open Ports:",     ", ".join(str(p) for p in shodan_ports) if shodan_ports else "None")

    shodan_vulns = threat_data.get("shodan_vulns", [])
    pdf.kv_row("CVEs (Shodan):",         ", ".join(shodan_vulns[:5]) if shodan_vulns else "None detected")

    # ── Section 4: OWASP Top 10 ───────────────────────────────────────────
    pdf.section_title("4.  OWASP Top 10 (2021) — Violations")

    owasp_hits = compliance.get("owasp", [])
    if owasp_hits:
        for item in owasp_hits:
            pdf.compliance_item(
                badge_text  = item["id"],
                title       = item["title"],
                description = item["description"],
                badge_color = C_RED
            )
    else:
        pdf.set_font("Helvetica", "I", 9)
        pdf.set_text_color(*C_GREEN)
        pdf.cell(0, 7, "No OWASP Top 10 violations detected.", ln=True)
        pdf.set_text_color(*C_DARK)

    # ── Section 5: NIST CSF ───────────────────────────────────────────────
    pdf.section_title("5.  NIST Cybersecurity Framework — Gaps")

    nist_hits = compliance.get("nist", [])
    if nist_hits:
        for item in nist_hits:
            pdf.compliance_item(
                badge_text  = item["id"],
                title       = f"[{item['function']}] {item['title']}",
                description = item["description"],
                badge_color = C_ORANGE
            )
    else:
        pdf.set_font("Helvetica", "I", 9)
        pdf.set_text_color(*C_GREEN)
        pdf.cell(0, 7, "No NIST CSF gaps detected.", ln=True)
        pdf.set_text_color(*C_DARK)

    # ── Section 6: Recommendations ────────────────────────────────────────
    pdf.section_title("6.  Recommendations")

    recs = _generate_recommendations(level, open_ports, threat_data, compliance)
    for rec in recs:
        pdf.bullet(rec)

    # ── Save ──────────────────────────────────────────────────────────────
    pdf.output(output_path)
    print(f"[+] Report saved: {output_path}")
    return output_path


# ─────────────────────────────────────────────────────────────────────────────
# RECOMMENDATIONS ENGINE
# ─────────────────────────────────────────────────────────────────────────────

def _generate_recommendations(
    level:       str,
    open_ports:  list,
    threat_data: dict,
    compliance:  dict
) -> List[str]:
    """Auto-generate action items based on what was detected."""

    recs = []
    port_nums = [p.get("port") for p in open_ports]

    if level == "HIGH":
        recs.append("IMMEDIATE ACTION REQUIRED — isolate this host from the network pending investigation.")
        recs.append("Notify your incident response team and begin forensic logging.")

    if threat_data.get("malicious", 0) > 0:
        recs.append("Block this IP at the firewall and DNS level — flagged malicious by VirusTotal.")

    if threat_data.get("abuse_score", 0) > 50:
        recs.append("High AbuseIPDB score — add to deny list and monitor all traffic from this IP.")

    if 22 in port_nums:
        recs.append("Disable SSH password authentication — enforce key-based login only (PR.AC-3).")

    if 3389 in port_nums:
        recs.append("Restrict RDP (3389) to VPN-only access — direct internet exposure is high risk.")

    if 21 in port_nums:
        recs.append("Replace FTP with SFTP or SCP — FTP transmits credentials in plain text (A02:2021).")

    if 80 in port_nums and 443 not in port_nums:
        recs.append("Enable HTTPS and redirect all HTTP traffic — plain HTTP exposes data in transit.")

    if any(p in port_nums for p in [3306, 5432, 1433, 27017]):
        recs.append("Close database port from public internet — databases must never be directly exposed.")

    vulns = threat_data.get("shodan_vulns", [])
    if vulns:
        recs.append(f"Patch CVEs immediately: {', '.join(vulns[:3])}{'...' if len(vulns) > 3 else ''}")

    owasp_count = compliance.get("summary", {}).get("total_owasp_hits", 0)
    if owasp_count > 0:
        recs.append(f"Address {owasp_count} OWASP Top 10 violation(s) identified in this report.")

    if len(open_ports) > 5:
        recs.append("Apply network segmentation and close all ports not required for business operations.")

    if not recs:
        recs.append("No critical actions required. Continue regular monitoring and vulnerability scanning.")

    return recs