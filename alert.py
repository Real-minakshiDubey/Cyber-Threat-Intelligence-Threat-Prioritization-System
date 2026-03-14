"""
Email Alert System
Sends HTML-formatted alert email when High or Critical vulnerabilities are found.
Triggered automatically after scanning — not manually.
"""

import smtplib
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime
from scanner import ScanResult, Finding


def _severity_color(sev: str) -> str:
    return {
        "Critical": "#c0392b",
        "High":     "#e67e22",
        "Medium":   "#f1c40f",
        "Low":      "#27ae60",
        "Informational": "#3498db",
    }.get(sev, "#555")


def _build_html(result: ScanResult, alert_findings: list) -> str:
    rows = ""
    for f in alert_findings:
        color = _severity_color(f.severity)
        rec_short = f.recommendation[:120] + ("…" if len(f.recommendation) > 120 else "")
        rows += f"""
        <tr>
          <td style="padding:8px 12px;border-bottom:1px solid #eee;">{f.name}</td>
          <td style="padding:8px 12px;border-bottom:1px solid #eee;text-align:center;">
            <span style="background:{color};color:#fff;padding:3px 10px;border-radius:4px;font-size:12px;font-weight:bold;">
              {f.severity}
            </span>
          </td>
          <td style="padding:8px 12px;border-bottom:1px solid #eee;text-align:center;font-weight:bold;">{f.score}/10</td>
          <td style="padding:8px 12px;border-bottom:1px solid #eee;font-size:12px;color:#555;">{rec_short}</td>
        </tr>"""

    risk_color = _severity_color(result.risk_level)

    html = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;font-family:Arial,sans-serif;background:#f4f4f4;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f4;padding:20px 0;">
    <tr><td align="center">
      <table width="620" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.1);">

        <!-- HEADER -->
        <tr>
          <td style="background:#1a1a2e;padding:24px 30px;">
            <h1 style="color:#e94560;margin:0;font-size:22px;">⚠ Security Alert</h1>
            <p style="color:#aaa;margin:6px 0 0;font-size:13px;">Automated Vulnerability Scan Report</p>
          </td>
        </tr>

        <!-- SUMMARY BANNER -->
        <tr>
          <td style="padding:20px 30px;background:#fff3cd;border-left:5px solid {risk_color};">
            <p style="margin:0;font-size:14px;color:#333;">
              <strong>Target:</strong> {result.target_url}<br>
              <strong>Scan Time:</strong> {result.timestamp}<br>
              <strong>Overall Risk Score:</strong>
              <span style="color:{risk_color};font-weight:bold;">{result.overall_risk_score}/100 ({result.risk_level})</span>
            </p>
          </td>
        </tr>

        <!-- FINDINGS TABLE -->
        <tr>
          <td style="padding:20px 30px;">
            <h2 style="font-size:16px;color:#1a1a2e;margin:0 0 12px;">Critical & High Findings</h2>
            <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;font-size:13px;">
              <thead>
                <tr style="background:#1a1a2e;color:#fff;">
                  <th style="padding:10px 12px;text-align:left;">Vulnerability</th>
                  <th style="padding:10px 12px;text-align:center;">Severity</th>
                  <th style="padding:10px 12px;text-align:center;">Score</th>
                  <th style="padding:10px 12px;text-align:left;">Recommended Action</th>
                </tr>
              </thead>
              <tbody>
                {rows}
              </tbody>
            </table>
          </td>
        </tr>

        <!-- TOTAL COUNT -->
        <tr>
          <td style="padding:0 30px 20px;">
            <p style="font-size:13px;color:#555;margin:0;">
              Total findings in this scan: <strong>{len(result.findings)}</strong>
              (Critical: {sum(1 for f in result.findings if f.severity=='Critical')},
               High: {sum(1 for f in result.findings if f.severity=='High')},
               Medium: {sum(1 for f in result.findings if f.severity=='Medium')},
               Low + Info: {sum(1 for f in result.findings if f.severity in ('Low','Informational'))})
            </p>
          </td>
        </tr>

        <!-- FOOTER DISCLAIMER -->
        <tr>
          <td style="background:#f8f8f8;padding:16px 30px;border-top:1px solid #eee;">
            <p style="font-size:11px;color:#999;margin:0;">
              <strong>DISCLAIMER:</strong> This alert was generated automatically by the WebVulnScan educational tool.
              Scans are performed only on authorized test/lab targets. This tool is intended solely for
              educational purposes as part of an academic assignment. No malicious activity is intended or condoned.
              Do not use this tool on systems you do not own or have explicit written permission to test.
              © {datetime.now().year} WebVulnScan — For Educational Use Only.
            </p>
          </td>
        </tr>

      </table>
    </td></tr>
  </table>
</body>
</html>"""
    return html


def send_alert(result: ScanResult,
               smtp_host: str,
               smtp_port: int,
               smtp_user: str,
               smtp_pass: str,
               recipient: str) -> dict:
    """
    Sends HTML alert email if High or Critical findings exist.
    Returns dict with keys: sent (bool), message (str), alert_count (int)
    """
    alert_findings = [f for f in result.findings if f.severity in ("Critical", "High")]

    if not alert_findings:
        return {"sent": False, "message": "No High/Critical findings — email not triggered.", "alert_count": 0}

    highest_sev = "Critical" if any(f.severity == "Critical" for f in alert_findings) else "High"
    domain = result.target_url.replace("https://", "").replace("http://", "").split("/")[0]
    subject = f"[{highest_sev.upper()} ALERT] Vulnerabilities Detected on {domain}"

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = smtp_user
    msg["To"] = recipient

    html_body = _build_html(result, alert_findings)
    msg.attach(MIMEText(html_body, "html"))

    try:
        if smtp_port == 465:
            with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=15) as server:
                server.login(smtp_user, smtp_pass)
                server.sendmail(smtp_user, recipient, msg.as_string())
        else:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
                server.ehlo()
                server.starttls()
                server.login(smtp_user, smtp_pass)
                server.sendmail(smtp_user, recipient, msg.as_string())

        return {
            "sent": True,
            "message": f"Alert email sent to {recipient} ({len(alert_findings)} findings).",
            "alert_count": len(alert_findings),
            "subject": subject,
        }
    except Exception as e:
        return {
            "sent": False,
            "message": f"Failed to send email: {str(e)}",
            "alert_count": len(alert_findings),
        }