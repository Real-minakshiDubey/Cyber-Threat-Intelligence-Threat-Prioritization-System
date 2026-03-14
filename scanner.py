"""
Vulnerability Scanner Module
Detects: SQLi, XSS, Open Redirect, Security Headers, Directory Listing,
         Cookie Flags, CSRF, SSL/TLS, Sensitive Files, Clickjacking
"""

import requests
import urllib.parse
import ssl
import socket
import time
import re
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Optional

requests.packages.urllib3.disable_warnings()

# ── Data Model ─────────────────────────────────────────────────────────────

SEVERITY_SCORE = {
    "Critical": 10,
    "High": 7,
    "Medium": 4,
    "Low": 2,
    "Informational": 1,
}

@dataclass
class Finding:
    name: str
    severity: str          # Critical | High | Medium | Low | Informational
    score: int
    description: str
    recommendation: str
    evidence: str = ""

@dataclass
class ScanResult:
    target_url: str
    timestamp: str
    findings: List[Finding] = field(default_factory=list)
    overall_risk_score: float = 0.0
    risk_level: str = ""
    scan_duration: float = 0.0
    error: Optional[str] = None

    def compute_risk(self):
        if not self.findings:
            self.overall_risk_score = 0.0
            self.risk_level = "None"
            return
        weights = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Informational": 0.5}
        total = sum(f.score * weights.get(f.severity, 1) for f in self.findings)
        max_possible = max(weights.values()) * max(SEVERITY_SCORE.values()) * len(self.findings)
        normalized = min(100, (total / max(max_possible, 1)) * 100)
        self.overall_risk_score = round(normalized, 1)
        if self.overall_risk_score >= 70:
            self.risk_level = "Critical"
        elif self.overall_risk_score >= 50:
            self.risk_level = "High"
        elif self.overall_risk_score >= 30:
            self.risk_level = "Medium"
        elif self.overall_risk_score > 0:
            self.risk_level = "Low"
        else:
            self.risk_level = "None"


# ── Helpers ─────────────────────────────────────────────────────────────────

HEADERS = {
    "User-Agent": "Mozilla/5.0 (VulnScannerBot/1.0; educational-use-only)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

def safe_get(url, params=None, timeout=8, verify=False, allow_redirects=True):
    try:
        r = requests.get(url, params=params, headers=HEADERS,
                         timeout=timeout, verify=verify,
                         allow_redirects=allow_redirects)
        return r
    except Exception:
        return None


# ── Check 1: SQL Injection (error-based probe) ───────────────────────────────

def check_sqli(base_url: str) -> Optional[Finding]:
    payloads = ["'", "\"", "' OR '1'='1", "1; DROP TABLE users--"]
    error_patterns = [
        r"sql syntax", r"mysql_fetch", r"ORA-\d{5}", r"syntax error",
        r"unclosed quotation", r"pg_query", r"sqlite3", r"microsoft ole db"
    ]
    parsed = urllib.parse.urlparse(base_url)
    qs = urllib.parse.parse_qs(parsed.query)

    if not qs:
        # Try appending a dummy param
        test_url = base_url + ("&" if "?" in base_url else "?") + "id="
    else:
        param = list(qs.keys())[0]
        test_url = base_url  # will replace below

    for payload in payloads:
        if qs:
            param = list(qs.keys())[0]
            injected = {k: (payload if k == param else v[0]) for k, v in qs.items()}
            r = safe_get(parsed.scheme + "://" + parsed.netloc + parsed.path, params=injected)
        else:
            r = safe_get(test_url + urllib.parse.quote(payload))

        if r and r.text:
            text_lower = r.text.lower()
            for pat in error_patterns:
                if re.search(pat, text_lower):
                    return Finding(
                        name="SQL Injection",
                        severity="Critical",
                        score=10,
                        description="The application may be vulnerable to SQL Injection. "
                                    "Database error messages were detected in the response.",
                        recommendation="Use parameterized queries / prepared statements. "
                                       "Never concatenate user input into SQL strings.",
                        evidence=f"Payload: {payload} → pattern matched: {pat}"
                    )
    return None


# ── Check 2: Reflected XSS ───────────────────────────────────────────────────

def check_xss(base_url: str) -> Optional[Finding]:
    xss_payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        '"><svg onload=alert(1)>',
    ]
    parsed = urllib.parse.urlparse(base_url)
    qs = urllib.parse.parse_qs(parsed.query)

    for payload in xss_payloads:
        if qs:
            param = list(qs.keys())[0]
            injected = {k: (payload if k == param else v[0]) for k, v in qs.items()}
            r = safe_get(parsed.scheme + "://" + parsed.netloc + parsed.path, params=injected)
        else:
            test_url = base_url + ("&" if "?" in base_url else "?") + "q=" + urllib.parse.quote(payload)
            r = safe_get(test_url)

        if r and payload in (r.text or ""):
            return Finding(
                name="Reflected Cross-Site Scripting (XSS)",
                severity="High",
                score=7,
                description="User-supplied input is reflected in the response without proper encoding, "
                            "enabling script injection attacks.",
                recommendation="HTML-encode all user input before rendering. "
                               "Implement a strict Content-Security-Policy header.",
                evidence=f"Payload reflected verbatim: {payload[:60]}"
            )
    return None


# ── Check 3: Security Headers ────────────────────────────────────────────────

REQUIRED_HEADERS = {
    "Strict-Transport-Security": ("High", 7,
        "HSTS is missing. Browsers will not enforce HTTPS, enabling downgrade attacks.",
        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"),
    "Content-Security-Policy": ("High", 7,
        "No CSP header found. The application is vulnerable to XSS and data injection.",
        "Define a restrictive CSP, e.g.: Content-Security-Policy: default-src 'self'"),
    "X-Frame-Options": ("Medium", 4,
        "Missing X-Frame-Options. Page can be embedded in iframes (Clickjacking risk).",
        "Add: X-Frame-Options: DENY  or use CSP frame-ancestors directive."),
    "X-Content-Type-Options": ("Low", 2,
        "Missing X-Content-Type-Options. Browser MIME-sniffing may lead to XSS.",
        "Add: X-Content-Type-Options: nosniff"),
    "Referrer-Policy": ("Informational", 1,
        "No Referrer-Policy header. Sensitive URLs may leak via Referer header.",
        "Add: Referrer-Policy: strict-origin-when-cross-origin"),
    "Permissions-Policy": ("Informational", 1,
        "No Permissions-Policy header. Browser features may be accessible to scripts.",
        "Add a Permissions-Policy header restricting camera, microphone, geolocation, etc."),
}

def check_security_headers(r: requests.Response) -> List[Finding]:
    findings = []
    for hdr, (sev, score, desc, rec) in REQUIRED_HEADERS.items():
        if hdr.lower() not in {k.lower() for k in r.headers}:
            findings.append(Finding(
                name=f"Missing Header: {hdr}",
                severity=sev,
                score=score,
                description=desc,
                recommendation=rec,
                evidence=f"Header '{hdr}' absent in response"
            ))
    return findings


# ── Check 4: Open Redirect ───────────────────────────────────────────────────

def check_open_redirect(base_url: str) -> Optional[Finding]:
    redirect_params = ["url", "redirect", "next", "return", "returnUrl", "to", "go", "dest"]
    evil = "https://evil-test-domain-xyz.com"
    parsed = urllib.parse.urlparse(base_url)

    for param in redirect_params:
        test = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{param}={urllib.parse.quote(evil)}"
        r = safe_get(test, allow_redirects=False)
        if r and r.status_code in (301, 302, 303, 307, 308):
            loc = r.headers.get("Location", "")
            if evil in loc or "evil-test" in loc:
                return Finding(
                    name="Open Redirect",
                    severity="Medium",
                    score=4,
                    description="The application redirects users to attacker-controlled URLs, "
                                "enabling phishing attacks.",
                    recommendation="Validate redirect targets against a whitelist of allowed domains.",
                    evidence=f"Param '{param}' caused redirect to: {loc[:80]}"
                )
    return None


# ── Check 5: Cookie Security Flags ──────────────────────────────────────────

def check_cookies(r: requests.Response) -> List[Finding]:
    findings = []
    set_cookie_headers = r.headers.getlist("Set-Cookie") if hasattr(r.headers, "getlist") \
                         else [v for k, v in r.headers.items() if k.lower() == "set-cookie"]

    if not set_cookie_headers:
        return findings

    for cookie_str in set_cookie_headers:
        cookie_lower = cookie_str.lower()
        name = cookie_str.split("=")[0].strip()

        if "httponly" not in cookie_lower:
            findings.append(Finding(
                name="Cookie Missing HttpOnly Flag",
                severity="Medium",
                score=4,
                description=f"Cookie '{name}' does not have the HttpOnly flag. "
                            "JavaScript can read this cookie, facilitating session hijacking via XSS.",
                recommendation="Set the HttpOnly flag on all session cookies.",
                evidence=f"Cookie: {cookie_str[:80]}"
            ))

        if "secure" not in cookie_lower:
            findings.append(Finding(
                name="Cookie Missing Secure Flag",
                severity="Medium",
                score=4,
                description=f"Cookie '{name}' does not have the Secure flag. "
                            "It may be transmitted over HTTP, exposing it to interception.",
                recommendation="Set the Secure flag on all cookies containing sensitive data.",
                evidence=f"Cookie: {cookie_str[:80]}"
            ))

        if "samesite" not in cookie_lower:
            findings.append(Finding(
                name="Cookie Missing SameSite Attribute",
                severity="Low",
                score=2,
                description=f"Cookie '{name}' lacks SameSite attribute, increasing CSRF risk.",
                recommendation="Add SameSite=Lax or SameSite=Strict to all session cookies.",
                evidence=f"Cookie: {cookie_str[:80]}"
            ))
    return findings


# ── Check 6: SSL/TLS ─────────────────────────────────────────────────────────

def check_ssl(base_url: str) -> List[Finding]:
    findings = []
    parsed = urllib.parse.urlparse(base_url)

    if parsed.scheme != "https":
        findings.append(Finding(
            name="No HTTPS / Plaintext HTTP",
            severity="High",
            score=7,
            description="The site is served over HTTP. All data is transmitted in plaintext.",
            recommendation="Obtain a TLS certificate (e.g., Let's Encrypt) and enforce HTTPS.",
            evidence=f"URL scheme: {parsed.scheme}"
        ))
        return findings

    host = parsed.netloc.split(":")[0]
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((host, 443), timeout=5), server_hostname=host) as s:
            cert = s.getpeercert()
            version = s.version()

        # Check for weak protocols
        if version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            findings.append(Finding(
                name="Weak TLS Version",
                severity="High",
                score=7,
                description=f"Server negotiated {version}, which is deprecated and insecure.",
                recommendation="Disable TLS 1.0 and 1.1. Support only TLS 1.2 and 1.3.",
                evidence=f"Negotiated: {version}"
            ))

        # Check certificate expiry
        expire_str = cert.get("notAfter", "")
        if expire_str:
            expire_dt = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
            days_left = (expire_dt - datetime.utcnow()).days
            if days_left < 0:
                findings.append(Finding(
                    name="Expired SSL Certificate",
                    severity="Critical",
                    score=10,
                    description="The SSL certificate has expired. Browsers will show security warnings.",
                    recommendation="Renew the certificate immediately.",
                    evidence=f"Expired: {expire_str}"
                ))
            elif days_left < 30:
                findings.append(Finding(
                    name="SSL Certificate Expiring Soon",
                    severity="High",
                    score=7,
                    description=f"SSL certificate expires in {days_left} days.",
                    recommendation="Renew the certificate before expiry.",
                    evidence=f"Expires: {expire_str} ({days_left} days remaining)"
                ))

    except ssl.SSLCertVerificationError as e:
        findings.append(Finding(
            name="Invalid / Untrusted SSL Certificate",
            severity="High",
            score=7,
            description="The SSL certificate is invalid or self-signed.",
            recommendation="Install a certificate from a trusted Certificate Authority.",
            evidence=str(e)[:120]
        ))
    except Exception:
        pass  # Network error – skip SSL check silently

    return findings


# ── Check 7: Sensitive Files Exposed ────────────────────────────────────────

SENSITIVE_PATHS = [
    ("/.env", "Environment file (.env) exposed — may contain API keys and DB credentials."),
    ("/.git/config", "Git config exposed — repository structure may be downloadable."),
    ("/admin", "Admin panel accessible without authentication check."),
    ("/phpinfo.php", "phpinfo() output exposed — reveals server configuration details."),
    ("/web.config", "web.config exposed — may reveal application secrets."),
    ("/wp-admin/", "WordPress admin login panel publicly accessible."),
    ("/server-status", "Apache server-status page exposed — reveals internal info."),
    ("/backup.zip", "Backup archive may be publicly downloadable."),
    ("/robots.txt", None),  # Informational only
]

def check_sensitive_files(base_url: str) -> List[Finding]:
    findings = []
    parsed = urllib.parse.urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    for path, desc in SENSITIVE_PATHS:
        r = safe_get(base + path)
        if r is None:
            continue

        if path == "/robots.txt" and r.status_code == 200:
            # Check if Disallow reveals sensitive paths
            disallowed = re.findall(r"Disallow:\s*(.+)", r.text)
            if disallowed:
                findings.append(Finding(
                    name="robots.txt Reveals Sensitive Paths",
                    severity="Informational",
                    score=1,
                    description="robots.txt lists paths that may hint at sensitive areas.",
                    recommendation="Avoid listing sensitive paths in robots.txt.",
                    evidence="Disallowed: " + ", ".join(disallowed[:5])
                ))
            continue

        if r.status_code == 200 and desc:
            findings.append(Finding(
                name=f"Sensitive File Exposed: {path}",
                severity="High",
                score=7,
                description=desc,
                recommendation=f"Remove or restrict access to '{path}' immediately.",
                evidence=f"HTTP 200 at {base + path}"
            ))
    return findings


# ── Check 8: Directory Listing ───────────────────────────────────────────────

def check_directory_listing(base_url: str) -> Optional[Finding]:
    patterns = ["Index of /", "Directory listing for", "<title>Index of"]
    common_dirs = ["/images/", "/uploads/", "/static/", "/files/", "/assets/"]
    parsed = urllib.parse.urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    for d in common_dirs:
        r = safe_get(base + d)
        if r and r.status_code == 200:
            for pat in patterns:
                if pat.lower() in r.text.lower():
                    return Finding(
                        name="Directory Listing Enabled",
                        severity="Medium",
                        score=4,
                        description=f"Directory listing is enabled at '{d}'. "
                                    "Attackers can enumerate all files.",
                        recommendation="Disable directory listing in web server config "
                                       "(e.g., Options -Indexes in Apache).",
                        evidence=f"Pattern '{pat}' found at {base + d}"
                    )
    return None


# ── Check 9: Clickjacking (redundant deep check) ─────────────────────────────

def check_clickjacking(r: requests.Response) -> Optional[Finding]:
    xfo = r.headers.get("X-Frame-Options", "").upper()
    csp = r.headers.get("Content-Security-Policy", "")
    has_frame_ancestors = "frame-ancestors" in csp.lower()

    if not xfo and not has_frame_ancestors:
        return Finding(
            name="Clickjacking Vulnerability",
            severity="Medium",
            score=4,
            description="No frame-busting protection found. The page can be embedded in an iframe "
                        "on an attacker's site to trick users into unintended actions.",
            recommendation="Add X-Frame-Options: DENY or CSP frame-ancestors 'none'.",
            evidence="Neither X-Frame-Options nor CSP frame-ancestors directive found."
        )
    return None


# ── Check 10: HTTPS Redirect ─────────────────────────────────────────────────

def check_https_redirect(base_url: str) -> Optional[Finding]:
    parsed = urllib.parse.urlparse(base_url)
    if parsed.scheme == "http":
        http_url = base_url
        https_url = "https://" + parsed.netloc + parsed.path
        r = safe_get(http_url, allow_redirects=False)
        if r and r.status_code not in (301, 302, 307, 308):
            return Finding(
                name="No HTTP→HTTPS Redirect",
                severity="Medium",
                score=4,
                description="HTTP requests are not automatically redirected to HTTPS.",
                recommendation="Configure a server-side redirect from HTTP to HTTPS.",
                evidence=f"HTTP request to {http_url} returned {r.status_code} without redirect."
            )
    return None


# ── Main Scanner ─────────────────────────────────────────────────────────────

def run_scan(target_url: str) -> ScanResult:
    result = ScanResult(
        target_url=target_url,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )
    start = time.time()

    # Normalize URL
    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url
        result.target_url = target_url

    # Fetch base response
    base_response = safe_get(target_url)
    if base_response is None:
        result.error = f"Unable to connect to {target_url}. Check the URL and your network connection."
        result.scan_duration = round(time.time() - start, 2)
        return result

    findings: List[Finding] = []

    # Run all checks
    sqli = check_sqli(target_url)
    if sqli:
        findings.append(sqli)

    xss = check_xss(target_url)
    if xss:
        findings.append(xss)

    findings.extend(check_security_headers(base_response))

    redirect = check_open_redirect(target_url)
    if redirect:
        findings.append(redirect)

    findings.extend(check_cookies(base_response))
    findings.extend(check_ssl(target_url))
    findings.extend(check_sensitive_files(target_url))

    dir_listing = check_directory_listing(target_url)
    if dir_listing:
        findings.append(dir_listing)

    clickjack = check_clickjacking(base_response)
    if clickjack:
        findings.append(clickjack)

    https_redir = check_https_redirect(target_url)
    if https_redir:
        findings.append(https_redir)

    # Deduplicate by name
    seen = set()
    unique = []
    for f in findings:
        if f.name not in seen:
            seen.add(f.name)
            unique.append(f)

    result.findings = sorted(unique, key=lambda x: -x.score)
    result.scan_duration = round(time.time() - start, 2)
    result.compute_risk()
    return result