# SENTINEL - Cyber Risk Platform

> **Author**: Minakshi Dubey
> **Project Type**: Final Project

## Project Overview
Sentinel is an advanced, real-time vulnerability analysis and risk intelligence dashboard. It maps open ports and active threats onto a three-dimensional Risk Matrix (Exposure, Threat, Context) and evaluates against NIST CSF and OWASP Top 10 compliance standards. 

This project aligns exactly with the 3-page structural assignment requirements:
- **Page 1 (Overview)**: Current state summaries, critical condition banners, KPIs, and clear visual timeline/bar distributions instead of text-heavy tables.
- **Page 2 (Analytics)**: Deep-dive table views showcasing combined NMAP and VirusTotal metrics alongside historical heatmaps.
- **Page 3 (Reports/History)**: Dedicated interfaces to pull SQLite/JSON historical logs into audit-ready PDF formats.

---

## 🛠 Project Structure & Modularity

Per the assignment requirements, this application is written in a strictly **modular format**. It is NOT a single giant python script. The architecture is cleanly separated into specialized modules:

```text
Final_Project/
├── .env                        # Environment variables (Ignored in Git)
├── .gitignore                  # Git ignore configuration
├── dashboard/
│   └── app.py                  # Main Streamlit UI frontend
├── scanner/
│   ├── config_scanner.py       # Local OS & package vulnerability auditing
│   ├── nmap_scanner.py         # Nmap port mapping & service detection
│   └── openvas.py              # OpenVAS Enterprise API wrapper
├── threat_intel/
│   ├── abuseipdb.py            # AbuseIPDB API wrapper
│   ├── aggregator.py           # Core logic merging threat intelligence feeds
│   ├── nessus.py               # Nessus Scanner Integration API
│   ├── shodan.py               # Shodan API wrapper
│   └── virustotal.py           # VirusTotal API wrapper
├── risk/
│   ├── advanced_analysis.py    # Advanced risk metrics analysis
│   ├── analytics_engine.py     # Aggregation for historical dashboard metrics
│   ├── anomaly.py              # Detection of unusual risk patterns
│   ├── compliance.py           # OWASP Top 10 and NIST CSF compliance mapping
│   ├── explainability.py       # Risk score rationale extraction
│   ├── feature_engineering.py  # Feature preparation for ML
│   ├── ml_model.py             # Machine learning risk prediction engine
│   ├── normalization.py        # ML data normalization
│   ├── posture.py              # Overall system cybersecurity posture calculation
│   ├── prioritization.py       # Risk remediation prioritization
│   ├── reasoning.py            # Automated reasoning engine
│   └── risk_score.py           # CVSS metric mathematics and base scoring
├── utils/
│   ├── alerts.py               # Toast notifications for dashboard
│   ├── email_alert.py          # SMTP-based high risk email notifications
│   ├── helpers.py              # General utility components
│   ├── report.py               # FPDF2 engine for audit-ready PDF reports
│   └── storage.py              # SQLite storage for historical scan tracking
├── data/
│   └── sentinel.db             # SQLite Database for historical analytics tracking
└── main.py                     # CLI fallback runner
```

---

## ⚙️ Core Technologies & Tools Used

To achieve this, several powerful cybersecurity and data tools were integrated:

1. **[Nmap (Network Mapper)](https://nmap.org/)**: An open-source utility for network discovery and security auditing. We use the `python-nmap` library to asynchronously discover open services on a target IP.
2. **[VirusTotal API](https://www.virustotal.com/)**: Analyzes suspicious files, domains, and IPs to detect malware. Integrated to fetch real-time community threat scores and malicious voting history.
3. **[Streamlit](https://streamlit.io/)**: An open-source Python framework used to build and layout the interactive, dynamic frontend data dashboard quickly.
4. **[Paramiko](https://www.paramiko.org/)**: Used within our backend for authenticated SSH configuration auditing (`config_scanner.py`).

---

## 🎯 Target Sites Used for Testing
During development, the following targets were primarily utilized for safe, ethical scanning:
- `scanme.nmap.org`: The official Nmap project test server. It intentionally leaves several ports open to allow users to legally verify their port scanners work correctly.
- `1.1.1.1`: Cloudflare's public DNS. An excellent benchmark to test "Clean/Low Risk" integrations since it has minimal open ports and a flawless VirusTotal reputation.

---

## 🚀 How to Run the Project

1. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
2. **Launch the Dashboard**:
   ```bash
   streamlit run dashboard/app.py
   ```
3. **Run a Scan**: 
   - Wait for the dashboard to load in your browser.
   - Open the **Target Context** input inside the slide-out sidebar.
   - Enter your target IP (e.g., `127.0.0.1` or `scanme.nmap.org`).
   - Click **Initiate Scan**.

---

## 🔒 Security & Credentials Note
**CRITICAL**: My personal API keys (VirusTotal, Shodan) are kept completely secret.
-  **No credentials** have been uploaded to GitHub.
- All keys are safely managed using `.env` files.
- The `.env` file is explicitly ignored from source control using `.gitignore`.
- Additionally, the dashboard's Target Input functionality has been relocated directly into the side-panel so any viewers on the main page cannot maliciously misuse the backend keys.

---

## 📸 Project Screenshots

*(Replace the placeholder links below with actual screenshots of your dashboard)*

![Overview Page Dashboard](/path/to/overview_screenshot.png)
*Figure 1: The Overview page demonstrating the System Posture Banner and KPIs.*

![Analytics Page](/path/to/analytics_screenshot.png)
*Figure 2: The combined NMAP & Threat Intelligence detailed view.*
