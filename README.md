# SENTINEL - Cyber Risk Platform

> **Author**: Minakshi Dubey
> **Project Type**: Final Project

## Project Overview
Sentinel is an advanced, real-time vulnerability analysis and risk intelligence dashboard. It maps open ports and active threats onto a three-dimensional Risk Matrix (Exposure, Threat, Context) and evaluates against NIST CSF and OWASP Top 10 compliance standards. 

This project organizes the platform into 4 main interfaces:
- **Page 1 (Overview)**: Current state summaries, critical condition banners, KPIs, and clear visual timeline/bar distributions instead of text-heavy tables.
- **Page 2 (Scan Report)**: Deep-dive detailed operational views showcasing combined NMAP surface features and VirusTotal metrics for each target.
- **Page 3 (History)**: Dedicated tracking of SQLite historical logs, trend analytics, and risk heatmap distributions over time.
- **Page 4 (Analytics)**: Interactive Multi-dimensional threat visualizations built from the full cross-target scan history.
- **Page 5 (Reports)**: Interactive interface to configure parameters and generate audit-ready, downloadable PDF formats mapping results to OWASP and NIST.

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

1. **[Nmap (Network Mapper)](https://nmap.org/)**: An open-source utility for network discovery. We use `python-nmap` to asynchronously discover open services on a target IP.
2. **[VirusTotal API](https://www.virustotal.com/)**: Analyzes suspicious files and IPs to detect malware, fetching real-time community threat scores.
3. **[Shodan API](https://www.shodan.io/)**: The search engine for Internet-connected devices. Used to verify a target's global exposure footprint (organization, country, and publicly charted CVEs).
4. **[AbuseIPDB API](https://www.abuseipdb.com/)**: Integrated to generate a secondary confidence metric identifying if the IP has been reported for abusive network behavior (spam, hacking).
5. **[Nessus & OpenVAS Integrations](https://www.tenable.com/products/nessus)**: Enterprise vulnerability scanning APIs integrated into the data aggregator for deep threat assessment workflows.
6. **[Paramiko](https://www.paramiko.org/)**: Used for authenticated SSH OS-level configuration auditing (extracting installed packages and vulnerable configs) via `config_scanner.py`.
7. **[Streamlit](https://streamlit.io/)**: The open-source Python framework powering the interactive, dynamic, multi-tab frontend data dashboard.
8. **[SQLite & Pandas](https://pandas.pydata.org/)**: For saving, tracking, and historically visualizing scan intelligence over time in the History tab.
9. **[FPDF2](https://pyfpdf.github.io/fpdf2/)**: Generating audit-ready, standalone PDF compliance reports mapped to NIST CSF and OWASP.

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

<img width="1900" height="791" alt="image" src="https://github.com/user-attachments/assets/5139ea12-4136-4b15-96c7-9583ba0112dc" />
*Figure 1: Overview — System Posture Banner, KPIs, and risk distribution charts.*


<img width="1876" height="794" alt="image" src="https://github.com/user-attachments/assets/475ef15b-a9a9-4a68-a356-b137fb30351f" />
*Figure 2: Scan Report — Per-target result card with ports, threat intel, and compliance hits.*


<img width="1875" height="790" alt="image" src="https://github.com/user-attachments/assets/9b8c3431-6928-456a-af4d-2b6bc60a9cd7" />
*Figure 3: History — Trend analytics, heatmap, and SQLite history table*


<img width="1875" height="797" alt="image" src="https://github.com/user-attachments/assets/4f3742e5-d115-4076-b25b-d1b07e8e2a89" />
*Figure 4: Analytics — Multi-dimensional threat visualizations across all scanned targets.*


<img width="1872" height="794" alt="image" src="https://github.com/user-attachments/assets/51d52805-b339-4584-8653-f6af91c96886" />
*Figure 5: Generated PDF report with OWASP Top 10 and NIST CSF compliance mapping.*
