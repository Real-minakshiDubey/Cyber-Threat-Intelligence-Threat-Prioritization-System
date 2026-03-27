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
├── dashboard/
│   └── app.py                  # Main Streamlit UI frontend
├── scanner/
│   ├── nmap_scanner.py         # Nmap port mapping logic
│   ├── config_scanner.py       # Local OS & package auditing
│   └── openvas.py              # OpenVAS Enterprise API wrapper
├── threat_intel/
│   └── aggregator.py           # Core logic merging VT, Shodan & AbuseIPDB
├── risk/
│   ├── risk_score.py           # CVSS metric mathematics
│   └── ml_model.py             # Feature engineering & ML risk prediction
├── data/
│   └── history.json            # Flat-file database for history/SQLite equivalent
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
