"""
WebVulnScan — Streamlit Risk Dashboard
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import json
import os
from datetime import datetime

from scanner import run_scan, SEVERITY_SCORE
from alert import send_alert

# ── Page Config ──────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="WebVulnScan",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ────────────────────────────────────────────────────────────────

st.markdown("""
<style>
  /* Dark sidebar */
  [data-testid="stSidebar"] { background: #1a1a2e; }
  [data-testid="stSidebar"] * { color: #e0e0e0 !important; }
  [data-testid="stSidebar"] .stButton>button {
    background: #e94560; color: white; border: none;
    border-radius: 6px; font-weight: bold; width: 100%;
  }
  [data-testid="stSidebar"] .stButton>button:hover { background: #c0392b; }

  /* Metric cards */
  [data-testid="metric-container"] {
    background: #1e1e2e;
    border: 1px solid #333;
    border-radius: 10px;
    padding: 16px;
    color: white;
  }
  [data-testid="metric-container"] label { color: #aaa !important; }
  [data-testid="metric-container"] [data-testid="stMetricValue"] { color: white !important; font-size: 2rem !important; }

  /* General */
  .main .block-container { padding-top: 1.5rem; padding-bottom: 2rem; }
  h1, h2, h3 { color: #1a1a2e; }

  /* Severity badges */
  .badge-Critical { background:#c0392b;color:#fff;padding:3px 10px;border-radius:20px;font-size:12px;font-weight:bold; }
  .badge-High     { background:#e67e22;color:#fff;padding:3px 10px;border-radius:20px;font-size:12px;font-weight:bold; }
  .badge-Medium   { background:#f39c12;color:#fff;padding:3px 10px;border-radius:20px;font-size:12px;font-weight:bold; }
  .badge-Low      { background:#27ae60;color:#fff;padding:3px 10px;border-radius:20px;font-size:12px;font-weight:bold; }
  .badge-Informational { background:#3498db;color:#fff;padding:3px 10px;border-radius:20px;font-size:12px;font-weight:bold; }

  /* Finding cards */
  .finding-card {
    border-left: 4px solid #e94560;
    background: #f9f9ff;
    padding: 12px 16px;
    border-radius: 6px;
    margin-bottom: 10px;
  }
  .risk-gauge-label { text-align:center; font-size:1.1rem; font-weight:bold; margin-top:-10px; }
</style>
""", unsafe_allow_html=True)


# ── Sidebar ───────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("## 🛡️ WebVulnScan")
    st.markdown("---")
    st.markdown("### 🎯 Target Configuration")

    target_url = st.text_input(
        "Target URL",
        placeholder="https://testphp.vulnweb.com",
        help="Only scan test/lab sites you are authorized to test."
    )

    st.markdown("### 📧 Email Alert Settings")
    enable_email = st.checkbox("Enable Email Alerts", value=False)

    smtp_host = st.text_input("SMTP Host", value="smtp.gmail.com", disabled=not enable_email)
    smtp_port = st.selectbox("SMTP Port", [587, 465, 25], disabled=not enable_email)
    smtp_user = st.text_input("SMTP Username / Email", disabled=not enable_email)
    smtp_pass = st.text_input("SMTP Password / App Password",
                              type="password", disabled=not enable_email)
    recipient  = st.text_input("Alert Recipient Email", disabled=not enable_email)

    st.markdown("---")
    scan_btn = st.button("🔍 Start Scan", use_container_width=True)
    st.markdown("---")
    st.markdown("""
    <small style='color:#888;'>
    ⚠️ <b>Legal Notice:</b> Only scan websites you own or have explicit written permission to test.
    Unauthorized scanning is illegal and strictly prohibited.
    </small>
    """, unsafe_allow_html=True)


# ── Session State ─────────────────────────────────────────────────────────────

if "scan_result" not in st.session_state:
    st.session_state.scan_result = None
if "email_result" not in st.session_state:
    st.session_state.email_result = None
if "scan_history" not in st.session_state:
    st.session_state.scan_history = []


# ── Scan Trigger ─────────────────────────────────────────────────────────────

if scan_btn:
    if not target_url.strip():
        st.sidebar.error("Please enter a target URL.")
    else:
        with st.spinner(f"Scanning {target_url} …"):
            result = run_scan(target_url.strip())
            st.session_state.scan_result = result
            st.session_state.email_result = None

            # Auto-trigger email if enabled
            if enable_email and smtp_user and smtp_pass and recipient:
                email_result = send_alert(
                    result, smtp_host, int(smtp_port),
                    smtp_user, smtp_pass, recipient
                )
                st.session_state.email_result = email_result

            # Save to history
            st.session_state.scan_history.append({
                "url": result.target_url,
                "timestamp": result.timestamp,
                "risk": result.overall_risk_score,
                "level": result.risk_level,
                "findings": len(result.findings),
            })


# ── Main Dashboard ────────────────────────────────────────────────────────────

result = st.session_state.scan_result

# ── Hero Header ──────────────────────────────────────────────────────────────
st.markdown("""
<div style="background:linear-gradient(135deg,#1a1a2e,#16213e);
            padding:28px 32px;border-radius:12px;margin-bottom:24px;">
  <h1 style="color:#e94560;margin:0;font-size:2rem;">🛡️ WebVulnScan</h1>
  <p style="color:#aaa;margin:6px 0 0;font-size:14px;">
    Web Application Vulnerability Scanner &amp; Risk Dashboard
  </p>
</div>
""", unsafe_allow_html=True)

# ── No Scan Yet ───────────────────────────────────────────────────────────────
if result is None:
    col1, col2, col3 = st.columns(3)
    with col1:
        st.info("**Step 1** — Enter a target URL in the sidebar")
    with col2:
        st.info("**Step 2** — Optionally configure email alerts")
    with col3:
        st.info("**Step 3** — Click **Start Scan** to begin")

    st.markdown("---")
    st.markdown("### 🔎 What We Check")
    checks = [
        ("🔴 SQL Injection", "Error-based detection via crafted payloads"),
        ("🟠 Cross-Site Scripting (XSS)", "Reflected XSS via common script payloads"),
        ("🟡 Security Headers", "HSTS, CSP, X-Frame-Options, and more"),
        ("🟡 Open Redirect", "URL parameter-based redirect probing"),
        ("🟡 Cookie Security", "HttpOnly, Secure, SameSite flags"),
        ("🔴 SSL / TLS Issues", "Certificate validity, weak protocols"),
        ("🟠 Sensitive File Exposure", ".env, .git, phpinfo, admin paths"),
        ("🟡 Directory Listing", "Enabled directory browsing"),
        ("🟡 Clickjacking", "iframe embedding protection check"),
        ("🟡 HTTPS Redirect", "HTTP to HTTPS enforcement"),
    ]
    col_a, col_b = st.columns(2)
    for i, (name, desc) in enumerate(checks):
        with (col_a if i % 2 == 0 else col_b):
            st.markdown(f"**{name}**  \n{desc}")
    st.stop()

# ── Error State ───────────────────────────────────────────────────────────────
if result.error:
    st.error(f"**Scan Error:** {result.error}")
    st.stop()


# ── Severity Color Map ────────────────────────────────────────────────────────
SEV_COLORS = {
    "Critical": "#c0392b",
    "High":     "#e67e22",
    "Medium":   "#f1c40f",
    "Low":      "#27ae60",
    "Informational": "#3498db",
}
sev_order = ["Critical", "High", "Medium", "Low", "Informational"]

findings = result.findings
df = pd.DataFrame([{
    "Vulnerability": f.name,
    "Severity": f.severity,
    "Score": f.score,
    "Description": f.description,
    "Recommendation": f.recommendation,
    "Evidence": f.evidence,
} for f in findings])


# ── KPI Row ───────────────────────────────────────────────────────────────────
st.markdown(f"**Target:** `{result.target_url}`  •  **Scanned:** {result.timestamp}  •  **Duration:** {result.scan_duration}s")
st.markdown("---")

k1, k2, k3, k4, k5 = st.columns(5)
k1.metric("Overall Risk Score", f"{result.overall_risk_score}/100", delta=result.risk_level)
k2.metric("Total Findings", len(findings))
k3.metric("Critical", sum(1 for f in findings if f.severity == "Critical"))
k4.metric("High", sum(1 for f in findings if f.severity == "High"))
k5.metric("Medium", sum(1 for f in findings if f.severity == "Medium"))


# ── Email Status Banner ───────────────────────────────────────────────────────
er = st.session_state.email_result
if er:
    if er["sent"]:
        st.success(f"📧 {er['message']}")
    else:
        if er["alert_count"] > 0:
            st.warning(f"📧 Email not sent: {er['message']}")
        else:
            st.info(f"📧 {er['message']}")

st.markdown("---")


# ── Row 2: Gauge + Pie + Bar ──────────────────────────────────────────────────
col_gauge, col_pie, col_bar = st.columns([1.2, 1.2, 1.6])

# Gauge
with col_gauge:
    st.markdown("#### 🎯 Risk Gauge")
    gauge_color = SEV_COLORS.get(result.risk_level, "#555")
    fig_gauge = go.Figure(go.Indicator(
        mode="gauge+number",
        value=result.overall_risk_score,
        domain={"x": [0, 1], "y": [0, 1]},
        title={"text": f"Risk Level: {result.risk_level}", "font": {"size": 14}},
        gauge={
            "axis": {"range": [0, 100], "tickwidth": 1},
            "bar": {"color": gauge_color},
            "steps": [
                {"range": [0, 30],  "color": "#d5f5e3"},
                {"range": [30, 50], "color": "#fef9e7"},
                {"range": [50, 70], "color": "#fdebd0"},
                {"range": [70, 100],"color": "#fadbd8"},
            ],
            "threshold": {
                "line": {"color": "red", "width": 3},
                "thickness": 0.75,
                "value": result.overall_risk_score
            }
        }
    ))
    fig_gauge.update_layout(height=260, margin=dict(t=40, b=0, l=20, r=20))
    st.plotly_chart(fig_gauge, use_container_width=True)

# Pie
with col_pie:
    st.markdown("#### 📊 Severity Distribution")
    sev_counts = df["Severity"].value_counts().reindex(sev_order).dropna()
    fig_pie = px.pie(
        names=sev_counts.index,
        values=sev_counts.values,
        color=sev_counts.index,
        color_discrete_map=SEV_COLORS,
        hole=0.45,
    )
    fig_pie.update_traces(textposition="inside", textinfo="percent+label")
    fig_pie.update_layout(height=260, margin=dict(t=20, b=0), showlegend=False)
    st.plotly_chart(fig_pie, use_container_width=True)

# Horizontal bar
with col_bar:
    st.markdown("#### 🔢 Findings by Severity")
    sev_counts_full = df["Severity"].value_counts().reindex(sev_order, fill_value=0)
    fig_bar = px.bar(
        x=sev_counts_full.values,
        y=sev_counts_full.index,
        orientation="h",
        color=sev_counts_full.index,
        color_discrete_map=SEV_COLORS,
        text=sev_counts_full.values,
    )
    fig_bar.update_traces(textposition="outside")
    fig_bar.update_layout(
        height=260,
        margin=dict(t=10, b=0, l=0, r=40),
        showlegend=False,
        xaxis_title="Count",
        yaxis_title="",
        plot_bgcolor="rgba(0,0,0,0)",
    )
    st.plotly_chart(fig_bar, use_container_width=True)


# ── Row 3: Score heatmap-style table + Radar ──────────────────────────────────
st.markdown("---")
col_tbl, col_radar = st.columns([1.8, 1.2])

with col_tbl:
    st.markdown("#### 📋 All Findings")
    if not df.empty:
        # Color-coded table
        def color_severity(val):
            colors = {
                "Critical": "background-color:#fadbd8;color:#c0392b;font-weight:bold",
                "High":     "background-color:#fdebd0;color:#e67e22;font-weight:bold",
                "Medium":   "background-color:#fef9e7;color:#d68910",
                "Low":      "background-color:#d5f5e3;color:#1e8449",
                "Informational": "background-color:#d6eaf8;color:#1a5276",
            }
            return colors.get(val, "")

        display_df = df[["Vulnerability", "Severity", "Score"]].copy()
        styled = display_df.style.applymap(color_severity, subset=["Severity"])
        st.dataframe(styled, use_container_width=True, height=300)
    else:
        st.success("No vulnerabilities found!")

with col_radar:
    st.markdown("#### 🕸️ Risk Radar")
    cats = ["Injection", "Headers", "Cookies", "SSL/TLS", "Exposure", "Config"]
    def category_score(category_keywords, findings):
        total = 0
        for f in findings:
            n = f.name.lower()
            if any(kw in n for kw in category_keywords):
                total += f.score
        return min(total, 10)

    radar_vals = [
        category_score(["sql", "xss", "injection", "redirect"], findings),
        category_score(["header", "csp", "hsts", "x-frame", "referrer", "permissions"], findings),
        category_score(["cookie"], findings),
        category_score(["ssl", "tls", "https", "certificate"], findings),
        category_score(["file", "directory", "listing", "exposed"], findings),
        category_score(["clickjack", "redirect", "config"], findings),
    ]

    fig_radar = go.Figure(go.Scatterpolar(
        r=radar_vals + [radar_vals[0]],
        theta=cats + [cats[0]],
        fill="toself",
        fillcolor="rgba(233,69,96,0.25)",
        line=dict(color="#e94560", width=2),
    ))
    fig_radar.update_layout(
        polar=dict(radialaxis=dict(visible=True, range=[0, 10])),
        height=300,
        margin=dict(t=20, b=20, l=20, r=20),
        showlegend=False,
    )
    st.plotly_chart(fig_radar, use_container_width=True)


# ── Row 4: Detailed Finding Cards ─────────────────────────────────────────────
st.markdown("---")
st.markdown("#### 🔍 Detailed Findings")

sev_filter = st.multiselect(
    "Filter by Severity",
    options=sev_order,
    default=sev_order,
)

filtered = [f for f in findings if f.severity in sev_filter]

if not filtered:
    st.info("No findings match the selected filters.")
else:
    for f in filtered:
        color = SEV_COLORS.get(f.severity, "#555")
        with st.expander(f"{'🔴' if f.severity=='Critical' else '🟠' if f.severity=='High' else '🟡' if f.severity=='Medium' else '🟢' if f.severity=='Low' else '🔵'} {f.name}  —  {f.severity} (Score: {f.score}/10)", expanded=(f.severity in ("Critical","High"))):
            c1, c2 = st.columns([1, 1])
            with c1:
                st.markdown(f"**📝 Description**  \n{f.description}")
                if f.evidence:
                    st.markdown(f"**🔎 Evidence**  \n`{f.evidence}`")
            with c2:
                st.markdown(f"**✅ Recommendation**  \n{f.recommendation}")


# ── Row 5: Scan History ───────────────────────────────────────────────────────
if len(st.session_state.scan_history) > 1:
    st.markdown("---")
    st.markdown("#### 📈 Scan History (This Session)")
    hist_df = pd.DataFrame(st.session_state.scan_history)
    fig_hist = px.line(
        hist_df, x="timestamp", y="risk",
        markers=True, text="level",
        labels={"timestamp": "Scan Time", "risk": "Risk Score"},
        color_discrete_sequence=["#e94560"],
    )
    fig_hist.update_traces(textposition="top center")
    fig_hist.update_layout(height=220, margin=dict(t=10, b=30))
    st.plotly_chart(fig_hist, use_container_width=True)


# ── Row 6: Export ─────────────────────────────────────────────────────────────
st.markdown("---")
st.markdown("#### 💾 Export Results")
exp1, exp2 = st.columns(2)

with exp1:
    if not df.empty:
        csv = df.to_csv(index=False)
        st.download_button(
            "⬇️ Download CSV Report",
            data=csv,
            file_name=f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
        )

with exp2:
    export_data = {
        "target": result.target_url,
        "timestamp": result.timestamp,
        "risk_score": result.overall_risk_score,
        "risk_level": result.risk_level,
        "scan_duration_s": result.scan_duration,
        "findings": [
            {"name": f.name, "severity": f.severity, "score": f.score,
             "description": f.description, "recommendation": f.recommendation,
             "evidence": f.evidence}
            for f in findings
        ]
    }
    st.download_button(
        "⬇️ Download JSON Report",
        data=json.dumps(export_data, indent=2),
        file_name=f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
        mime="application/json",
    )