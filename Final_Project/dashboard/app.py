import sys
import os
import socket
import time
import json
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from scanner.nmap_scanner import scan_target
from scanner.config_scanner import scan_system_config
from threat_intel.aggregator import get_combined_threat_data
from risk.feature_engineering import extract_features
from risk.ml_model import predict_risk, confidence_score
from risk.anomaly import detect_anomaly
from risk.posture import calculate_posture
from risk.compliance import get_compliance_mapping
from utils.storage import save_scan, get_all_scans, clear_scans
from utils.alerts import generate_alert
from utils.report import generate_pdf
from utils.email_alert import send_email_alert

from risk.analytics_engine import (
    prepare_dataframe,
    get_summary_stats,
    get_top_risky,
    get_ip_risk,
    get_distribution
)

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def resolve_to_ip(target):
    try:
        return socket.gethostbyname(target)
    except:
        return target

# ─────────────────────────────────────────────────────────────────────────────
# PAGE CONFIG
# ─────────────────────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="SENTINEL — Cyber Risk Platform",
    page_icon="⬡",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ─────────────────────────────────────────────────────────────────────────────
# GLOBAL CSS — dark terminal aesthetic, IBM Plex Mono + Syne
# ─────────────────────────────────────────────────────────────────────────────

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@300;400;500;600&family=Syne:wght@400;600;700;800&display=swap');

html, body, [class*="css"] {
    font-family: 'IBM Plex Mono', monospace;
    background-color: #080c10;
    color: #c8d6e5;
}
.stApp {
    background-color: #080c10;
    background-image:
        linear-gradient(rgba(0,245,212,0.015) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0,245,212,0.015) 1px, transparent 1px);
    background-size: 40px 40px;
}
::-webkit-scrollbar { width: 4px; }
::-webkit-scrollbar-track { background: #0d1117; }
::-webkit-scrollbar-thumb { background: #00f5d4; border-radius: 2px; }

[data-testid="stSidebar"] {
    background: #0a0f15 !important;
    border-right: 1px solid #1a2535;
}
[data-testid="stSidebar"] .stRadio label {
    font-family: 'IBM Plex Mono', monospace !important;
    font-size: 11px !important;
    color: #7a9bb5 !important;
    text-transform: uppercase;
    letter-spacing: 0.15em;
    padding: 0.5rem 0.75rem !important;
    border-radius: 4px !important;
    transition: all 0.2s ease !important;
    margin-bottom: 4px !important;
}
[data-testid="stSidebar"] .stRadio label:hover { 
    background: #00f5d4 !important;
    box-shadow: 0 0 20px rgba(0,245,212,0.3) !important;
}
[data-testid="stSidebar"] .stRadio label:hover * {
    color: #080c10 !important;
    font-weight: 700 !important;
    text-shadow: none !important;
}

.block-container { padding: 2rem 2.5rem 4rem; max-width: 1400px; }

.sentinel-title {
    font-family: 'Syne', sans-serif;
    font-size: 40px;
    font-weight: 800;
    letter-spacing: -0.02em;
    color: #e8f4fd;
    line-height: 1;
    margin-top: 2.5rem;
    margin-bottom: 4px;
}
.sentinel-subtitle {
    font-size: 10px;
    color: #3a5a7a;
    letter-spacing: 0.25em;
    text-transform: uppercase;
    margin-bottom: 2rem;
}
.sentinel-accent { color: #00f5d4; }

.sec-label {
    font-size: 10px;
    letter-spacing: 0.3em;
    text-transform: uppercase;
    color: #00f5d4;
    margin-bottom: 0.75rem;
    padding-bottom: 6px;
    border-bottom: 1px solid #1a2535;
}

[data-testid="stMetric"] {
    background: #0d1520;
    border: 1px solid #1a2535;
    border-radius: 8px;
    padding: 1rem 1.25rem;
}
[data-testid="stMetricLabel"] {
    font-size: 10px !important;
    letter-spacing: 0.2em;
    text-transform: uppercase;
    color: #3a5a7a !important;
}
[data-testid="stMetricValue"] {
    font-family: 'Syne', sans-serif !important;
    font-size: 24px !important;
    font-weight: 700 !important;
    color: #e8f4fd !important;
}

.stButton > button {
    font-family: 'IBM Plex Mono', monospace !important;
    font-size: 11px !important;
    font-weight: 600 !important;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    background: transparent !important;
    color: #00f5d4 !important;
    border: 1px solid #00f5d4 !important;
    border-radius: 4px !important;
    padding: 0.5rem 1.5rem !important;
    transition: all 0.2s ease;
}
.stButton > button:hover {
    background: #00f5d4 !important;
    color: #080c10 !important;
    box-shadow: 0 0 20px rgba(0,245,212,0.3) !important;
}

.stTextInput > div > div > input,
.stTextArea > div > div > textarea,
.stNumberInput > div > div > input {
    background: #0d1520 !important;
    border: 1px solid #1a2535 !important;
    border-radius: 6px !important;
    color: #c8d6e5 !important;
    font-family: 'IBM Plex Mono', monospace !important;
    font-size: 13px !important;
}
.stTextInput > div > div > input:focus,
.stTextArea > div > div > textarea:focus {
    border-color: #00f5d4 !important;
    box-shadow: 0 0 0 1px #00f5d4 !important;
}

.stSelectbox > div > div, .stMultiSelect > div > div {
    background: #0d1520 !important;
    border: 1px solid #1a2535 !important;
    color: #c8d6e5 !important;
    font-family: 'IBM Plex Mono', monospace !important;
}
.stCheckbox label {
    font-size: 12px !important;
    letter-spacing: 0.1em;
    color: #7a9bb5 !important;
}
hr { border-color: #1a2535 !important; margin: 1.5rem 0 !important; }

.risk-badge {
    display: inline-block;
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 0.2em;
    text-transform: uppercase;
    padding: 3px 10px;
    border-radius: 3px;
}
.risk-high { background: rgba(255,56,96,0.15); color: #ff3860; border: 1px solid rgba(255,56,96,0.4); }
.risk-med  { background: rgba(255,221,87,0.1);  color: #ffdd57; border: 1px solid rgba(255,221,87,0.4); }
.risk-low  { background: rgba(35,209,96,0.1);   color: #23d160; border: 1px solid rgba(35,209,96,0.4); }

.terminal-box {
    background: #050810;
    border: 1px solid #1a2535;
    border-left: 3px solid #00f5d4;
    border-radius: 4px;
    padding: 1rem 1.25rem;
    font-size: 12px;
    line-height: 1.9;
    color: #7a9bb5;
    margin-bottom: 1rem;
}
.t-green  { color: #23d160; }
.t-cyan   { color: #00f5d4; }
.t-red    { color: #ff3860; }
.t-yellow { color: #ffdd57; }
.t-white  { color: #e8f4fd; }

.port-row {
    display: flex;
    align-items: center;
    gap: 1rem;
    padding: 6px 0;
    border-bottom: 1px solid #0f1922;
    font-size: 12px;
}
.port-num  { color: #00f5d4; width: 60px; font-weight: 600; }
.port-svc  { color: #c8d6e5; flex: 1; }
.port-pill { font-size: 9px; letter-spacing: 0.15em; padding: 2px 8px; border-radius: 2px; }

.dot { display: inline-block; width: 6px; height: 6px; border-radius: 50%; margin-right: 6px; }
.dot-green  { background: #23d160; box-shadow: 0 0 6px #23d160; }
.dot-yellow { background: #ffdd57; box-shadow: 0 0 6px #ffdd57; }
.dot-red    { background: #ff3860; box-shadow: 0 0 6px #ff3860; }

.sidebar-logo {
    font-family: 'Syne', sans-serif;
    font-size: 20px;
    font-weight: 800;
    color: #00f5d4;
    letter-spacing: 0.05em;
    padding: 0.5rem 0 0.25rem;
}
.sidebar-tagline {
    font-size: 9px;
    color: #3a5a7a;
    letter-spacing: 0.2em;
    text-transform: uppercase;
    margin-bottom: 1.5rem;
}

.stDownloadButton > button {
    font-family: 'IBM Plex Mono', monospace !important;
    font-size: 11px !important;
    letter-spacing: 0.1em;
    background: transparent !important;
    color: #7a9bb5 !important;
    border: 1px solid #1a2535 !important;
    border-radius: 4px !important;
}
.stDownloadButton > button:hover {
    border-color: #00f5d4 !important;
    color: #00f5d4 !important;
}
.streamlit-expanderHeader {
    background: #0d1520 !important;
    border: 1px solid #1a2535 !important;
    font-family: 'IBM Plex Mono', monospace !important;
    font-size: 11px !important;
    color: #7a9bb5 !important;
    letter-spacing: 0.08em;
}
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# PLOTLY THEME
# ─────────────────────────────────────────────────────────────────────────────

PLOTLY_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(family="IBM Plex Mono", color="#7a9bb5", size=11),
    title_font=dict(family="Syne", color="#e8f4fd", size=14),
    xaxis=dict(gridcolor="#1a2535", zerolinecolor="#1a2535", color="#7a9bb5"),
    yaxis=dict(gridcolor="#1a2535", zerolinecolor="#1a2535", color="#7a9bb5"),
    margin=dict(l=16, r=16, t=40, b=16),
    colorway=["#00f5d4", "#ff3860", "#ffdd57", "#3273dc", "#9b59b6"],
)

def styled_chart(fig):
    fig.update_layout(**PLOTLY_LAYOUT)
    return fig

def clean_df_for_display(df):
    """Replace open_ports list-of-dicts with a readable port string."""
    import json
    df = df.copy()
    if "open_ports" in df.columns:
        def fmt_ports(val):
            if isinstance(val, list):
                return ", ".join(f":{p.get('port','')} ({p.get('service','')})" for p in val) if val else "—"
            if isinstance(val, str):
                try:
                    parsed = json.loads(val)
                    return ", ".join(f":{p.get('port','')} ({p.get('service','')})" for p in parsed) if parsed else "—"
                except Exception:
                    return val
            return "—"
        df["open_ports"] = df["open_ports"].apply(fmt_ports)
    return df

# ─────────────────────────────────────────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown('<div class="sidebar-logo">⬡ SENTINEL</div>', unsafe_allow_html=True)
    st.markdown('<div class="sidebar-tagline">Cyber Risk Intelligence Platform</div>', unsafe_allow_html=True)
    st.markdown("---")

    page = st.radio(
        "nav",
        ["◈  OVERVIEW", "⬡  SCAN REPORT", "◉  HISTORY", "◂  ANALYTICS", "▣  REPORTS"],
        label_visibility="collapsed"
    )

    st.markdown("---")
    st.markdown('<div style="font-size:10px;color:#3a5a7a;letter-spacing:0.15em;text-transform:uppercase;margin-bottom:8px;">Target Context</div>', unsafe_allow_html=True)
    targets = st.text_area(
        "targets",
        placeholder="45.33.32.156, scanme.nmap.org",
        height=80,
        label_visibility="collapsed"
    )
    monitoring = st.checkbox("⟳  Monitor (3 cycles)")
    run_scan = st.button("⬡  INITIATE SCAN", use_container_width=True)

    st.markdown("---")
    st.markdown('<div class="sidebar-logo" style="font-size:12px; margin-bottom: 2px;">Filter Results</div>', unsafe_allow_html=True)
    try:
        _sb_scans = get_all_scans()
        _sb_ips = ["All"] + sorted(list(set(s["ip"] for s in _sb_scans if "ip" in s)))
    except Exception:
        _sb_ips = ["All"]
    
    st.markdown('<div style="font-size:10px;color:#3a5a7a;letter-spacing:0.1em;text-transform:uppercase;margin:4px 0;">Target Filter</div>', unsafe_allow_html=True)
    selected_ip_filter = st.selectbox("Target Option", _sb_ips, label_visibility="collapsed")

    st.markdown('<div style="font-size:10px;color:#3a5a7a;letter-spacing:0.1em;text-transform:uppercase;margin:8px 0 4px;">Service Filter</div>', unsafe_allow_html=True)
    selected_service_filter = st.selectbox("Service Option", ["All", "http", "https", "ssh", "ftp", "telnet"], label_visibility="collapsed")
    
    st.markdown('<div style="font-size:10px;color:#3a5a7a;letter-spacing:0.1em;text-transform:uppercase;margin:8px 0 4px;">Severity Filter</div>', unsafe_allow_html=True)
    selected_severity_filter = st.multiselect(
        "Severity Tracker",
        ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        label_visibility="collapsed"
    )

    st.markdown("---")
    st.markdown(
        '<div style="font-size:10px;color:#3a5a7a;letter-spacing:0.15em;text-transform:uppercase;margin-bottom:8px;">System Status</div>'
        '<div style="font-size:11px;line-height:2.2;">'
        '<span class="dot dot-green"></span><span style="color:#7a9bb5">VirusTotal API</span><br>'
        '<span class="dot dot-green"></span><span style="color:#7a9bb5">AbuseIPDB API</span><br>'
        '<span class="dot dot-yellow"></span><span style="color:#7a9bb5">Shodan API</span><br>'
        '<span class="dot dot-green"></span><span style="color:#7a9bb5">Nmap Engine</span>'
        '</div>',
        unsafe_allow_html=True
    )

# ── Global Helper for filtering history exactly as chosen ──
def filter_history_records(records):
    filtered = []
    for s in records:
        if selected_ip_filter != "All" and s.get("ip") != selected_ip_filter: continue
        if selected_severity_filter and s.get("level", "INFO") not in selected_severity_filter: continue
        if selected_service_filter != "All":
            if not any(p.get("service") == selected_service_filter for p in s.get("open_ports", [])):
                continue
        filtered.append(s)
    return filtered

# ─────────────────────────────────────────────────────────────────────────────
# PAGE: SCAN (OVERVIEW)
# ─────────────────────────────────────────────────────────────────────────────

if "OVERVIEW" in page:

    st.markdown('<div class="sentinel-title">⬡ Sentinel <span class="sentinel-accent">Overview</span></div>', unsafe_allow_html=True)
    st.markdown('<div class="sentinel-subtitle">■ Current data status and system intelligence (Filters Applied)</div>', unsafe_allow_html=True)

    try:
        raw_hist = get_all_scans()
        _ov_hist = filter_history_records(raw_hist)
        
        if _ov_hist:
            _ov_posture = calculate_posture(_ov_hist)
            _ov_bc = {"POOR": "#ff3860", "MODERATE": "#ffdd57", "GOOD": "#23d160"}.get(_ov_posture, "#3a5a7a")
            _ov_rgb = f"{int(_ov_bc[1:3],16)},{int(_ov_bc[3:5],16)},{int(_ov_bc[5:7],16)}"
            st.markdown(
                f'<div style="background:rgba({_ov_rgb},0.12);border-left:4px solid {_ov_bc};'
                f'border-radius:4px;padding:10px 16px;margin-bottom:12px;">'
                f'<span style="color:{_ov_bc};font-weight:bold;letter-spacing:0.1em;">OVERALL SYSTEM POSTURE: {_ov_posture}</span></div>',
                unsafe_allow_html=True
            )
            _ov_df = prepare_dataframe(_ov_hist).tail(20)
            if not _ov_df.empty:
                _ov_stats = get_summary_stats(_ov_df)
                _ov_anomaly = detect_anomaly(_ov_hist)
                if _ov_anomaly:
                    st.markdown(f'<div class="terminal-box"><span class="t-red">[ ANOMALY ]</span> <span class="t-white">{_ov_anomaly}</span></div>', unsafe_allow_html=True)
                
                ov1, ov2, ov3, ov4, ov5 = st.columns(5)
                ov1.metric("Avg Risk",    round(_ov_stats["avg_score"], 1))
                ov2.metric("Max Risk",    _ov_stats["max_score"])
                ov3.metric("Min Risk",    _ov_stats["min_score"])
                ov4.metric("Filtered Scans", _ov_stats["total_scans"])
                ov5.metric("Posture",     _ov_posture)
                
                st.markdown('<div class="sec-label" style="margin-top:10px;">Intelligence Overview</div>', unsafe_allow_html=True)
                ovc1, ovc2, ovc3 = st.columns(3)
                with ovc1:
                    _ov_fl = px.area(_ov_df, y="score", title="Risk Over Time", color_discrete_sequence=["#00f5d4"])
                    _ov_fl.update_traces(line_color="#00f5d4", fillcolor="rgba(0,245,212,0.07)")
                    st.plotly_chart(styled_chart(_ov_fl), use_container_width=True, key="ov_line")
                with ovc2:
                    _ov_dist = get_distribution(_ov_df)
                    _ov_pie = px.pie(names=list(_ov_dist.keys()), values=list(_ov_dist.values()),
                                     hole=0.55, title="Risk Distribution",
                                     color=list(_ov_dist.keys()),
                                     color_discrete_map={"HIGH":"#ff3860","MEDIUM":"#ffdd57","LOW":"#23d160"})
                    st.plotly_chart(styled_chart(_ov_pie), use_container_width=True, key="ov_pie")
                with ovc3:
                    _ov_ip = get_ip_risk(_ov_df)
                    _ov_bar = px.bar(_ov_ip, x="ip", y="score", title="Avg Risk by IP",
                                     color="score", color_continuous_scale=[[0,"#23d160"],[0.5,"#ffdd57"],[1,"#ff3860"]])
                    _ov_bar.update_traces(marker_line_width=0)
                    st.plotly_chart(styled_chart(_ov_bar), use_container_width=True, key="ov_bar")
        else:
            st.markdown('<div class="terminal-box"><span class="t-yellow">[ READY ]</span> <span class="t-white">No data matches current filters or no scan history.</span></div>', unsafe_allow_html=True)
    except Exception as _ov_e:
        st.markdown(f'<div class="terminal-box"><span class="t-red">[ ERR ]</span> {_ov_e}</div>', unsafe_allow_html=True)

    st.markdown("---")

    # ── helper: render one host result ───────────────────────────────────────
    def render_host_result(r):
        host        = r["host"]
        threat      = r["threat"]
        level       = r["level"]
        score       = r["score"]
        conf        = r["conf"]
        compliance  = r["compliance"]
        config_data = r["config_data"]
        ip          = host["ip"]
        malicious   = threat["malicious"]
        suspicious  = threat["suspicious"]
        abuse_score = threat["abuse_score"]

        card_accent = {"HIGH": "#ff3860", "MEDIUM": "#ffdd57", "LOW": "#23d160"}.get(level, "#00f5d4")
        badge_cls   = {"HIGH": "risk-high", "MEDIUM": "risk-med", "LOW": "risk-low"}.get(level, "")

        st.markdown(f'<div class="sec-label" style="font-size:12px; margin-top:10px;">➔ &nbsp; {ip} &nbsp; ({level} RISK)</div>', unsafe_allow_html=True)
        with st.container():
            st.markdown(
                f'<div style="background:#0d1520;border:1px solid #1a2535;border-top:2px solid {card_accent};'
                f'border-radius:8px;padding:1.1rem 1.4rem;margin-bottom:0.75rem;">'
                f'<div style="display:flex;justify-content:space-between;align-items:flex-start;">'
                f'<div><div style="font-family:Syne,sans-serif;font-size:22px;font-weight:700;color:#e8f4fd;">{ip}</div>'
                f'<div style="font-size:10px;color:#3a5a7a;letter-spacing:0.15em;margin-top:3px;">'
                f'STATE: {host["state"].upper()}  ·  OPEN PORTS: {host["total_open_ports"]}</div></div>'
                f'<div><span class="risk-badge {badge_cls}">{level} RISK</span></div>'
                f'</div></div>', unsafe_allow_html=True
            )
            m1, m2, m3, m4, m5 = st.columns(5)
            m1.metric("Risk Score",  score)
            m2.metric("Confidence",  f"{conf}%")
            m3.metric("Malicious",   malicious)
            m4.metric("Suspicious",  suspicious)
            m5.metric("Abuse Score", abuse_score)

            st.markdown('<div class="sec-label">Network & Configuration Scan (Nmap / System)</div>', unsafe_allow_html=True)
            net1, net2 = st.columns(2)
            with net1:
                if host["open_ports"]:
                    critical_ports = {21, 22, 23, 3389, 445, 5900, 4444}
                    st.markdown("<strong>Open Ports</strong>", unsafe_allow_html=True)
                    port_html = ""
                    for p in host["open_ports"]:
                        pnum    = p["port"]
                        is_crit = pnum in critical_ports
                        pill = ('<span class="port-pill" style="background:rgba(255,56,96,0.15);color:#ff3860;border:1px solid rgba(255,56,96,0.35);">CRITICAL</span>' if is_crit else '<span class="port-pill" style="background:rgba(0,245,212,0.07);color:#00f5d4;border:1px solid rgba(0,245,212,0.2);">OPEN</span>')
                        port_html += f'<div class="port-row"><span class="port-num">:{pnum}</span><span class="port-svc">{p["service"]}</span>{pill}</div>'
                    st.markdown(f'<div class="terminal-box">{port_html}</div>', unsafe_allow_html=True)
            with net2:
                st.markdown("<strong>Host OS & Configs</strong>", unsafe_allow_html=True)
                os_str    = config_data.get("os_info", "") or "Unknown OS"
                vulns     = config_data.get("vulnerable_configs", [])
                errs      = config_data.get("errors", [])
                vuln_html = "".join([f'<span class="t-red">✗ {v}</span><br>' for v in vulns]) if vulns else ("".join([f'<span class="t-yellow">⚠ {e}</span><br>' for e in errs]) if errs else '<span class="t-green">✓ No glaring local config issues</span>')
                st.markdown(f'<div class="terminal-box"><span class="t-cyan">os_fingerprint :</span> <span class="t-white">{os_str}</span><br><span class="t-cyan">packages_found :</span> <span class="t-white">{config_data.get("installed_packages_count", 0)}</span><br><br>{vuln_html}</div>', unsafe_allow_html=True)

            st.markdown('<div class="sec-label">External Threat Intel & Compliance (VirusTotal / Shodan)</div>', unsafe_allow_html=True)
            ti1, ti2 = st.columns(2)
            with ti1:
                st.markdown("<strong>VirusTotal & Enterprise Platforms</strong>", unsafe_allow_html=True)
                st.markdown(f'<div class="terminal-box"><span class="t-red">malicious  :</span> <span class="t-white">{malicious}</span><br><span class="t-yellow">suspicious :</span> <span class="t-white">{suspicious}</span><br><span class="t-cyan">nessus  :</span> <span class="t-white">{threat.get("nessus_status", "Offline")}</span><br><span class="t-cyan">openvas :</span> <span class="t-white">{threat.get("openvas_status", "Offline")}</span></div>', unsafe_allow_html=True)
            with ti2:
                st.markdown("<strong>Shodan Exposure</strong>", unsafe_allow_html=True)
                shodan_vulns = threat.get("shodan_vulns", [])
                sv_html = ('<span class="t-red">' + ", ".join(shodan_vulns[:3]) + ('...' if len(shodan_vulns) > 3 else '') + '</span>' if shodan_vulns else '<span class="t-green">none detected</span>')
                st.markdown(f'<div class="terminal-box"><span class="t-cyan">org     :</span> <span class="t-white">{threat.get("shodan_org", "N/A")}</span><br><span class="t-cyan">country :</span> <span class="t-white">{threat.get("shodan_country", "N/A")}</span><br><span class="t-cyan">cves    :</span> {sv_html}</div>', unsafe_allow_html=True)

            owasp_hits = compliance["owasp"]
            nist_hits  = compliance["nist"]
            if len(owasp_hits) + len(nist_hits) > 0:
                cc1, cc2 = st.columns(2)
                with cc1:
                    for item in owasp_hits: st.markdown(f'<div style="margin-bottom:10px;"><span class="risk-badge risk-high">{item["id"]}</span>&nbsp;<span style="color:#c8d6e5;">{item["title"]}</span></div>', unsafe_allow_html=True)
                with cc2:
                    for item in nist_hits: st.markdown(f'<div style="margin-bottom:10px;"><span class="risk-badge risk-med">{item["id"]}</span>&nbsp;<span style="color:#c8d6e5;">{item["title"]}</span></div>', unsafe_allow_html=True)

    if run_scan:
        if not targets.strip():
            st.warning("Enter at least one target.")
            st.stop()

        target_list = [t.strip() for t in targets.split(",") if t.strip()]
        cycles = 3 if monitoring else 1

        # ── Scan all targets, store everything in session_state ───────────────
        st.session_state["scan_results"] = {}
        st.session_state["scan_targets"] = target_list
        st.session_state["scan_cycles"]  = cycles

        for cycle in range(cycles):
            cycle_key = f"cycle_{cycle}"
            st.session_state["scan_results"][cycle_key] = {}

            with st.spinner(f"Scanning {len(target_list)} target(s) — cycle {cycle+1}/{cycles}..."):
                for target in target_list:
                    scan_raw  = scan_target(target)
                    processed = []
                    if scan_raw:
                        for host in scan_raw:
                            ip           = resolve_to_ip(host["ip"])
                            host["ip"]   = ip
                            threat       = get_combined_threat_data(ip)
                            malicious    = threat["malicious"]
                            suspicious   = threat["suspicious"]
                            abuse_score  = threat["abuse_score"]
                            features     = extract_features([p["port"] for p in host["open_ports"]], malicious, suspicious, abuse_score)
                            level, score = predict_risk(features)
                            conf         = confidence_score(score)
                            compliance   = get_compliance_mapping(open_ports=[p["port"] for p in host["open_ports"]], malicious=malicious, suspicious=suspicious, vulns=threat.get("shodan_vulns", []))
                            config_data  = scan_system_config(ip)
                            save_scan({"ip": ip, "score": score, "level": level, "malicious": malicious, "suspicious": suspicious, "abuse_score": abuse_score, "open_ports": host["open_ports"]})
                            alert = generate_alert(level, ip, score)
                            if alert:
                                st.toast(alert["message"], icon="🚨" if level == "HIGH" else "⚠️")
                            if level == "HIGH":
                                send_email_alert(ip, score, level)
                            processed.append({"host": host, "threat": threat, "level": level, "score": score, "conf": conf, "compliance": compliance, "config_data": config_data})
                    st.session_state["scan_results"][cycle_key][target] = processed

            if monitoring and cycle < cycles - 1:
                time.sleep(2)

    # ── Render: only the selected target's data ───────────────────────────────
    if "scan_results" in st.session_state and st.session_state["scan_results"]:
        target_list = st.session_state.get("scan_targets", [])
        cycles      = st.session_state.get("scan_cycles", 1)

        if not target_list:
            st.stop()

        st.markdown('<div class="sec-label">Select Target</div>', unsafe_allow_html=True)
        selected_target = st.radio(
            "target_selector",
            target_list,
            horizontal=True,
            label_visibility="collapsed",
        )

        for cycle in range(cycles):
            if cycles > 1:
                st.markdown(f'<div class="sec-label">Scan Cycle {cycle + 1} / {cycles}</div>', unsafe_allow_html=True)
            cycle_key = f"cycle_{cycle}"
            results   = st.session_state["scan_results"].get(cycle_key, {}).get(selected_target, [])
            if not results:
                st.markdown(f'<div class="terminal-box"><span class="t-yellow">[ WARN ]</span> No results for <span class="t-cyan">{selected_target}</span>.</div>', unsafe_allow_html=True)
            else:
                for r in results:
                    render_host_result(r)

# ─────────────────────────────────────────────────────────────────────────────
# PAGE: ANALYTICS (SCAN REPORT)
# ─────────────────────────────────────────────────────────────────────────────

elif "SCAN REPORT" in page:

    st.markdown('<div class="sentinel-title">Scan <span class="sentinel-accent">Report</span></div>', unsafe_allow_html=True)
    st.markdown('<div class="sentinel-subtitle">■ Detailed health check — nmap surface + threat intelligence per target</div>', unsafe_allow_html=True)

    try:
        raw_history = get_all_scans()
        history = filter_history_records(raw_history)

        df = prepare_dataframe(history)

        if df.empty:
            st.markdown('<div class="terminal-box"><span class="t-yellow">[ WARN ]</span> No data found for these filters.</div>', unsafe_allow_html=True)
            st.stop()

        st.markdown('<div class="sec-label">Controls</div>', unsafe_allow_html=True)
        ctrl1, ctrl2, ctrl3, ctrl4 = st.columns([2, 1, 1, 1])
        with ctrl2:
            if st.button("⟳  Clear History", use_container_width=True):
                clear_scans()
                st.success("History cleared.")
                st.rerun()
        with ctrl3:
            st.download_button("↓  Export CSV", data=df.to_csv(index=False), file_name="sentinel_history.csv", mime="text/csv", use_container_width=True)
        with ctrl4:
            recent_n = st.slider("Last N scans", 1, max(len(df), 1), min(20, len(df)), label_visibility="collapsed")

        df = df.tail(recent_n)

        stats_sr   = get_summary_stats(df)
        posture_sr = calculate_posture(history)
        k1, k2, k3, k4, k5 = st.columns(5)
        k1.metric("Avg Risk",    round(stats_sr["avg_score"], 1))
        k2.metric("Max Risk",    stats_sr["max_score"])
        k3.metric("Min Risk",    stats_sr["min_score"])
        k4.metric("Total Scans", stats_sr["total_scans"])
        k5.metric("Posture",     posture_sr)

        st.markdown("---")

        st.markdown('<div class="sec-label">Surface Intelligence</div>', unsafe_allow_html=True)
        ch1, ch2, ch3 = st.columns(3)
        with ch1:
            fig_line = px.area(df, y="score", title="Risk Score Over Time", color_discrete_sequence=["#00f5d4"])
            fig_line.update_traces(line_color="#00f5d4", fillcolor="rgba(0,245,212,0.07)")
            st.plotly_chart(styled_chart(fig_line), use_container_width=True)
        with ch2:
            ip_data = get_ip_risk(df)
            fig_bar = px.bar(ip_data, x="ip", y="score", title="Average Risk Score by IP", color="score",
                             color_continuous_scale=[[0, "#23d160"], [0.5, "#ffdd57"], [1, "#ff3860"]])
            fig_bar.update_traces(marker_line_width=0)
            st.plotly_chart(styled_chart(fig_bar), use_container_width=True)
        with ch3:
            fig_sun = px.sunburst(df, path=["level", "ip"], values="score", title="Risk Hierarchy",
                                  color="score", color_continuous_scale=[[0, "#1a2535"], [0.5, "#3273dc"], [1, "#ff3860"]])
            st.plotly_chart(styled_chart(fig_sun), use_container_width=True)

        st.markdown("---")

        st.markdown('<div class="sec-label">Nmap + Risk Scan Data</div>', unsafe_allow_html=True)
        if "level" in df.columns:
            def color_level_sr(val): return {"HIGH": "color: #ff3860", "MEDIUM": "color: #ffdd57", "LOW": "color: #23d160"}.get(val, "")
            st.dataframe(clean_df_for_display(df).style.map(color_level_sr, subset=["level"]), use_container_width=True)
        else:
            st.dataframe(clean_df_for_display(df), use_container_width=True)

        st.markdown('<div class="sec-label" style="margin-top:16px;">Threat Intelligence Summary (VT Scores)</div>', unsafe_allow_html=True)
        _vt_cols = ["ip", "score", "level", "malicious", "suspicious", "abuse_score"]
        _vt_available = [c for c in _vt_cols if c in df.columns]
        if _vt_available:
            _vt_df = df[_vt_available].copy().tail(recent_n)
            _vt_df.columns = [c.replace("_", " ").title() for c in _vt_df.columns]
            def _color_vt_level(val):
                return {"HIGH": "color: #ff3860", "MEDIUM": "color: #ffdd57", "LOW": "color: #23d160"}.get(str(val).upper(), "")
            if "Level" in _vt_df.columns:
                st.dataframe(_vt_df.style.map(_color_vt_level, subset=["Level"]), use_container_width=True)
            else:
                st.dataframe(_vt_df, use_container_width=True)
        else:
            st.markdown('<div class="terminal-box"><span class="t-yellow">[ INFO ]</span> No threat intel data stored yet.</div>', unsafe_allow_html=True)

    except Exception as e:
        if "no such table" in str(e).lower() or "missing" in str(e).lower():
            st.markdown('<div class="terminal-box"><span class="t-yellow">[ WARN ]</span> No scan data found. Run a scan to generate data.</div>', unsafe_allow_html=True)
        else:
            st.error(f"Scan Report error: {e}")

# ─────────────────────────────────────────────────────────────────────────────
# PAGE: HISTORY
# ─────────────────────────────────────────────────────────────────────────────

elif "HISTORY" in page:

    st.markdown('<div class="sentinel-title">History <span class="sentinel-accent">Section</span></div>', unsafe_allow_html=True)
    st.markdown('<div class="sentinel-subtitle">■ Full scan history, trends &amp; SQLite data table (Filters Applied)</div>', unsafe_allow_html=True)

    try:
        raw_history = get_all_scans()
        history = filter_history_records(raw_history)
        df = prepare_dataframe(history)

        if df.empty:
            st.markdown('<div class="terminal-box"><span class="t-yellow">[ WARN ]</span> No data matches current filters.</div>', unsafe_allow_html=True)
            st.stop()

        ctrl1, ctrl2, ctrl3, ctrl4 = st.columns([2, 1, 1, 1])
        with ctrl2:
            if st.button("⟳  Clear All History ", use_container_width=True):
                clear_scans()
                st.success("History cleared.")
                st.rerun()
        with ctrl3:
            st.download_button("↓  Export CSV", data=df.to_csv(index=False), file_name="sentinel_history.csv", mime="text/csv", use_container_width=True)
        with ctrl4:
            recent_n_h = st.slider("Last N", 1, max(len(df), 1), min(20, len(df)), label_visibility="collapsed")

        df = df.tail(recent_n_h)

        stats_h   = get_summary_stats(df)
        posture_h = calculate_posture(history)
        anomaly_h = detect_anomaly(history)
        h1, h2, h3, h4, h5 = st.columns(5)
        h1.metric("Avg Risk",    round(stats_h["avg_score"], 1))
        h2.metric("Max Risk",    stats_h["max_score"])
        h3.metric("Min Risk",    stats_h["min_score"])
        h4.metric("Filtered Scans", stats_h["total_scans"])
        h5.metric("Posture",     posture_h)
        if anomaly_h: st.markdown(f'<div class="terminal-box"><span class="t-red">[ ANOMALY ]</span> <span class="t-white">{anomaly_h}</span></div>', unsafe_allow_html=True)

        st.markdown("---")

        st.markdown('<div class="sec-label">Trends &amp; Distribution</div>', unsafe_allow_html=True)
        hc1, hc2, hc3 = st.columns(3)
        with hc1:
            fig_trend = px.line(df.reset_index(), x="index", y="score", title="Risk Score Trend", color_discrete_sequence=["#00f5d4"])
            fig_trend.update_traces(line_color="#00f5d4", line_width=2)
            st.plotly_chart(styled_chart(fig_trend), use_container_width=True)
        with hc2:
            dist_h = get_distribution(df)
            fig_dist = px.bar(x=list(dist_h.keys()), y=list(dist_h.values()), title="Level Distribution",
                              color=list(dist_h.keys()), color_discrete_map={"HIGH":"#ff3860","MEDIUM":"#ffdd57","LOW":"#23d160"})
            fig_dist.update_layout(showlegend=False)
            st.plotly_chart(styled_chart(fig_dist), use_container_width=True)
        with hc3:
            ip_data_h = get_ip_risk(df)
            fig_ip_h = px.bar(ip_data_h, x="ip", y="score", title="Avg Risk by IP",
                              color="score", color_continuous_scale=[[0,"#23d160"],[0.5,"#ffdd57"],[1,"#ff3860"]])
            fig_ip_h.update_traces(marker_line_width=0)
            st.plotly_chart(styled_chart(fig_ip_h), use_container_width=True)

        st.markdown('<div class="sec-label">Advanced Correlated Intel</div>', unsafe_allow_html=True)
        adv1, adv2 = st.columns(2)
        with adv1:
            heat_df = df.pivot_table(values="score", index="ip", columns="level", aggfunc="mean").fillna(0)
            if not heat_df.empty:
                fig_heat = px.imshow(heat_df, text_auto=True, title="IP × Risk Level Heatmap", color_continuous_scale=[[0,"#0d1520"],[0.5,"#3273dc"],[1,"#ff3860"]])
                st.plotly_chart(styled_chart(fig_heat), use_container_width=True)
        with adv2:
            fig_scat = px.scatter(df, x="ip", y="score", size="score", color="level", title="Scatter Intelligence",
                                  color_discrete_map={"HIGH":"#ff3860","MEDIUM":"#ffdd57","LOW":"#23d160"})
            st.plotly_chart(styled_chart(fig_scat), use_container_width=True)

        st.markdown('<div class="sec-label">SQLite History Table</div>', unsafe_allow_html=True)
        if "level" in df.columns:
            def color_level_h(val): return {"HIGH": "color: #ff3860", "MEDIUM": "color: #ffdd57", "LOW": "color: #23d160"}.get(val, "")
            st.dataframe(clean_df_for_display(df).style.map(color_level_h, subset=["level"]), use_container_width=True)
        else:
            st.dataframe(clean_df_for_display(df), use_container_width=True)

    except Exception as e:
        if "no such table" in str(e).lower() or "missing" in str(e).lower():
            st.markdown('<div class="terminal-box"><span class="t-yellow">[ WARN ]</span> No SQLite scan data found.</div>', unsafe_allow_html=True)
        else:
            st.error(f"History error: {e}")

# ─────────────────────────────────────────────────────────────────────────────
# PAGE: ANALYTICS
# ─────────────────────────────────────────────────────────────────────────────

elif "ANALYTICS" in page:

    st.markdown('<div class="sentinel-title">Deep <span class="sentinel-accent">Analytics</span></div>', unsafe_allow_html=True)
    st.markdown('<div class="sentinel-subtitle">■ Multi-dimensional threat data visualizations (Filters Applied)</div>', unsafe_allow_html=True)

    try:
        raw_history = get_all_scans()
        history = filter_history_records(raw_history)
        df = prepare_dataframe(history)

        if df.empty:
            st.markdown('<div class="terminal-box"><span class="t-yellow">[ WARN ]</span> No data matches current filters. Run a scan or clear filters.</div>', unsafe_allow_html=True)
            st.stop()
            
        port_rows = []
        for h in history:
            ip = h.get("ip", "Unknown")
            level = h.get("level", "INFO")
            score = h.get("score", 0)
            vt_score = h.get("malicious", 0)
            
            for p in h.get("open_ports", []):
                port_rows.append({
                    "ip": ip,
                    "level": level,
                    "score": score,
                    "vt_score": vt_score,
                    "port": p.get("port", "-"),
                    "service": p.get("service", "unknown"),
                    "risk_tag": "CRITICAL" if p.get("port") in [21, 22, 23, 3389, 445, 5900, 4444] else "STANDARD"
                })
        
        pdf = pd.DataFrame(port_rows)
        
        st.markdown('<div class="sec-label">Network & Service Exposure</div>', unsafe_allow_html=True)
        r1_1, r1_2, r1_3 = st.columns(3)
        
        with r1_1:
            if not pdf.empty:
                pr_df = pdf.groupby(["risk_tag", "level"]).size().reset_index(name="count")
                fig1 = px.bar(pr_df, x="risk_tag", y="count", color="level", title="Port Risk Distribution",
                              color_discrete_map={"HIGH":"#ff3860","MEDIUM":"#ffdd57","LOW":"#23d160", "INFO":"#3a5a7a"})
                st.plotly_chart(styled_chart(fig1), use_container_width=True)
            else:
                st.info("No open ports tracked.")
        
        with r1_2:
            if not pdf.empty:
                svc_df = pdf["service"].value_counts().reset_index()
                svc_df.columns = ["service", "count"]
                fig2 = px.bar(svc_df, y="service", x="count", orientation="h", title="Services Exposed", color="count", color_continuous_scale=[[0,"#23d160"],[1,"#ff3860"]])
                fig2.update_layout(yaxis={'categoryorder':'total ascending'})
                st.plotly_chart(styled_chart(fig2), use_container_width=True)
            else:
                 st.info("No open ports tracked.")

        with r1_3:
            if "malicious" in df.columns:
                vt_df = df[["ip", "malicious", "suspicious"]].melt(id_vars="ip", var_name="Intel Type", value_name="Score")
                fig3 = px.bar(vt_df, x="ip", y="Score", color="Intel Type", barmode="group", title="Threat Intel by Target", color_discrete_sequence=["#ff3860", "#ffdd57"])
                st.plotly_chart(styled_chart(fig3), use_container_width=True)
            
        st.markdown("---")
        st.markdown('<div class="sec-label">Composite Risk Mapping</div>', unsafe_allow_html=True)
        r2_1, r2_2 = st.columns(2)
        
        with r2_1:
            if not pdf.empty:
                bub_df = pdf.groupby(["ip", "level", "score"]).size().reset_index(name="open_ports")
                fig4 = px.scatter(bub_df, x="open_ports", y="score", size="score", color="level", hover_name="ip", title="Composite Risk vs Open Ports", color_discrete_map={"HIGH":"#ff3860","MEDIUM":"#ffdd57","LOW":"#23d160", "INFO":"#3a5a7a"})
                st.plotly_chart(styled_chart(fig4), use_container_width=True)
            else:
                st.info("No open ports mapped.")
                
        with r2_2:
            if "malicious" in df.columns:
                fig5 = px.scatter(df, x="score", y="malicious", size="score", color="level", hover_name="ip", title="Sentinel Score vs VT Malicious Flags", color_discrete_map={"HIGH":"#ff3860","MEDIUM":"#ffdd57","LOW":"#23d160", "INFO":"#3a5a7a"})
                st.plotly_chart(styled_chart(fig5), use_container_width=True)
            
        st.markdown("---")
        st.markdown('<div class="sec-label">Service Correlated Intel</div>', unsafe_allow_html=True)
        r3_1, r3_2, r3_3 = st.columns(3)
        
        with r3_1:
            if not pdf.empty:
                svc_risk = pdf.groupby("service")["score"].mean().reset_index()
                fig6 = px.bar(svc_risk, y="service", x="score", orientation="h", title="Avg Risk by Service", color="score", color_continuous_scale=[[0,"#00f5d4"],[1,"#ff3860"]])
                fig6.update_layout(yaxis={'categoryorder':'total ascending'})
                st.plotly_chart(styled_chart(fig6), use_container_width=True)
            else:
                st.info("No data.")
                
        with r3_2:
            if not pdf.empty:
                heat_df = pdf.pivot_table(index="ip", columns="risk_tag", values="score", aggfunc="mean").fillna(0)
                fig7 = px.imshow(heat_df, text_auto=True, title="Target vs Port Risk Tag Heatmap", color_continuous_scale=[[0,"#0d1520"],[0.5,"#3273dc"],[1,"#ff3860"]])
                st.plotly_chart(styled_chart(fig7), use_container_width=True)
            else:
                st.info("No data.")
                
        with r3_3:
            if not df.empty and "level" in df.columns:
                fig8 = px.sunburst(df, path=["level", "ip"], values="score", title="Global Risk Hierarchy", color="score", color_continuous_scale=[[0, "#1a2535"], [0.5, "#3273dc"], [1, "#ff3860"]])
                st.plotly_chart(styled_chart(fig8), use_container_width=True)
            else:
                 st.info("No data.")

    except Exception as e:
        if "no such table" in str(e).lower() or "missing" in str(e).lower():
            st.markdown('<div class="terminal-box"><span class="t-yellow">[ WARN ]</span> No SQLite scan data found.</div>', unsafe_allow_html=True)
        else:
            st.error(f"Analytics error: {e}")

# ─────────────────────────────────────────────────────────────────────────────
# PAGE: REPORTS
# ─────────────────────────────────────────────────────────────────────────────

elif "REPORTS" in page or "▣  REPORTS" in page:

    st.markdown('<div class="sentinel-title">Report <span class="sentinel-accent">Generator</span></div>', unsafe_allow_html=True)
    st.markdown('<div class="sentinel-subtitle">■ Audit-ready PDF with OWASP &amp; NIST compliance mapping</div>', unsafe_allow_html=True)

    st.markdown('<div class="sec-label">Report Parameters</div>', unsafe_allow_html=True)

    r1, r2 = st.columns(2)
    with r1:
        ip         = st.text_input("Target IP", placeholder="e.g. 45.33.32.156")
        level      = st.selectbox("Risk Level", ["LOW", "MEDIUM", "HIGH"])
    with r2:
        score      = st.number_input("Risk Score (0–100)", min_value=0, max_value=100, value=50)
        ports_raw  = st.text_input("Open Ports (comma-separated)", placeholder="22, 80, 443, 3389")

    st.markdown("---")

    if ip:
        port_list = []
        if ports_raw:
            try: port_list = [int(p.strip()) for p in ports_raw.split(",") if p.strip()]
            except: pass

        preview_compliance = get_compliance_mapping(
            open_ports = port_list, malicious  = 1 if level == "HIGH" else 0, suspicious = 1 if level in ("HIGH", "MEDIUM") else 0, vulns      = []
        )

        st.markdown('<div class="sec-label">Live Preview</div>', unsafe_allow_html=True)
        p1, p2, p3, p4 = st.columns(4)
        p1.metric("Target",     ip)
        p2.metric("Score",      score)
        p3.metric("OWASP Hits", preview_compliance["summary"]["total_owasp_hits"])
        p4.metric("NIST Gaps",  preview_compliance["summary"]["total_nist_hits"])

        if preview_compliance["owasp"] or preview_compliance["nist"]:
            owasp_lines = "".join(f'<span class="t-red">[ OWASP {i["id"]} ]</span> <span class="t-white">{i["title"]}</span><br>' for i in preview_compliance["owasp"])
            nist_lines = "".join(f'<span class="t-yellow">[ NIST  {i["id"]} ]</span> <span class="t-white">{i["function"]} — {i["title"]}</span><br>' for i in preview_compliance["nist"])
            st.markdown(f'<div class="terminal-box">{owasp_lines}{nist_lines}</div>', unsafe_allow_html=True)

        st.markdown("---")

    if st.button("◉  GENERATE PDF REPORT"):
        if not ip:
            st.warning("Enter a target IP first.")
        else:
            port_list = []
            if ports_raw:
                try: port_list = [int(p.strip()) for p in ports_raw.split(",") if p.strip()]
                except: pass

            open_ports_fmt = [{"port": p, "service":  "unknown", "priority": "HIGH" if p in {21, 22, 23, 3389, 445, 5900} else "LOW"} for p in port_list]
            compliance_data = get_compliance_mapping(open_ports = port_list, malicious  = 1 if level == "HIGH" else 0, suspicious = 1 if level in ("HIGH", "MEDIUM") else 0, vulns = [])
            out_path = f"report_{ip.replace('.', '_')}.pdf"

            with st.spinner("Generating report..."):
                output = generate_pdf(ip = ip, score = score, level = level, open_ports  = open_ports_fmt, threat_data = {}, compliance  = compliance_data, output_path = out_path)

            with open(output, "rb") as f:
                st.download_button(label = "↓  Download PDF Report", data = f, file_name = f"sentinel_report_{ip}.pdf", mime = "application/pdf")

            st.markdown(f'<div class="terminal-box"><span class="t-green">[ OK ]</span> Report saved  →  <span class="t-cyan">{output}</span><br><span class="t-green">[ OK ]</span> OWASP violations: <span class="t-white">{compliance_data["summary"]["total_owasp_hits"]}</span><br><span class="t-green">[ OK ]</span> NIST CSF gaps:    <span class="t-white">{compliance_data["summary"]["total_nist_hits"]}</span></div>', unsafe_allow_html=True)