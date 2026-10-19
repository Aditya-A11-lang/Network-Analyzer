"""AI-Based Network Communication Fingerprinting and Anomaly Detection.

Streamlit dashboard entry point. Educational tool for AUTHORIZED network
monitoring only. Analyzes traffic metadata (never payloads) to build
per-device behavioral fingerprints and flag statistical deviations using
an unsupervised Isolation Forest model. An "anomaly" is a behavioral
deviation that warrants investigation - not a confirmed attack.
"""
from __future__ import annotations

import os
import sys
import tempfile
import time

import pandas as pd
import streamlit as st

sys.path.insert(0, os.path.dirname(__file__))

from src import capture, database
from src.packet_parser import parse_pcap_bytes, InvalidPcapError, EmptyCaptureError, packets_to_dataframe
from src.feature_engineering import build_device_features, feature_matrix
from src.fingerprint import build_fingerprints, bar_string
from src.anomaly_model import (
    train_anomaly_model, predict_anomaly, model_exists,
    InsufficientDataError, ModelUnavailableError,
)
from src.baseline import (
    establish_baseline, aggregate_features, compare_to_baseline,
    has_significant_deviation, InsufficientBaselineError,
)
from src.risk_scoring import calculate_risk_score, calculate_network_health
from src.ai_review import generate_ai_review
from src.traffic_analysis import (
    compute_summary_stats, top_n, protocol_distribution_figure,
    traffic_over_time_figure, top_talkers_figure,
)
from src.utils import get_logger

logger = get_logger("app")

st.set_page_config(
    page_title="Network Analyzer with AI",
    page_icon="🛡️",
    layout="wide",
)

# ---------------------------------------------------------------------------
# Advanced UI Styling - Elite Cyber Command Executive Theme
# ---------------------------------------------------------------------------
st.markdown("""
<style>
    /* Global Executive Slate/Navy Palette */
    .stApp {
        background: linear-gradient(180deg, #f1f5f9 0%, #e2e8f0 100%);
        color: #0f172a;
        font-family: 'Inter', system-ui, -apple-system, sans-serif;
    }
    
    .main .block-container {
        padding-top: 1.5rem;
        padding-bottom: 3rem;
        max-width: 1440px;
        animation: fadeIn 0.3s cubic-bezier(0.16, 1, 0.3, 1);
    }

    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(4px); }
        to { opacity: 1; transform: translateY(0); }
    }
    
    /* Top Header Bar */
    .top-header-bar {
        display: flex;
        align-items: center;
        justify-content: space-between;
            gap: 1rem;
            flex-wrap: wrap;
            background: linear-gradient(120deg, #0b1224 0%, #142747 58%, #173a67 100%);
            padding: 1.25rem 1.6rem;
            border: 1px solid rgba(148, 163, 184, 0.18);
            border-bottom: 4px solid #38bdf8;
            border-radius: 18px;
            margin-bottom: 1.5rem;
            box-shadow: 0 12px 28px -12px rgba(15, 23, 42, 0.45);
    }
    
    .top-header-title {
        font-size: clamp(1.05rem, 2vw, 1.4rem);
        font-weight: 800;
        color: #ffffff;
        display: flex;
        align-items: center;
        gap: 0.75rem;
        letter-spacing: -0.02em;
    }

    .top-header-badge {
        font-size: 0.75rem;
        padding: 7px 14px;
        background: rgba(37, 99, 235, 0.2);
        color: #60a5fa;
        border: 1px solid rgba(96, 165, 250, 0.3);
        border-radius: 20px;
        font-weight: 700;
        letter-spacing: 0.05em;
        text-transform: uppercase;
    }

    /* Scope navigation styles so page action buttons keep their own appearance. */
    [class*="st-key-nav_btn_"] button {
        width: 100% !important;
        min-height: 3.25rem !important;
        padding: 0.65rem 0.8rem !important;
        border-radius: 13px !important;
        transition: background 0.2s ease, border-color 0.2s ease,
            box-shadow 0.2s ease, transform 0.2s ease !important;
    }

    [class*="st-key-nav_btn_"] button p {
        font-size: 0.88rem !important;
        font-weight: 700 !important;
        line-height: 1.25 !important;
        white-space: normal !important;
    }

    [class*="st-key-nav_btn_"] button[kind="primary"] {
        background: linear-gradient(135deg, #1d4ed8 0%, #2563eb 100%) !important;
        border: 1px solid #1e40af !important;
        box-shadow: 0 5px 14px rgba(37, 99, 235, 0.28) !important;
        transform: translateY(-1px);
    }

    [class*="st-key-nav_btn_"] button[kind="primary"] p {
        color: #ffffff !important;
    }

    [class*="st-key-nav_btn_"] button[kind="secondary"] {
        background: rgba(255, 255, 255, 0.88) !important;
        border: 1px solid #d5deea !important;
        box-shadow: 0 2px 7px rgba(15, 23, 42, 0.04) !important;
    }

    [class*="st-key-nav_btn_"] button[kind="secondary"] p {
        color: #334155 !important;
    }

    [class*="st-key-nav_btn_"] button[kind="secondary"]:hover {
        background: #eff6ff !important;
        border-color: #60a5fa !important;
        box-shadow: 0 4px 12px rgba(37, 99, 235, 0.12) !important;
        transform: translateY(-1px);
    }

    .navigation-label {
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin: 0.1rem 0 0.5rem;
        color: #64748b;
        font-size: 0.72rem;
        font-weight: 800;
        letter-spacing: 0.1em;
        text-transform: uppercase;
    }

    .navigation-label span:last-child {
        font-size: 0.72rem;
        font-weight: 500;
        letter-spacing: 0;
        text-transform: none;
    }

    /* Clean Card Containers */
    div.stContainer {
        border-radius: 16px;
        padding: 1.5rem;
        background: #ffffff;
        border: 1px solid #e2e8f0;
        box-shadow: 0 4px 15px -3px rgba(0, 0, 0, 0.05);
    }

    /* Metrics Styling */
    div[data-testid="stMetric"] {
        background: #ffffff;
        border: 1px solid #e2e8f0;
        padding: 14px 18px;
        border-radius: 12px;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.03);
        transition: all 0.2s ease;
    }
    
    div[data-testid="stMetric"]:hover {
        border-color: #2563eb;
        box-shadow: 0 4px 12px rgba(37, 99, 235, 0.1);
    }
    
    div[data-testid="stMetric"] label {
        color: #64748b !important;
        font-weight: 600 !important;
        font-size: 0.85rem !important;
    }

    div[data-testid="stMetric"] div[data-testid="stMetricValue"] {
        color: #0f172a !important;
        font-weight: 800 !important;
    }

    /* Dataframes */
    div[data-testid="stDataFrame"] {
        border-radius: 12px;
        overflow: hidden;
        border: 1px solid #e2e8f0;
    }
</style>
""", unsafe_allow_html=True)

PAGES = [
    "Overview",
    "Live Analyzer",
    "PCAP Analyzer",
    "Communication Fingerprint",
    "AI Analysis",
    "What Changed?",
    "Traffic Statistics",
    "Analysis History",
]

# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------
def _init_state():
    defaults = {
        "active_page": "Overview",
        "df": None,
        "features": None,
        "fingerprints": None,
        "anomaly_results": None,
        "comparison": None,
        "risk_result": None,
        "ai_review": None,
        "source": None,
        "last_error": None,
        "capture_state": capture.CaptureState(),
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


_init_state()
database.init_db()


# ---------------------------------------------------------------------------
# Shared analysis pipeline
# ---------------------------------------------------------------------------
def run_full_analysis(df: pd.DataFrame, source: str) -> None:
    st.session_state["df"] = df
    st.session_state["source"] = source
    st.session_state["last_error"] = None

    features = build_device_features(df)
    st.session_state["features"] = features

    if features.empty:
        st.session_state["last_error"] = "Insufficient traffic data for anomaly analysis."
        return

    fingerprints = build_fingerprints(features)
    st.session_state["fingerprints"] = fingerprints

    matrix = feature_matrix(features)

    anomaly_results = None
    try:
        if not model_exists():
            train_anomaly_model(matrix)
        anomaly_results = predict_anomaly(matrix)
    except InsufficientDataError:
        st.session_state["last_error"] = (
            "Insufficient traffic data for anomaly analysis. Capture or "
            "upload more traffic (multiple devices / more packets) to enable AI analysis."
        )
    except ModelUnavailableError:
        st.session_state["last_error"] = (
            "The anomaly model is not yet available. Analyze more traffic first."
        )
    st.session_state["anomaly_results"] = anomaly_results

    current_agg = aggregate_features(features)
    stored_baseline = database.get_latest_baseline()
    comparison = None
    if stored_baseline is None:
        try:
            baseline_snapshot = establish_baseline(features)
            database.save_baseline(baseline_snapshot)
            stored_baseline = baseline_snapshot
        except InsufficientBaselineError:
            pass
    if stored_baseline is not None:
        comparison = compare_to_baseline(stored_baseline, current_agg)
    st.session_state["comparison"] = comparison

    if anomaly_results:
        worst = max(anomaly_results, key=lambda r: r.anomaly_score)
        anomaly_norm = worst.anomaly_score / 100.0
        is_anomalous = any(r.is_anomalous for r in anomaly_results)
    else:
        worst = None
        anomaly_norm = 0.0
        is_anomalous = False

    risk_result = calculate_risk_score(anomaly_norm, comparison)
    st.session_state["risk_result"] = risk_result

    ai_review = generate_ai_review(
        is_anomalous=is_anomalous,
        anomaly_score=anomaly_norm,
        risk_result=risk_result,
        comparison=comparison,
        device_ip=(worst.src_ip if worst else None),
    )
    st.session_state["ai_review"] = ai_review

    stats = compute_summary_stats(df)
    anomaly_count = sum(1 for r in anomaly_results if r.is_anomalous) if anomaly_results else 0
    analysis_id = database.save_analysis(
        source=source,
        duration=stats["duration_seconds"],
        packet_count=stats["total_packets"],
        total_bytes=stats["total_bytes"],
        device_count=len(features),
        anomaly_count=anomaly_count,
        risk_score=risk_result["risk_score"],
        severity=risk_result["severity"],
        classification=ai_review["classification"],
    )
    database.save_fingerprints(analysis_id, fingerprints)


# ---------------------------------------------------------------------------
# Header Bar & Horizontal Navigation
# ---------------------------------------------------------------------------
st.markdown("""
    <div class="top-header-bar">
        <div class="top-header-title">
            <span>🛡️</span> AI-Powered Network Fingerprinting & Anomaly Detection
        </div>
        <div class="top-header-badge">SOC Operations Suite</div>
    </div>
    <div class="navigation-label">
        <span>Workspace navigation</span>
        <span>Choose a section</span>
    </div>
""", unsafe_allow_html=True)

nav_columns = 4
for row_start in range(0, len(PAGES), nav_columns):
    nav_cols = st.columns(nav_columns)
    for offset, page_name in enumerate(PAGES[row_start:row_start + nav_columns]):
        page_index = row_start + offset
        is_current = st.session_state["active_page"] == page_name
        btn_type = "primary" if is_current else "secondary"
        label = f"✓  {page_name}" if is_current else page_name
        if nav_cols[offset].button(label, key=f"nav_btn_{page_index}", type=btn_type):
            st.session_state["active_page"] = page_name
            st.rerun()

st.markdown("<div style='margin-bottom: 1.5rem;'></div>", unsafe_allow_html=True)

with st.sidebar.expander("🔒 Privacy & Security Notice", expanded=False):
    st.write(
        "This tool analyzes network **metadata only** - IP addresses, ports, "
        "protocols, packet sizes, and timestamps. It never captures or stores "
        "packet payloads, passwords, or authentication cookies, and never "
        "inspects application-layer message contents."
    )

if st.session_state["last_error"]:
    st.sidebar.warning(st.session_state["last_error"])


# ---------------------------------------------------------------------------
# Page: Overview
# ---------------------------------------------------------------------------
def page_overview():
    st.title("🌐 Network Overview")
    st.markdown("Monitor core infrastructure health, active host counts, and behavioral anomaly summaries at a glance.")
    
    metrics = database.get_overview_metrics()
    avg_risk = float(metrics.get("average_risk") or 0.0)
    anomalies = int(metrics.get("total_anomalies") or 0)
    devices = int(metrics.get("active_devices") or 0)
    total_analyses = int(metrics.get("total_analyses") or 0)
    anomaly_rate = (anomalies / devices) if devices else 0.0
    health = calculate_network_health(avg_risk, anomaly_rate)

    cols = st.columns(6)
    cols[0].metric("Health Score", f"{health}/100")
    cols[1].metric("Devices", devices)
    cols[2].metric("Packets", f"{int(metrics.get('total_packets') or 0):,}")
    cols[3].metric("Bytes", f"{int(metrics.get('total_bytes') or 0):,}")
    cols[4].metric("Anomalies", anomalies)
    cols[5].metric("Avg Risk", f"{avg_risk:.1f}")

    st.caption(
        "💡 *Note: Network Health and Risk Score are project-defined analytical metrics, "
        "not industry-standard security ratings.*"
    )
    st.divider()

    if total_analyses == 0:
        st.info(
            "👋 **Welcome!** No analyses recorded yet. Head over to the **PCAP Analyzer** page to upload a capture file, "
            "or use the **Live Analyzer** page to capture local traffic."
        )
    else:
        st.success(f"✨ **{total_analyses}** successful analyses recorded so far. Check out the **Analysis History** page for a full audit trail.")


# ---------------------------------------------------------------------------
# Page: Live Analyzer
# ---------------------------------------------------------------------------
def page_live_analyzer():
    st.title("⚡ Live Network Analyzer")

    if capture.is_cloud_environment():
        st.warning(
            "⚠️ Live capture requires running the application locally on an "
            "authorized machine. Cloud deployments support PCAP upload and "
            "analysis - please use the **PCAP Analyzer** page instead."
        )
        return

    st.info(
        "📡 This captures traffic on **this machine's** network interface only. "
        "Ensure you are authorized to monitor this network before proceeding. "
        "No packet payloads are stored; only metadata is analyzed."
    )

    interfaces = capture.list_interfaces()
    interface = None
    if interfaces:
        interface = st.selectbox("Select Network Interface (Optional)", ["Auto-detect"] + interfaces)
        interface = None if interface == "Auto-detect" else interface
    else:
        st.caption("No interface list available - Auto-detect will be used.")

    state: capture.CaptureState = st.session_state["capture_state"]

    col1, col2 = st.columns(2)
    start_clicked = col1.button("🚀 START ANALYZER", disabled=state.running, use_container_width=True)
    stop_clicked = col2.button("🛑 STOP & ANALYZE", disabled=not state.running, use_container_width=True)

    if start_clicked:
        try:
            capture.start_capture(state, interface=interface)
            st.rerun()
        except RuntimeError as exc:
            st.error(str(exc))

    if state.running:
        st.markdown("---")
        status_cols = st.columns(4)
        status_cols[0].metric("Status", "🟢 CAPTURING")
        status_cols[1].metric("Elapsed Time", f"{state.elapsed():.0f}s")
        status_cols[2].metric("Packets Captured", state.packet_count)
        status_cols[3].metric("Total Bytes", f"{state.total_bytes:,}")
        time.sleep(1)
        st.rerun()

    if stop_clicked:
        capture.stop_capture(state)
        if state.error:
            from src.utils import FRIENDLY_MESSAGES
            st.error(FRIENDLY_MESSAGES.get(state.error, FRIENDLY_MESSAGES["generic"]))
        elif not state.packets:
            st.warning("No packets were captured. Try again with more active network traffic.")
        else:
            with st.spinner("🔍 Parsing captured packets and running analysis pipeline..."):
                try:
                    df = packets_to_dataframe(state.packets)
                    run_full_analysis(df, source="live")
                    st.success(
                        f"✅ Successfully analyzed {len(df)} packets from {df['src_ip'].nunique()} device(s). "
                        "Navigate to **AI Analysis**, **Communication Fingerprint**, or **What Changed?** to view insights."
                    )
                except EmptyCaptureError:
                    st.error("No usable packet metadata was found in this capture.")
                except Exception:
                    logger.exception("Live capture analysis failed")
                    st.error("Something went wrong while analyzing the captured traffic.")


# ---------------------------------------------------------------------------
# Page: PCAP Analyzer
# ---------------------------------------------------------------------------
def page_pcap_analyzer():
    st.title("📂 PCAP File Analyzer")
    st.markdown(
        "Upload a `.pcap` or `.pcapng` capture file for deep behavioral parsing and anomaly detection. "
        "Works seamlessly across local and cloud deployments."
    )

    uploaded = st.file_uploader("Upload Capture File", type=["pcap", "pcapng"])
    if uploaded is None:
        return

    st.markdown("---")
    if st.button("🔍 Analyze PCAP File", type="primary", use_container_width=True):
        with st.spinner("⚙️ Parsing PCAP and executing full AI analytics pipeline..."):
            try:
                with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
                    tmp_path = tmp.name
                df = parse_pcap_bytes(uploaded.getvalue(), tmp_path)
                run_full_analysis(df, source="pcap")
                st.success(
                    f"✨ Successfully analyzed {len(df)} packets from {df['src_ip'].nunique()} device(s). "
                    "Explore the **AI Analysis**, **Communication Fingerprint**, and **What Changed?** pages for details."
                )
            except EmptyCaptureError:
                st.error("The uploaded file contains no readable packets.")
            except InvalidPcapError:
                st.error("Please upload a valid PCAP or PCAPNG file.")
            except Exception:
                logger.exception("PCAP analysis failed")
                st.error("Something went wrong while analyzing this file.")
            finally:
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass


# ---------------------------------------------------------------------------
# Page: Communication Fingerprint
# ---------------------------------------------------------------------------
def page_fingerprint():
    st.title("🧬 Communication Fingerprints")
    st.markdown("Examine structural communication habits and behavioral feature distributions per device.")
    
    fingerprints = st.session_state["fingerprints"]
    if not fingerprints:
        st.info("ℹ️ Run an analysis on the **Live Analyzer** or **PCAP Analyzer** page first to generate fingerprints.")
        return

    st.caption(
        "💡 *Each fingerprint ID is a project-level behavioral identifier derived "
        "from this session's traffic features - not a globally unique device identity.*"
    )
    st.markdown("---")

    for src_ip, fp in fingerprints.items():
        with st.container(border=True):
            cols = st.columns([2, 1])
            cols[0].subheader(f"💻 Device: `{src_ip}`")
            cols[1].caption(f"**Fingerprint ID:** `{fp['fingerprint_id']}`")
            st.markdown("---")
            for label, pct in fp["bars"].items():
                st.text(f"{label:<28}{bar_string(pct)}")


# ---------------------------------------------------------------------------
# Page: AI Analysis
# ---------------------------------------------------------------------------
def page_ai_analysis():
    st.title("🤖 AI Behavioral Review")
    review = st.session_state["ai_review"]
    anomaly_results = st.session_state["anomaly_results"]

    if not review:
        st.info("ℹ️ Run an analysis on the **Live Analyzer** or **PCAP Analyzer** page first.")
        return

    cols = st.columns(4)
    cols[0].metric("Classification", review["classification"])
    cols[1].metric("Anomaly Score", f"{review['anomaly_score']:.2f}")
    cols[2].metric("Risk Score", f"{review['risk_score']:.0f}/100")
    cols[3].metric("Severity", review["severity"])

    st.markdown("---")
    with st.container(border=True):
        st.subheader(f"📌 {review['title']}")
        if review["deviations"]:
            st.write("**Observed Behavioral Deviations:**")
            for bullet in review["deviations"]:
                st.markdown(f"- {bullet}")
        st.markdown("#### **Interpretation**")
        st.write(review["interpretation"])
        st.markdown("#### **Recommended Action**")
        st.write(review["recommendation"])
        st.caption(f"🔒 *{review['disclaimer']}*")

    if anomaly_results:
        st.divider()
        st.subheader("📊 Per-Device Anomaly Breakdown")
        rows = [
            {
                "Device": r.src_ip,
                "Classification": "🚨 ANOMALOUS" if r.is_anomalous else "✅ NORMAL",
                "Anomaly Score": round(r.anomaly_score, 1),
            }
            for r in anomaly_results
        ]
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)


# ---------------------------------------------------------------------------
# Page: What Changed?
# ---------------------------------------------------------------------------
def page_what_changed():
    st.title("📈 What Changed? (Baseline Comparison)")
    comparison = st.session_state["comparison"]

    if comparison is None or comparison.empty:
        st.info(
            "ℹ️ No baseline comparison is available yet. A baseline is "
            "established automatically the first time enough traffic is analyzed."
        )
        return

    if has_significant_deviation(comparison):
        st.warning("⚠️ **Significant behavioral deviation detected** in one or more tracked metrics below.")
    else:
        st.success("✅ **Current traffic is stable** and broadly consistent with the established baseline.")

    st.markdown("---")
    display = comparison.copy()
    display["percentage_change"] = display["percentage_change"].map(lambda v: f"{v:+.0f}%")
    display = display.rename(columns={
        "metric": "Metric", "baseline": "Baseline", "current": "Current",
        "absolute_change": "Absolute Change", "percentage_change": "Change",
        "significant": "Significant Deviation",
    })
    st.dataframe(display, use_container_width=True, hide_index=True)
    st.caption("💡 *Anomalous does not automatically mean malicious — review flagged metrics in proper network context.*")


# ---------------------------------------------------------------------------
# Page: Traffic Statistics
# ---------------------------------------------------------------------------
def page_traffic_statistics():
    st.title("📊 Traffic Statistics & Analytics")
    df = st.session_state["df"]
    if df is None or df.empty:
        st.info("ℹ️ Run an analysis on the **Live Analyzer** or **PCAP Analyzer** page first.")
        return

    stats = compute_summary_stats(df)
    cols = st.columns(4)
    cols[0].metric("Total Packets", f"{stats['total_packets']:,}")
    cols[1].metric("Total Bytes", f"{int(stats['total_bytes']):,}")
    cols[2].metric("Duration", f"{stats['duration_seconds']:.1f}s")
    cols[3].metric("Unique Devices", stats["unique_devices"])

    st.markdown("---")
    c1, c2 = st.columns(2)
    with c1:
        st.plotly_chart(protocol_distribution_figure(df), use_container_width=True)
    with c2:
        st.plotly_chart(traffic_over_time_figure(df), use_container_width=True)

    st.markdown("---")
    c3, c4, c5 = st.columns(3)
    with c3:
        st.plotly_chart(top_talkers_figure(df, "src_ip", "Top Source IPs"), use_container_width=True)
    with c4:
        st.plotly_chart(top_talkers_figure(df, "dst_ip", "Top Destination IPs"), use_container_width=True)
    with c5:
        st.plotly_chart(top_talkers_figure(df, "dst_port", "Top Destination Ports"), use_container_width=True)


# ---------------------------------------------------------------------------
# Page: Analysis History
# ---------------------------------------------------------------------------
def page_history():
    st.title("📜 Analysis History Audit Trail")
    st.markdown("Review past network capture sessions, risk scores, and anomaly counts.")
    
    history = database.get_analysis_history()
    if not history:
        st.info("ℹ️ No analyses recorded in history yet.")
        return
        
    st.markdown("---")
    df = pd.DataFrame(history)
    st.dataframe(df, use_container_width=True, hide_index=True)


PAGE_FUNCS = {
    "Overview": page_overview,
    "Live Analyzer": page_live_analyzer,
    "PCAP Analyzer": page_pcap_analyzer,
    "Communication Fingerprint": page_fingerprint,
    "AI Analysis": page_ai_analysis,
    "What Changed?": page_what_changed,
    "Traffic Statistics": page_traffic_statistics,
    "Analysis History": page_history,
}

current_page_func = PAGE_FUNCS.get(st.session_state["active_page"], page_overview)
current_page_func()