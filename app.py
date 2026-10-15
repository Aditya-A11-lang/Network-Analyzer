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
    page_icon=None,
    layout="wide",
)

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
        "df": None,                # last parsed metadata DataFrame
        "features": None,          # last per-device feature DataFrame
        "fingerprints": None,      # last fingerprint dict
        "anomaly_results": None,   # last list[AnomalyResult]
        "comparison": None,        # last What-Changed DataFrame
        "risk_result": None,       # last risk_scoring result dict
        "ai_review": None,         # last ai_review dict (aggregate)
        "source": None,            # 'live' or 'pcap'
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
    """Run the full pipeline (features -> fingerprints -> anomaly ->
    baseline compare -> risk -> AI review -> persist) on a metadata
    DataFrame, storing everything needed by the dashboard pages."""
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

    # Anomaly detection: train a fresh model on this sample if none exists
    # yet, otherwise reuse the persisted baseline model.
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

    # Baseline / What Changed
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

    # Aggregate risk + AI review (based on the worst-scoring device, if any)
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

    # Persist analysis history + fingerprints
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
# Sidebar navigation
# ---------------------------------------------------------------------------
st.sidebar.title("Network Analyzer with AI")
st.sidebar.caption("AI-Based Network Communication Fingerprinting and Anomaly Detection")
page = st.sidebar.radio("Navigate", PAGES, label_visibility="collapsed")

with st.sidebar.expander("Privacy notice", expanded=False):
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
    st.title("Overview")
    metrics = database.get_overview_metrics()
    avg_risk = float(metrics.get("average_risk") or 0.0)
    anomalies = int(metrics.get("total_anomalies") or 0)
    devices = int(metrics.get("active_devices") or 0)
    total_analyses = int(metrics.get("total_analyses") or 0)
    anomaly_rate = (anomalies / devices) if devices else 0.0
    health = calculate_network_health(avg_risk, anomaly_rate)

    cols = st.columns(6)
    cols[0].metric("Network Health", f"{health}/100")
    cols[1].metric("Active Devices", devices)
    cols[2].metric("Packets", f"{int(metrics.get('total_packets') or 0):,}")
    cols[3].metric("Bytes", f"{int(metrics.get('total_bytes') or 0):,}")
    cols[4].metric("Anomalies", anomalies)
    cols[5].metric("Average Risk", f"{avg_risk:.1f}")

    st.caption(
        "Network Health and Risk Score are project-defined analytical metrics, "
        "not industry-standard security ratings."
    )
    st.divider()

    if total_analyses == 0:
        st.info(
            "No analyses yet. Head to **PCAP Analyzer** to upload a capture, "
            "or **Live Analyzer** to capture traffic locally."
        )
    else:
        st.write(f"**{total_analyses}** analyses recorded so far. See **Analysis History** for details.")


# ---------------------------------------------------------------------------
# Page: Live Analyzer
# ---------------------------------------------------------------------------
def page_live_analyzer():
    st.title("Live Analyzer")

    if capture.is_cloud_environment():
        st.warning(
            "Live capture requires running the application locally on an "
            "authorized machine. Cloud deployments support PCAP upload and "
            "analysis - use the **PCAP Analyzer** page instead."
        )
        return

    st.info(
        "This captures traffic on **this machine's** network interface only. "
        "Ensure you are authorized to monitor this network before proceeding. "
        "No packet payloads are stored; only metadata is analyzed."
    )

    interfaces = capture.list_interfaces()
    interface = None
    if interfaces:
        interface = st.selectbox("Network interface (optional)", ["Auto-detect"] + interfaces)
        interface = None if interface == "Auto-detect" else interface
    else:
        st.caption("No interface list available - Auto-detect will be used.")

    state: capture.CaptureState = st.session_state["capture_state"]

    col1, col2 = st.columns(2)
    start_clicked = col1.button("START ANALYZER", disabled=state.running, use_container_width=True)
    stop_clicked = col2.button("STOP & ANALYZE", disabled=not state.running, use_container_width=True)

    if start_clicked:
        try:
            capture.start_capture(state, interface=interface)
            st.rerun()
        except RuntimeError as exc:
            st.error(str(exc))

    if state.running:
        status_cols = st.columns(4)
        status_cols[0].metric("Status", "CAPTURING")
        status_cols[1].metric("Elapsed", f"{state.elapsed():.0f}s")
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
            st.warning("No packets were captured. Try again with more network activity.")
        else:
            with st.spinner("Parsing captured packets and running analysis..."):
                try:
                    df = packets_to_dataframe(state.packets)
                    run_full_analysis(df, source="live")
                    st.success(
                        f"Analyzed {len(df)} packets from {df['src_ip'].nunique()} device(s). "
                        "See AI Analysis, Communication Fingerprint, and What Changed? pages."
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
    st.title("PCAP Analyzer")
    st.caption(
        "Upload a .pcap or .pcapng file. Works in local and cloud deployments. "
        "Only packet metadata is read - payload contents are never stored."
    )

    uploaded = st.file_uploader("Upload capture file", type=["pcap", "pcapng"])
    if uploaded is None:
        return

    if st.button("Analyze PCAP", type="primary"):
        with st.spinner("Parsing PCAP and running the full analysis pipeline..."):
            try:
                with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
                    tmp_path = tmp.name
                df = parse_pcap_bytes(uploaded.getvalue(), tmp_path)
                run_full_analysis(df, source="pcap")
                st.success(
                    f"Analyzed {len(df)} packets from {df['src_ip'].nunique()} device(s). "
                    "See AI Analysis, Communication Fingerprint, and What Changed? pages."
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
    st.title("Communication Fingerprint")
    fingerprints = st.session_state["fingerprints"]
    if not fingerprints:
        st.info("Run an analysis on the Live Analyzer or PCAP Analyzer page first.")
        return

    st.caption(
        "Each fingerprint ID is a project-level behavioral identifier derived "
        "from this session's traffic features - not a globally unique device identity."
    )

    for src_ip, fp in fingerprints.items():
        with st.container(border=True):
            st.subheader(f"Device: {src_ip}")
            st.caption(f"Fingerprint ID: `{fp['fingerprint_id']}`")
            for label, pct in fp["bars"].items():
                st.text(f"{label:<28}{bar_string(pct)}")


# ---------------------------------------------------------------------------
# Page: AI Analysis
# ---------------------------------------------------------------------------
def page_ai_analysis():
    st.title("AI Analysis")
    review = st.session_state["ai_review"]
    anomaly_results = st.session_state["anomaly_results"]

    if not review:
        st.info("Run an analysis on the Live Analyzer or PCAP Analyzer page first.")
        return

    cols = st.columns(4)
    cols[0].metric("Classification", review["classification"])
    cols[1].metric("Anomaly Score", f"{review['anomaly_score']:.2f}")
    cols[2].metric("Risk Score", f"{review['risk_score']:.0f}/100")
    cols[3].metric("Severity", review["severity"])

    st.subheader(review["title"])
    if review["deviations"]:
        st.write("**Observed deviations:**")
        for bullet in review["deviations"]:
            st.write(f"- {bullet}")
    st.write("**Interpretation**")
    st.write(review["interpretation"])
    st.write("**Recommendation**")
    st.write(review["recommendation"])
    st.caption(review["disclaimer"])

    if anomaly_results:
        st.divider()
        st.subheader("Per-device results")
        rows = [
            {
                "Device": r.src_ip,
                "Classification": "ANOMALOUS" if r.is_anomalous else "NORMAL",
                "Anomaly Score": round(r.anomaly_score, 1),
            }
            for r in anomaly_results
        ]
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)


# ---------------------------------------------------------------------------
# Page: What Changed?
# ---------------------------------------------------------------------------
def page_what_changed():
    st.title("What Changed?")
    comparison = st.session_state["comparison"]

    if comparison is None or comparison.empty:
        st.info(
            "No baseline comparison is available yet. A baseline is "
            "established automatically the first time enough traffic is analyzed."
        )
        return

    if has_significant_deviation(comparison):
        st.warning("Significant behavioral deviation detected in one or more metrics below.")
    else:
        st.success("Current traffic is broadly consistent with the established baseline.")

    display = comparison.copy()
    display["percentage_change"] = display["percentage_change"].map(lambda v: f"{v:+.0f}%")
    display = display.rename(columns={
        "metric": "Metric", "baseline": "Baseline", "current": "Current",
        "absolute_change": "Absolute Change", "percentage_change": "Change",
        "significant": "Significant",
    })
    st.dataframe(display, use_container_width=True, hide_index=True)
    st.caption("Anomalous does not automatically mean malicious - review flagged metrics for context.")


# ---------------------------------------------------------------------------
# Page: Traffic Statistics
# ---------------------------------------------------------------------------
def page_traffic_statistics():
    st.title("Traffic Statistics")
    df = st.session_state["df"]
    if df is None or df.empty:
        st.info("Run an analysis on the Live Analyzer or PCAP Analyzer page first.")
        return

    stats = compute_summary_stats(df)
    cols = st.columns(4)
    cols[0].metric("Total Packets", f"{stats['total_packets']:,}")
    cols[1].metric("Total Bytes", f"{int(stats['total_bytes']):,}")
    cols[2].metric("Duration (s)", f"{stats['duration_seconds']:.1f}")
    cols[3].metric("Devices", stats["unique_devices"])

    c1, c2 = st.columns(2)
    c1.plotly_chart(protocol_distribution_figure(df), use_container_width=True)
    c2.plotly_chart(traffic_over_time_figure(df), use_container_width=True)

    c3, c4, c5 = st.columns(3)
    c3.plotly_chart(top_talkers_figure(df, "src_ip", "Top Source IPs"), use_container_width=True)
    c4.plotly_chart(top_talkers_figure(df, "dst_ip", "Top Destination IPs"), use_container_width=True)
    c5.plotly_chart(top_talkers_figure(df, "dst_port", "Top Destination Ports"), use_container_width=True)


# ---------------------------------------------------------------------------
# Page: Analysis History
# ---------------------------------------------------------------------------
def page_history():
    st.title("Analysis History")
    history = database.get_analysis_history()
    if not history:
        st.info("No analyses recorded yet.")
        return
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

PAGE_FUNCS[page]()
