
from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
import time

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

sys.path.insert(0, os.path.dirname(__file__))

from src import capture, database, iam
from src.help_assistant import answer_user_query
from src.packet_parser import (
    parse_pcap_bytes,
    InvalidPcapError,
    EmptyCaptureError,
    metadata_rows_to_dataframe,
)
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
    page_title="Network Packet Analyzer with AI",
    page_icon="",
    layout="wide",
)

# ---------------------------------------------------------------------------
# Shared workspace styling
# ---------------------------------------------------------------------------
st.markdown("""
<style>
    .stApp {
        background: var(--na-background, #f5f8f5);
        color: var(--na-text, #193b3b);
        font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }

    .main .block-container {
        padding-top: 1.5rem;
        padding-bottom: 3rem;
        max-width: 1440px;
        animation: fadeIn 0.45s cubic-bezier(0.2, 0.7, 0.25, 1);
    }

    .main h1 {
        color: var(--na-text);
        font-size: clamp(1.7rem, 3vw, 2.25rem);
        letter-spacing: -0.035em;
    }

    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(7px); }
        to { opacity: 1; transform: translateY(0); }
    }

    .auth-intro {
        max-width: 34rem;
        padding: 1rem 0.5rem;
        animation: fadeIn 0.65s cubic-bezier(0.2, 0.7, 0.25, 1);
    }

    .auth-wordmark {
        display: flex;
        align-items: center;
        gap: 0.65rem;
        color: #2b6660;
        font-size: 0.75rem;
        font-weight: 750;
        letter-spacing: 0.13em;
    }

    .auth-mark {
        display: inline-block;
        width: 0.8rem;
        height: 0.8rem;
        border: 2px solid #36877b;
        border-radius: 0.28rem;
        box-shadow: 0 0 0 4px rgba(54, 135, 123, 0.1);
    }

    .auth-eyebrow {
        margin: 0.45rem 0 0;
        color: #71847e;
        font-size: 0.76rem;
        letter-spacing: 0.08em;
        text-transform: uppercase;
    }

    .auth-intro h1 {
        margin: 1.6rem 0 0.8rem;
        color: #193b3b;
        font-size: clamp(2.2rem, 4.2vw, 3rem);
        line-height: 1.08;
        letter-spacing: -0.045em;
    }

    .auth-intro h1 span {
        color: #378176;
    }

    .auth-intro p {
        max-width: 30rem;
        color: #5a716d;
        font-size: 1.02rem;
        line-height: 1.75;
    }

    .auth-local-status {
        display: inline-flex;
        align-items: center;
        gap: 0.6rem;
        margin-top: 1.15rem;
        padding: 0.65rem 0.85rem;
        border: 1px solid #dce9e1;
        border-radius: 999px;
        background: rgba(255, 255, 255, 0.72);
        color: #45615c;
        font-size: 0.84rem;
    }

    .auth-local-status span {
        width: 0.55rem;
        height: 0.55rem;
        border-radius: 50%;
        background: #388c70;
        box-shadow: 0 0 0 4px rgba(56, 140, 112, 0.12);
    }

    [class*="st-key-auth_form_card"] {
        border-color: #dce8e0 !important;
        border-radius: 20px !important;
        background: rgba(255, 255, 255, 0.94) !important;
        box-shadow: 0 18px 50px rgba(28, 66, 57, 0.08) !important;
    }

    [class*="st-key-auth_form_card"] h2,
    [class*="st-key-auth_form_card"] h3 {
        color: #193b3b !important;
        letter-spacing: -0.025em;
    }

    [class*="st-key-auth_form_card"] [data-testid="stFormSubmitButton"] button {
        min-height: 2.8rem;
        border-radius: 10px;
        font-weight: 650;
        transition: box-shadow 180ms ease, transform 180ms ease;
    }

    [class*="st-key-auth_form_card"] [data-testid="stFormSubmitButton"] button:hover {
        box-shadow: 0 6px 16px rgba(24, 111, 99, 0.2);
        transform: translateY(-1px);
    }

    @media (prefers-reduced-motion: reduce) {
        *, *::before, *::after {
            animation-duration: 0.01ms !important;
            animation-iteration-count: 1 !important;
            scroll-behavior: auto !important;
            transition-duration: 0.01ms !important;
        }
    }

    .top-header-bar {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 1rem;
        flex-wrap: wrap;
        background: linear-gradient(120deg, #07122b 0%, #0a1d44 60%, #0d2a62 100%);
        padding: 1.25rem 1.6rem;
        border: 1px solid rgba(59, 130, 246, 0.28);
        border-radius: 18px;
        margin-bottom: 1.1rem;
        box-shadow: 0 12px 28px -12px rgba(7, 18, 43, 0.55);
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

    .header-mark {
        display: inline-block;
        width: 1rem;
        height: 1rem;
        border: 2px solid #38bdf8;
        border-radius: 0.32rem;
        box-shadow: 0 0 0 4px rgba(56, 130, 246, 0.14);
    }

    .top-header-badge {
        font-size: 0.75rem;
        padding: 7px 14px;
        background: rgba(47, 123, 255, 0.14);
        color: #bfdbfe;
        border: 1px solid rgba(96, 165, 250, 0.3);
        border-radius: 20px;
        font-weight: 700;
        letter-spacing: 0.05em;
        text-transform: uppercase;
    }

    .sidebar-brand {
        display: flex;
        align-items: center;
        gap: 0.7rem;
        padding: 0.25rem 0.2rem 0.8rem;
    }

    .sidebar-brand-mark {
        display: grid;
        place-items: center;
        width: 2.35rem;
        height: 2.35rem;
        border: 1px solid rgba(56, 189, 248, 0.45);
        border-radius: 0.8rem;
        background: rgba(47, 123, 255, 0.15);
        color: #7dd3fc !important;
        font-size: 1.25rem;
    }

    .sidebar-brand-name {
        color: var(--na-text);
        font-size: 1.05rem;
        font-weight: 800;
        letter-spacing: -0.025em;
    }

    .sidebar-brand-caption {
        color: var(--na-muted) !important;
        font-size: 0.65rem;
        letter-spacing: 0.11em;
        text-transform: uppercase;
    }

    [class*="st-key-nav_btn_"] button {
        min-height: 2.55rem;
        border-radius: 0.75rem;
        justify-content: flex-start;
        transition: transform 160ms ease, box-shadow 160ms ease;
    }

    [class*="st-key-nav_btn_"] button[kind="primary"] {
        box-shadow: 0 6px 18px rgba(47, 123, 255, 0.22);
    }

    [class*="st-key-nav_btn_"] button:hover {
        transform: translateX(2px);
    }

    .dashboard-hero {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 1.5rem;
        padding: 1.5rem 1.7rem;
        margin: 0.25rem 0 1rem;
        border: 1px solid rgba(59, 130, 246, 0.28);
        border-radius: 1.15rem;
        background:
            radial-gradient(ellipse at 90% 20%, rgba(37, 99, 235, 0.26), transparent 45%),
            linear-gradient(115deg, #07122b 0%, #0a1d44 65%, #0d2a62 100%);
        color: #e6edf8;
    }

    .dashboard-hero-eyebrow {
        color: #93c5fd;
        font-size: 0.7rem;
        font-weight: 700;
        letter-spacing: 0.16em;
        text-transform: uppercase;
    }

    .dashboard-hero h1 {
        margin: 0.3rem 0 0.45rem;
        color: #ffffff;
        font-size: clamp(1.55rem, 3vw, 2.25rem);
        letter-spacing: -0.04em;
    }

    .dashboard-hero p {
        max-width: 42rem;
        margin: 0;
        color: #c3d0e6;
        line-height: 1.6;
    }

    .dashboard-hero-icon {
        width: clamp(3rem, 5vw, 4rem);
        height: clamp(3rem, 5vw, 4rem);
        color: #60a5fa;
        opacity: 0.9;
    }

    [class*="st-key-floating_help"] {
        position: fixed;
        right: 1.25rem;
        bottom: 1.25rem;
        z-index: 1000;
    }

    [class*="st-key-floating_help"] > button {
        min-height: 2.8rem;
        padding: 0.55rem 1rem;
        border: 1px solid rgba(96, 165, 250, 0.4);
        border-radius: 999px;
        background: linear-gradient(100deg, #1d6bff, #1676d2);
        color: #ffffff;
        box-shadow: 0 8px 22px rgba(37, 99, 235, 0.3);
    }

    @media (max-width: 720px) {
        .dashboard-hero {
            padding: 1.2rem;
        }

        .dashboard-hero-icon {
            display: none;
        }
    }

    @media (max-width: 640px) {
        [class*="st-key-floating_help"] {
            right: 0.75rem;
            bottom: 0.75rem;
        }
    }

    div.stContainer {
        border-radius: 16px;
        padding: 1.5rem;
        background: var(--na-surface, #ffffff);
        border: 1px solid var(--na-border, #e2e8f0);
        color: var(--na-text, #193b3b);
        box-shadow: 0 4px 15px -3px rgba(0, 0, 0, 0.05);
    }

    div[data-testid="stMetric"] {
        background: var(--na-surface, #ffffff);
        border: 1px solid var(--na-border, #e2e8f0);
        padding: 14px 18px;
        border-radius: 12px;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.03);
        transition: all 0.2s ease;
    }
    
    div[data-testid="stMetric"]:hover {
        border-color: #82b7a0;
        box-shadow: 0 4px 12px rgba(36, 111, 88, 0.1);
    }
    
    div[data-testid="stMetric"] label {
        color: var(--na-muted) !important;
        font-weight: 600 !important;
        font-size: 0.85rem !important;
    }

    div[data-testid="stMetric"] div[data-testid="stMetricValue"] {
        color: var(--na-text) !important;
        font-weight: 800 !important;
    }

    div[data-testid="stDataFrame"] {
        border-radius: 12px;
        overflow: hidden;
        border: 1px solid var(--na-border, #e2e8f0);
    }
</style>
""", unsafe_allow_html=True)

NAV_GROUPS = {
    "Overview": ["Overview"],
    "Traffic analysis": ["Live Analyzer", "PCAP Analyzer", "Traffic Statistics"],
    "AI & insights": ["AI Analysis", "Communication Fingerprint"],
    "Baselines": ["What Changed?"],
    "History": ["Analysis History"],
    "Help & settings": ["Help Assistant"],
    "Administration": ["User Management"],
}

PAGE_LABELS = {
    "Overview": "Dashboard",
    "Live Analyzer": "Live packet capture",
    "PCAP Analyzer": "PCAP / PCAPNG upload",
    "Traffic Statistics": "Traffic statistics",
    "AI Analysis": "Anomaly and risk review",
    "Communication Fingerprint": "Communication fingerprints",
    "What Changed?": "Behavioral changes",
    "Analysis History": "Previous analyses",
    "Help Assistant": "Help assistant",
    "User Management": "User management",
}

PAGE_ICONS = {
    "Overview": "dashboard",
    "Live Analyzer": "sensors",
    "PCAP Analyzer": "upload_file",
    "Traffic Statistics": "monitoring",
    "AI Analysis": "troubleshoot",
    "Communication Fingerprint": "fingerprint",
    "What Changed?": "compare_arrows",
    "Analysis History": "history",
    "Help Assistant": "help",
    "User Management": "manage_accounts",
}

PAGE_GROUP = {
    page: group
    for group, pages in NAV_GROUPS.items()
    for page in pages
}

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
        "auth_username": None,
        "chat_history": [],
        "analysis_complete_notice": None,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


_init_state()
database.init_db()


def _render_authentication() -> None:
    is_first_run = not iam.has_accounts()
    intro, form_column = st.columns(
        [1.05, 0.95],
        gap="large",
        vertical_alignment="center",
        wrap=True,
    )
    with intro:
        st.markdown(
            """
            <section class="auth-intro">
              <div class="auth-wordmark"><span class="auth-mark"></span> NETWORK ANALYZER</div>
              <p class="auth-eyebrow">Local analysis · Private by design</p>
              <h1>Understand your network.<br><span>At your own pace.</span></h1>
              <p>Explore traffic patterns and device activity in a clear, calm workspace.
                 Your account and analysis stay on this computer.</p>
              <div class="auth-local-status"><span></span> Local workspace ready</div>
            </section>
            """,
            unsafe_allow_html=True,
        )

    with form_column:
        with st.container(key="auth_form_card", border=True):
            if is_first_run:
                st.subheader("Create your administrator account")
                st.caption("This one-time setup gives you control over local user access.")
                with st.form("first_admin_setup"):
                    name_column, username_column = st.columns(2, gap="small", wrap=True)
                    full_name = name_column.text_input("Your name")
                    username = username_column.text_input(
                        "Choose a username",
                        help="3–32 letters, numbers, dots, dashes, or underscores.",
                    )
                    password_column, confirm_column = st.columns(2, gap="small", wrap=True)
                    password = password_column.text_input(
                        "Create a password",
                        type="password",
                        help=f"Use at least {iam.MIN_PASSWORD_LENGTH} characters.",
                    )
                    confirm_password = confirm_column.text_input("Confirm password", type="password")
                    submitted = st.form_submit_button("Create administrator account", type="primary")
                if submitted:
                    if password != confirm_password:
                        st.error("The passwords do not match.")
                    else:
                        try:
                            account = iam.create_first_admin(username, password, full_name)
                            st.session_state["auth_username"] = account["username"]
                            st.success("Administrator account created. Opening your dashboard...")
                            st.rerun()
                        except (iam.IAMError, ValueError) as exc:
                            st.error(str(exc))
                        except sqlite3.Error:
                            logger.exception("Could not create the initial administrator account.")
                            st.error("The administrator account could not be saved. Check the local database and try again.")
                st.caption("Use a unique password that is at least 12 characters long.")
                return

            st.subheader("Welcome back")
            st.caption("Sign in with your local account to continue.")
            with st.form("local_sign_in"):
                username = st.text_input("Username", autocomplete="username")
                password = st.text_input("Password", type="password", autocomplete="current-password")
                submitted = st.form_submit_button("Sign in", type="primary")
            if submitted:
                try:
                    account = iam.authenticate_user(username, password)
                except sqlite3.Error:
                    logger.exception("Local account sign-in failed because the database was unavailable.")
                    st.error("Sign-in is temporarily unavailable because the local account database could not be read.")
                    return
                if account is None:
                    st.error("Username or password is incorrect, or this account is disabled.")
                else:
                    st.session_state["auth_username"] = account["username"]
                    st.rerun()
            st.caption("Forgot your password? Ask an administrator to reset it.")


def _require_login() -> dict | None:
    username = st.session_state.get("auth_username")
    if not username:
        try:
            _render_authentication()
        except sqlite3.Error:
            logger.exception("Unable to load the local account database.")
            st.error("The local account database could not be opened.")
        return None
    try:
        account = iam.get_user(username)
    except (ValueError, sqlite3.Error):
        logger.exception("Unable to validate the local account.")
        st.error("The local account database could not be checked.")
        return None
    if account is None or not account["is_active"]:
        st.session_state["auth_username"] = None
        st.warning("This account is unavailable. Please sign in again.")
        _render_authentication()
        return None
    return account


THEME_OPTIONS = ("Light", "Dark", "System Default")

THEME_PALETTES = {
    "Light": {
        "background": "#f5f8f5",
        "surface": "#ffffff",
        "surface_muted": "#eaf1ec",
        "text": "#193b3b",
        "muted": "#607773",
        "border": "#dce7e0",
        "accent": "#28796e",
        "grid": "#dfe8e2",
    },
    "Dark": {
        "background": "#050b1c",
        "surface": "#0b1730",
        "surface_muted": "#102044",
        "text": "#e6edf8",
        "muted": "#8fa3c4",
        "border": "rgba(59, 130, 246, 0.28)",
        "accent": "#2f7bff",
        "grid": "#1f3152",
    },
}


def _save_theme_preference(username: str) -> None:
    try:
        database.set_user_theme(username, st.session_state["theme_preference"])
        st.session_state["theme_save_error"] = None
    except (sqlite3.Error, ValueError):
        logger.exception("Could not save the local theme preference.")
        st.session_state["theme_save_error"] = "Theme preference could not be saved."


def _apply_theme_styles(theme: str) -> None:
    palette = THEME_PALETTES["Dark" if theme == "Dark" else "Light"]
    system_dark_css = ""
    if theme == "System Default":
        dark = THEME_PALETTES["Dark"]
        system_dark_css = f"""
        @media (prefers-color-scheme: dark) {{
            :root {{
                --na-background: {dark['background']};
                --na-surface: {dark['surface']};
                --na-surface-muted: {dark['surface_muted']};
                --na-text: {dark['text']};
                --na-muted: {dark['muted']};
                --na-border: {dark['border']};
                --na-accent: {dark['accent']};
                --na-grid: {dark['grid']};
            }}
        }}
        """

    st.markdown(
        f"""
        <style>
        :root {{
            --na-background: {palette['background']};
            --na-surface: {palette['surface']};
            --na-surface-muted: {palette['surface_muted']};
            --na-text: {palette['text']};
            --na-muted: {palette['muted']};
            --na-border: {palette['border']};
            --na-accent: {palette['accent']};
            --na-grid: {palette['grid']};
        }}
        .stApp, [data-testid="stAppViewContainer"], section.main {{
            background: var(--na-background) !important;
            color: var(--na-text) !important;
        }}
        [data-testid="stSidebar"] {{
            background: var(--na-surface) !important;
            border-right: 1px solid var(--na-border);
        }}
        [data-testid="stSidebar"] * {{ color: var(--na-text); }}
        [data-testid="stMetric"], [data-testid="stVerticalBlockBorderWrapper"] > div {{
            background: var(--na-surface) !important;
            color: var(--na-text) !important;
            border-color: var(--na-border) !important;
        }}
        div.stContainer {{
            background: var(--na-surface) !important;
            color: var(--na-text) !important;
            border-color: var(--na-border) !important;
        }}
        [data-testid="stMetric"] label, [data-testid="stCaptionContainer"] {{
            color: var(--na-muted) !important;
        }}
        [data-testid="stAppViewContainer"] label,
        [data-testid="stAppViewContainer"] [data-testid="stMarkdownContainer"] p,
        [data-testid="stAppViewContainer"] [data-testid="stMarkdownContainer"] li {{
            color: var(--na-text) !important;
        }}
        [data-testid="stAppViewContainer"] [data-testid="stMarkdownContainer"] .dashboard-hero p {{
            color: #c3d0e6 !important;
        }}
        [data-testid="stSidebar"] p,
        [data-testid="stSidebar"] label,
        [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] {{
            color: var(--na-text) !important;
        }}
        [data-testid="stTextInput"] input, [data-testid="stTextArea"] textarea,
        [data-testid="stNumberInput"] input, [data-testid="stDateInput"] input,
        [data-testid="stSelectbox"] [data-baseweb="select"],
        [data-testid="stMultiSelect"] [data-baseweb="select"],
        [data-testid="stFileUploader"] section {{
            background: var(--na-surface-muted) !important;
            color: var(--na-text) !important;
            border-color: var(--na-border) !important;
        }}
        [data-testid="stSelectbox"] [data-baseweb="select"] *,
        [data-testid="stMultiSelect"] [data-baseweb="select"] *,
        [data-testid="stTextInput"] input,
        [data-testid="stTextArea"] textarea,
        [data-testid="stNumberInput"] input,
        [data-testid="stDateInput"] input {{
            color: var(--na-text) !important;
            caret-color: var(--na-text);
        }}
        [data-baseweb="popover"], [data-baseweb="menu"], [role="listbox"],
        [role="option"], [role="dialog"], [data-testid="stExpander"] details {{
            background: var(--na-surface) !important;
            color: var(--na-text) !important;
            border-color: var(--na-border) !important;
        }}
        [role="option"]:hover, [role="option"][aria-selected="true"] {{
            background: var(--na-surface-muted) !important;
        }}
        [data-testid="stDataFrame"], [data-testid="stTable"] {{
            border: 1px solid var(--na-border);
            border-radius: 12px;
            overflow: hidden;
        }}
        [data-testid="stAlert"] {{
            background: var(--na-surface) !important;
            color: var(--na-text) !important;
            border-color: var(--na-border) !important;
        }}
        [data-testid="stBaseButton-primary"] {{
            background: var(--na-accent) !important;
            border-color: var(--na-accent) !important;
        }}
        [data-testid="stBaseButton-secondary"] {{
            background: var(--na-surface) !important;
            color: var(--na-text) !important;
            border-color: var(--na-border) !important;
        }}
        [data-testid="stBaseButton-secondary"]:hover,
        [data-testid="stBaseButton-primary"]:hover {{
            transform: translateY(-1px);
            transition: transform 160ms ease, box-shadow 160ms ease;
            box-shadow: 0 5px 14px rgba(37, 105, 91, 0.16);
        }}
        .js-plotly-plot .xtick text, .js-plotly-plot .ytick text,
        .js-plotly-plot .legendtext, .js-plotly-plot .gtitle,
        .js-plotly-plot .annotation-text {{
            fill: var(--na-text) !important;
        }}
        .js-plotly-plot .gridlayer path, .js-plotly-plot .zerolinelayer path {{
            stroke: var(--na-grid) !important;
        }}
        .js-plotly-plot .hoverlayer .hovertext path {{
            fill: var(--na-surface) !important;
            stroke: var(--na-border) !important;
        }}
        .js-plotly-plot .hoverlayer .hovertext text {{
            fill: var(--na-text) !important;
        }}
        @media (prefers-reduced-motion: reduce) {{
            *, *::before, *::after {{
                animation-duration: 0.01ms !important;
                animation-iteration-count: 1 !important;
                scroll-behavior: auto !important;
                transition-duration: 0.01ms !important;
            }}
        }}
        {system_dark_css}
        </style>
        """,
        unsafe_allow_html=True,
    )


def _style_plotly_figure(figure: go.Figure) -> go.Figure:
    theme = st.session_state.get("theme_preference", "Light")
    is_dark = theme == "Dark"
    palette = THEME_PALETTES["Dark" if is_dark else "Light"]
    figure.update_layout(
        template="plotly_dark" if is_dark else "plotly_white",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color=palette["text"],
        hoverlabel={
            "bgcolor": palette["surface"],
            "font_color": palette["text"],
            "bordercolor": palette["border"],
        },
    )
    figure.update_xaxes(gridcolor=palette["grid"], zerolinecolor=palette["grid"])
    figure.update_yaxes(gridcolor=palette["grid"], zerolinecolor=palette["grid"])
    return figure


def _navigate_to(page: str) -> None:
    st.session_state["navigate_to"] = page
    st.rerun()


@st.dialog("Configure live capture")
def _render_live_capture_dialog() -> None:
    if capture.is_cloud_environment():
        st.warning(
            "Live capture is only available when the app runs locally. "
            "Use PCAP Analyzer to analyze an uploaded capture."
        )
        return

    interfaces = capture.list_interfaces()
    if interfaces:
        options = ["Auto-detect"] + interfaces
        st.caption("Choose the local interface that carries the traffic you are authorized to monitor.")
    else:
        options = ["Auto-detect"]
        st.warning(
            "No interfaces were listed. Auto-detect will be tried; on Windows, "
            "live capture also requires Npcap."
        )

    interface = st.selectbox("Network interface", options, key="capture_setup_interface")
    duration = st.number_input(
        "Capture duration (seconds)",
        min_value=1,
        max_value=3600,
        value=60,
        step=5,
        key="capture_setup_duration",
    )
    st.caption("Only packet metadata is collected. Capture stops automatically at the selected duration.")

    if st.button("Start capture", type="primary", icon=":material/play_arrow:", width="stretch"):
        try:
            state = st.session_state["capture_state"]
            capture.start_capture(
                state,
                interface=None if interface == "Auto-detect" else interface,
                max_duration=int(duration),
            )
            st.session_state["active_page"] = "Live Analyzer"
            st.rerun()
        except (RuntimeError, ValueError) as exc:
            st.error(str(exc))


def _render_floating_help() -> None:
    current_df = st.session_state.get("df")
    context = {
        "active_page": st.session_state.get("active_page", "Overview"),
        "has_data": current_df is not None and not current_df.empty,
        "packet_count": len(current_df) if current_df is not None else 0,
        "risk_score": (
            st.session_state["risk_result"]["risk_score"]
            if st.session_state.get("risk_result")
            else "not available"
        ),
        "classification": (
            st.session_state["ai_review"]["classification"]
            if st.session_state.get("ai_review")
            else "not available"
        ),
    }

    with st.popover(
        "Help",
        key="floating_help",
        icon=":material/help:",
    ):
        st.subheader("NetGuard Help")
        st.caption(f"Guidance for {PAGE_LABELS.get(context['active_page'], 'this page')}")
        st.write(answer_user_query("What should I do on this page?", context))
        with st.expander("Capture live traffic"):
            st.write(answer_user_query("How do I start a live capture?", context))
        with st.expander("Analyze a capture file"):
            st.write(answer_user_query("How do I upload a PCAP file?", context))
        with st.expander("Understand scores"):
            st.write(answer_user_query("What does the risk score mean?", context))
        st.caption("Built-in guidance only. No questions or packet data are sent to an external service.")


def _render_account_controls(account: dict) -> None:
    if st.session_state.get("theme_user") != account["username"]:
        try:
            saved_theme = database.get_user_theme(account["username"])
            st.session_state["theme_preference"] = (
                saved_theme if saved_theme in THEME_OPTIONS else "Dark"
            )
        except sqlite3.Error:
            logger.exception("Could not load the local theme preference.")
            st.session_state["theme_preference"] = "Dark"
            st.session_state["theme_save_error"] = "Saved theme could not be loaded; using Dark mode."
        st.session_state["theme_user"] = account["username"]

    if st.session_state.get("navigate_to") in PAGE_GROUP:
        target_page = st.session_state.pop("navigate_to")
        st.session_state["active_page"] = target_page

    groups = {
        group: pages
        for group, pages in NAV_GROUPS.items()
        if group != "Administration" or account["role"] == "admin"
    }
    if st.session_state["active_page"] == "User Management" and account["role"] != "admin":
        st.session_state["active_page"] = "Overview"

    with st.sidebar:
        st.markdown(
            """
            <div class="sidebar-brand">
              <span class="sidebar-brand-mark">N</span>
              <div>
                <div class="sidebar-brand-name">NetGuard AI</div>
                <div class="sidebar-brand-caption">Network Analyzer</div>
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.caption(f"{account['username']} · {account['role'].title()}")
        for group, pages in groups.items():
            if group != "Overview":
                st.caption(group)
            for page in pages:
                if st.button(
                    PAGE_LABELS[page],
                    key=f"nav_btn_{page}",
                    icon=f":material/{PAGE_ICONS[page]}:",
                    type="primary" if st.session_state["active_page"] == page else "secondary",
                    width="stretch",
                ):
                    st.session_state["active_page"] = page
                    st.rerun()

        st.divider()
        st.selectbox(
            "Appearance",
            THEME_OPTIONS,
            key="theme_preference",
            on_change=_save_theme_preference,
            args=(account["username"],),
        )
        if st.session_state.get("theme_save_error"):
            st.warning(st.session_state["theme_save_error"])

        with st.expander("Privacy and security"):
            st.write(
                "Only traffic metadata is analyzed. Packet payloads, passwords, "
                "and authentication cookies are not stored."
            )
        with st.expander("Account"):
            st.caption(f"Signed in as {account['username']}")
            if st.button("Sign out", key="sign_out", width="stretch"):
                st.session_state["auth_username"] = None
                st.session_state["df"] = None
                st.session_state["features"] = None
                st.session_state["fingerprints"] = None
                st.session_state["anomaly_results"] = None
                st.session_state["comparison"] = None
                st.session_state["risk_result"] = None
                st.session_state["ai_review"] = None
                st.session_state["source"] = None
                st.session_state["last_error"] = None
                st.session_state["chat_history"] = []
                state = st.session_state["capture_state"]
                if state.running:
                    capture.stop_capture(state)
                st.session_state["capture_state"] = capture.CaptureState()
                st.session_state["active_page"] = "Overview"
                st.session_state["theme_user"] = None
                st.rerun()

    _apply_theme_styles(st.session_state["theme_preference"])


current_account = _require_login()
if current_account is None:
    st.stop()
_render_account_controls(current_account)


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
        actor=current_account["username"],
    )
    database.save_fingerprints(analysis_id, fingerprints)


# ---------------------------------------------------------------------------
# Header Bar and active workspace
# ---------------------------------------------------------------------------
active_page = st.session_state["active_page"]
active_group = PAGE_GROUP.get(active_page, "Overview")
st.markdown(
    f"""
    <div class="top-header-bar">
        <div class="top-header-title">
            <span class="header-mark" aria-hidden="true"></span>
            NetGuard AI <span style="font-weight:450;opacity:.78">/ {PAGE_LABELS.get(active_page, 'Dashboard')}</span>
        </div>
        <div class="top-header-badge">Local workspace · {active_group}</div>
    </div>
    """,
    unsafe_allow_html=True,
)

if st.session_state["last_error"]:
    st.sidebar.warning(st.session_state["last_error"])

if st.session_state.get("analysis_complete_notice"):
    st.success(st.session_state.pop("analysis_complete_notice"), title="Analysis complete")

_render_floating_help()


# ---------------------------------------------------------------------------
# Page: Overview
# ---------------------------------------------------------------------------
def page_overview():
    st.markdown(
        """
        <section class="dashboard-hero">
          <div>
            <div class="dashboard-hero-eyebrow">Your local network workspace</div>
            <h1>Understand your network.</h1>
            <p>Analyze a capture, review device behavior, and compare results over time.
               Packet payloads are not stored.</p>
          </div>
          <div>
            <svg class="dashboard-hero-icon" viewBox="0 0 64 64" aria-hidden="true">
              <path d="M32 5 54 14v16c0 13-8.5 23-22 29C18.5 53 10 43 10 30V14z"
                    fill="rgba(7,18,43,.45)" stroke="currentColor" stroke-width="2.5"/>
              <path d="m20 33 8 8 16-18" fill="none" stroke="currentColor"
                    stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
          </div>
        </section>
        """,
        unsafe_allow_html=True,
    )

    action_cols = st.columns(2)
    with action_cols[0]:
        if st.button(
            "Start live analysis",
            type="primary",
            icon=":material/sensors:",
            width="stretch",
        ):
            _render_live_capture_dialog()
    with action_cols[1]:
        if st.button(
            "Upload capture file",
            icon=":material/upload_file:",
            width="stretch",
        ):
            _navigate_to("PCAP Analyzer")

    metrics = database.get_overview_metrics()
    history = database.get_analysis_history(limit=8)
    latest = history[0] if history else None
    avg_risk = float(latest.get("risk_score") or 0.0) if latest else 0.0
    anomalies = int(metrics.get("total_anomalies") or 0)
    devices = int(latest.get("device_count") or 0) if latest else 0
    total_analyses = int(metrics.get("total_analyses") or 0)
    anomaly_rate = (anomalies / int(metrics.get("total_analyses") or 1)) if total_analyses else 0.0
    health = calculate_network_health(avg_risk, anomaly_rate)

    cols = st.columns(4)
    cols[0].metric("Packets analyzed", f"{int(metrics.get('total_packets') or 0):,}")
    cols[1].metric("Devices in latest scan", devices)
    cols[2].metric("Anomalies recorded", anomalies)
    latest_risk = (
        f"{latest.get('severity', 'Unrated')} · {avg_risk:.0f}/100"
        if latest
        else "—"
    )
    cols[3].metric("Latest risk", latest_risk)
    st.caption(
        f"Network health: {health}/100 · Based on saved analysis metadata; "
        "risk scores are project-defined indicators, not industry ratings."
    )

    current_df = st.session_state["df"]
    st.subheader("Network activity")
    chart_columns = st.columns(2, gap="large")
    if current_df is not None and not current_df.empty:
        with chart_columns[0]:
            st.plotly_chart(
                _style_plotly_figure(protocol_distribution_figure(current_df)),
                width="stretch",
                key="overview_protocol_chart",
            )
        with chart_columns[1]:
            st.plotly_chart(
                _style_plotly_figure(traffic_over_time_figure(current_df)),
                width="stretch",
                key="overview_traffic_chart",
            )
    elif history:
        ordered = list(reversed(history))
        dates = pd.to_datetime([row["timestamp"] for row in ordered], utc=True)
        risk_figure = go.Figure(
            go.Scatter(
                x=dates,
                y=[row["risk_score"] for row in ordered],
                mode="lines+markers",
                name="Risk score",
                line={"color": THEME_PALETTES["Dark" if st.session_state["theme_preference"] == "Dark" else "Light"]["accent"], "width": 2},
            )
        )
        risk_figure.update_layout(
            title="Risk score across recent scans",
            yaxis_title="Risk score (0–100)",
            margin={"t": 50, "b": 20, "l": 10, "r": 10},
        )
        with chart_columns[0]:
            st.plotly_chart(
                _style_plotly_figure(risk_figure),
                width="stretch",
                key="overview_risk_chart",
            )
        with chart_columns[1]:
            st.info("Analyze a new capture to view its protocol mix and traffic timeline.")
    else:
        with chart_columns[0]:
            st.info("No scan data yet. Start a live analysis or upload a capture file.")
        with chart_columns[1]:
            st.info("Traffic charts will appear here after your first analysis.")

    talkers_column, history_column = st.columns([1, 1.15], gap="large")
    with talkers_column:
        st.subheader("Top source devices")
        if current_df is not None and not current_df.empty:
            talkers = (
                current_df.groupby("src_ip", as_index=False)
                .agg(Packets=("src_ip", "size"), Bytes=("length", "sum"))
                .sort_values("Packets", ascending=False)
                .head(5)
                .rename(columns={"src_ip": "Device"})
            )
            st.dataframe(talkers, width="stretch", hide_index=True)
        else:
            st.caption("Analyze a capture to see the most active source devices.")

    with history_column:
        st.subheader("Recent activity")
        if history:
            recent = pd.DataFrame(history).rename(
                columns={
                    "timestamp": "Time",
                    "source": "Source",
                    "packet_count": "Packets",
                    "device_count": "Devices",
                    "severity": "Severity",
                    "risk_score": "Risk",
                }
            )
            columns = ["Time", "Source", "Packets", "Devices", "Severity", "Risk"]
            st.dataframe(
                recent[[column for column in columns if column in recent.columns]],
                width="stretch",
                hide_index=True,
            )
            st.caption(f"{total_analyses} saved analyses · Open History for the full list.")
        else:
            st.info("Completed scans will appear here and remain available after sign-out.")


# ---------------------------------------------------------------------------
# Page: Live Analyzer
# ---------------------------------------------------------------------------
def page_live_analyzer():
    st.title("Live packet capture")
    st.caption("Capture metadata from an authorized network interface on this computer.")

    if capture.is_cloud_environment():
        st.warning(
            "Live capture requires running the application locally on an "
            "authorized machine. Cloud deployments support PCAP upload and "
            "analysis - please use the **PCAP Analyzer** page instead."
        )
        return

    st.info(
        "This captures traffic on **this machine's** network interface only. "
        "Ensure you are authorized to monitor this network before proceeding. "
        "No packet payloads are stored; only metadata is analyzed."
    )

    state: capture.CaptureState = st.session_state["capture_state"]
    interfaces = capture.list_interfaces()
    interface_options = ["Auto-detect"] + interfaces
    interface_choice = st.selectbox(
        "Network interface",
        interface_options,
        key="live_capture_interface",
        disabled=state.running,
    )
    if not interfaces:
        st.caption("No interfaces were listed. Auto-detect will be tried; on Windows, live capture requires Npcap.")
    duration = st.number_input(
        "Capture duration (seconds)",
        min_value=1,
        max_value=3600,
        value=60,
        step=5,
        key="live_capture_duration",
        disabled=state.running,
    )

    if state.error:
        from src.utils import FRIENDLY_MESSAGES

        if state.error == "packet_limit":
            st.warning("The capture reached the 50,000-packet limit. Captured packets are still available to analyze.")
        else:
            st.error(FRIENDLY_MESSAGES.get(state.error, FRIENDLY_MESSAGES["generic"]))

    col1, col2 = st.columns(2)
    start_clicked = col1.button(
        "Start capture",
        icon=":material/play_arrow:",
        disabled=state.running,
        type="primary",
        width="stretch",
    )
    stop_clicked = col2.button(
        "Stop capture",
        icon=":material/stop:",
        disabled=not state.running,
        width="stretch",
    )

    if start_clicked:
        try:
            capture.start_capture(
                state,
                interface=None if interface_choice == "Auto-detect" else interface_choice,
                max_duration=int(duration),
            )
            st.rerun()
        except (RuntimeError, ValueError) as exc:
            st.error(str(exc))

    if stop_clicked:
        capture.stop_capture(state)
        st.rerun()

    if state.running:
        st.markdown("---")
        status_cols = st.columns(4)
        status_cols[0].metric("Status", "Capturing")
        status_cols[1].metric("Elapsed Time", f"{state.elapsed():.0f}s")
        status_cols[2].metric("Packets Captured", state.packet_count)
        status_cols[3].metric("Total Bytes", f"{state.total_bytes:,}")
        st.caption(f"Capture stops automatically after {state.max_duration:,} seconds.")
        time.sleep(1)
        st.rerun()

    if not state.running and state.start_time is not None:
        st.metric("Capture status", "Stopped")
        st.caption(
            f"Captured {state.packet_count:,} packets and {state.total_bytes:,} bytes "
            f"in {state.elapsed():.1f} seconds."
        )

    if not state.running and not state.records and not state.error:
        st.info("No packets captured yet. Start a capture, then generate some authorized network traffic.")

    if st.button(
        "Analyze captured traffic",
        type="primary",
        icon=":material/analytics:",
        disabled=state.running or not state.records,
        width="stretch",
    ):
        with st.spinner("Analyzing captured packet metadata..."):
            try:
                df = metadata_rows_to_dataframe(state.records)
                run_full_analysis(df, source="live")
                st.session_state["analysis_complete_notice"] = (
                    f"Analyzed {len(df):,} packets from {df['src_ip'].nunique()} device(s). "
                    "Review the findings below or use AI & insights for more detail."
                )
                st.session_state["navigate_to"] = "AI Analysis"
                st.rerun()
            except EmptyCaptureError:
                st.error("No usable packet metadata was found in this capture.")
            except Exception:
                logger.exception("Live capture analysis failed")
                st.error("Something went wrong while analyzing the captured traffic.")


# ---------------------------------------------------------------------------
# Page: PCAP Analyzer
# ---------------------------------------------------------------------------
def page_pcap_analyzer():
    st.title("PCAP / PCAPNG upload")
    st.markdown(
        "Analyze a saved capture file for packet patterns, anomalies, and behavioral changes."
    )

    uploaded = st.file_uploader("Choose a PCAP or PCAPNG file", type=["pcap", "pcapng"])
    if uploaded is None:
        st.info("Your file stays in this local application. Packet payloads are not saved.")
        return

    st.markdown("---")
    if st.button("Analyze capture", type="primary", icon=":material/analytics:", width="stretch"):
        with st.spinner("Parsing capture and running the analysis pipeline..."):
            try:
                with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
                    tmp_path = tmp.name
                df = parse_pcap_bytes(uploaded.getvalue(), tmp_path)
                run_full_analysis(df, source="pcap")
                st.session_state["analysis_complete_notice"] = (
                    f"Analyzed {len(df):,} packets from {df['src_ip'].nunique()} device(s). "
                    "Your findings are ready to review."
                )
                st.session_state["navigate_to"] = "AI Analysis"
                st.rerun()
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
    st.title("Communication fingerprints")
    st.markdown("Examine structural communication habits and behavioral feature distributions per device.")
    
    fingerprints = st.session_state["fingerprints"]
    if not fingerprints:
        st.info("Run an analysis on the **Live Analyzer** or **PCAP Analyzer** page first to generate fingerprints.")
        return

    st.caption(
        "*Each fingerprint ID is a project-level behavioral identifier derived "
        "from this session's traffic features - not a globally unique device identity.*"
    )
    st.markdown("---")

    for src_ip, fp in fingerprints.items():
        with st.container(border=True):
            cols = st.columns([2, 1])
            cols[0].subheader(f"Device: `{src_ip}`")
            cols[1].caption(f"**Fingerprint ID:** `{fp['fingerprint_id']}`")
            st.markdown("---")
            for label, pct in fp["bars"].items():
                st.text(f"{label:<28}{bar_string(pct)}")


# ---------------------------------------------------------------------------
# Page: AI Analysis
# ---------------------------------------------------------------------------
def page_ai_analysis():
    st.title("Anomaly and risk review")
    review = st.session_state["ai_review"]
    anomaly_results = st.session_state["anomaly_results"]

    if not review:
        st.info("Run an analysis on the **Live Analyzer** or **PCAP Analyzer** page first.")
        return

    cols = st.columns(4)
    cols[0].metric("Classification", review["classification"])
    cols[1].metric("Anomaly Score", f"{review['anomaly_score']:.2f}")
    cols[2].metric("Risk Score", f"{review['risk_score']:.0f}/100")
    cols[3].metric("Severity", review["severity"])

    st.markdown("---")
    with st.container(border=True):
        st.subheader(review["title"])
        if review["deviations"]:
            st.write("**Observed Behavioral Deviations:**")
            for bullet in review["deviations"]:
                st.markdown(f"- {bullet}")
        st.markdown("#### **Interpretation**")
        st.write(review["interpretation"])
        st.markdown("#### **Recommended Action**")
        st.write(review["recommendation"])
        st.caption(f"*{review['disclaimer']}*")

    if anomaly_results:
        st.divider()
        st.subheader("Per-device anomaly breakdown")
        rows = [
            {
                "Device": r.src_ip,
                "Classification": "Anomalous" if r.is_anomalous else "Normal",
                "Anomaly Score": round(r.anomaly_score, 1),
            }
            for r in anomaly_results
        ]
        st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)


# ---------------------------------------------------------------------------
# Page: What Changed?
# ---------------------------------------------------------------------------
def page_what_changed():
    st.title("Baselines and behavioral changes")
    comparison = st.session_state["comparison"]
    features = st.session_state["features"]

    if features is not None and not features.empty:
        if st.button("Save this analysis as the new baseline", icon=":material/bookmark_add:"):
            baseline_snapshot = aggregate_features(features)
            database.save_baseline(baseline_snapshot)
            st.session_state["comparison"] = compare_to_baseline(
                baseline_snapshot,
                aggregate_features(features),
            )
            st.success("Baseline saved. Future analyses will be compared with this traffic profile.")
            st.rerun()

    if comparison is None or comparison.empty:
        st.info(
            "A baseline is created automatically when there is enough traffic. "
            "Once a comparison is available, this page will show changes against it."
        )
        return

    if has_significant_deviation(comparison):
        st.warning("**Significant behavioral deviation detected** in one or more tracked metrics below.")
    else:
        st.success("Current traffic is stable and broadly consistent with the established baseline.")

    st.markdown("---")
    display = comparison.copy()
    display["percentage_change"] = display["percentage_change"].map(lambda v: f"{v:+.0f}%")
    display = display.rename(columns={
        "metric": "Metric", "baseline": "Baseline", "current": "Current",
        "absolute_change": "Absolute Change", "percentage_change": "Change",
        "significant": "Significant Deviation",
    })
    st.dataframe(display, width="stretch", hide_index=True)
    st.caption("*Anomalous does not automatically mean malicious — review flagged metrics in proper network context.*")


# ---------------------------------------------------------------------------
# Page: Traffic Statistics
# ---------------------------------------------------------------------------
def page_traffic_statistics():
    st.title("Traffic statistics")
    df = st.session_state["df"]
    if df is None or df.empty:
        st.info("Run an analysis on the **Live Analyzer** or **PCAP Analyzer** page first.")
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
        st.plotly_chart(
            _style_plotly_figure(protocol_distribution_figure(df)),
            width="stretch",
        )
    with c2:
        st.plotly_chart(
            _style_plotly_figure(traffic_over_time_figure(df)),
            width="stretch",
        )

    st.markdown("---")
    c3, c4, c5 = st.columns(3)
    with c3:
        st.plotly_chart(
            _style_plotly_figure(top_talkers_figure(df, "src_ip", "Top source IPs")),
            width="stretch",
        )
    with c4:
        st.plotly_chart(
            _style_plotly_figure(top_talkers_figure(df, "dst_ip", "Top destination IPs")),
            width="stretch",
        )
    with c5:
        st.plotly_chart(
            _style_plotly_figure(top_talkers_figure(df, "dst_port", "Top destination ports")),
            width="stretch",
        )


# ---------------------------------------------------------------------------
# Page: Analysis History
# ---------------------------------------------------------------------------
def page_history():
    st.title("Previous analyses")
    st.markdown("Review saved scan summaries. These records remain available after sign-out.")
    
    history = database.get_analysis_history()
    if not history:
        st.info("No analyses recorded in history yet.")
        return
        
    df = pd.DataFrame(history)
    if "source" in df:
        sources = ["All sources"] + sorted(df["source"].dropna().unique().tolist())
        selected_source = st.selectbox("Filter by source", sources)
        if selected_source != "All sources":
            df = df[df["source"] == selected_source]
    st.dataframe(df, width="stretch", hide_index=True)


def page_help_assistant():
    st.title("Help Assistant")
    st.markdown(
        "Ask about the analyzer, traffic findings, or local capture setup. "
        "This assistant uses built-in guidance and does not connect to an external AI service."
    )
    if not st.session_state["chat_history"]:
        st.info(
            "Try a question such as “How do I capture traffic?”, “What does the risk score mean?”, "
            "or “How do I compare with a baseline?”"
        )
    for message in st.session_state["chat_history"]:
        with st.chat_message(message["role"]):
            st.write(message["content"])

    prompt = st.chat_input("Ask about live capture, PCAPs, fingerprints, or risk scores")
    if prompt:
        st.session_state["chat_history"].append({"role": "user", "content": prompt})
        normalized_prompt = prompt.casefold().strip(" \t\r\n?!.,")
        if normalized_prompt in {"hi", "hello", "hey", "how are you", "how are you doing"}:
            answer = (
                "Hi! I’m ready to help you use Network Analyzer. "
                "Ask me about capturing traffic, analyzing a PCAP, understanding findings, "
                "or comparing a baseline."
            )
        else:
            answer = answer_user_query(
                prompt,
                {
                    "active_page": st.session_state["active_page"],
                    "has_data": st.session_state["df"] is not None,
                    "packet_count": len(st.session_state["df"]) if st.session_state["df"] is not None else 0,
                    "risk_score": (
                        st.session_state["risk_result"]["risk_score"]
                        if st.session_state["risk_result"]
                        else "not available"
                    ),
                    "classification": (
                        st.session_state["ai_review"]["classification"]
                        if st.session_state["ai_review"]
                        else "not available"
                    ),
                },
            )
        st.session_state["chat_history"].append({"role": "assistant", "content": answer})
        st.rerun()


def _confirm_admin_password(password: str) -> bool:
    if not password:
        st.error("Enter your administrator password to confirm this change.")
        return False
    try:
        account = iam.authenticate_user(current_account["username"], password)
    except sqlite3.Error:
        logger.exception("Could not verify administrator credentials for an account change.")
        st.error("The administrator password could not be verified because the local database is unavailable.")
        return False
    if account is None or account["role"] != "admin":
        st.error("Administrator password is incorrect.")
        return False
    return True


def page_user_management():
    st.title("User Management")
    if current_account["role"] != "admin":
        st.error("An administrator account is required to manage users.")
        return

    st.subheader("Create an account")
    with st.form("create_local_user", clear_on_submit=True):
        new_username = st.text_input("Username", help="3–32 letters, numbers, dots, dashes, or underscores.")
        new_full_name = st.text_input("Name")
        new_password = st.text_input(
            "Temporary password",
            type="password",
            help=f"At least {iam.MIN_PASSWORD_LENGTH} characters.",
        )
        new_role = st.selectbox("Role", iam.ROLES, format_func=str.title)
        create_admin_password = st.text_input(
            "Confirm your administrator password",
            type="password",
        )
        create_submitted = st.form_submit_button("Create account", type="primary")
    if create_submitted and _confirm_admin_password(create_admin_password):
        try:
            iam.create_user(
                new_username,
                new_password,
                new_full_name,
                new_role,
                current_account["username"],
            )
            st.success(f"Account '{new_username.strip()}' created. Share its username and temporary password securely.")
            st.rerun()
        except (iam.IAMError, ValueError) as exc:
            st.error(str(exc))
        except sqlite3.Error:
            logger.exception("Could not create the local user account.")
            st.error("The account could not be saved. Check the local database and try again.")

    st.subheader("Manage existing accounts")
    try:
        accounts = iam.list_users()
    except sqlite3.Error:
        logger.exception("Could not load local accounts.")
        st.error("The account list could not be loaded from the local database.")
        return
    if not accounts:
        st.info("No accounts are available.")
        return
    account_by_label = {
        f"{account['username']} — {account['role'].title()}"
        + ("" if account["is_active"] else " (disabled)"): account
        for account in accounts
    }
    selected_label = st.selectbox("Select an account", list(account_by_label))
    selected = account_by_label[selected_label]
    st.caption(f"Last sign-in: {selected['last_login']}")

    with st.form(f"edit_account_{selected['username']}", clear_on_submit=True):
        role_col, status_col = st.columns(2, wrap=True)
        selected_role = role_col.selectbox(
            "Account role",
            iam.ROLES,
            index=iam.ROLES.index(selected["role"]),
            key=f"role_{selected['username']}",
            format_func=str.title,
        )
        selected_active = status_col.toggle(
            "Account enabled",
            value=bool(selected["is_active"]),
            key=f"active_{selected['username']}",
        )
        edit_admin_password = st.text_input(
            "Confirm your administrator password",
            type="password",
        )
        edit_submitted = st.form_submit_button("Save account changes", type="primary")
    if edit_submitted and _confirm_admin_password(edit_admin_password):
        try:
            changed = False
            if selected_role != selected["role"]:
                iam.update_user_role(selected["username"], selected_role, current_account["username"])
                changed = True
            if selected_active != bool(selected["is_active"]):
                iam.update_user_active_state(
                    selected["username"],
                    selected_active,
                    current_account["username"],
                )
                changed = True
            if changed:
                st.success("Account changes saved.")
                st.rerun()
            st.info("No account changes to save.")
        except (iam.IAMError, ValueError) as exc:
            st.error(str(exc))
        except sqlite3.Error:
            logger.exception("Could not update local account settings.")
            st.error("Account changes could not be saved. Check the local database and try again.")

    with st.expander("Reset this account's password"):
        with st.form(f"reset_password_{selected['username']}", clear_on_submit=True):
            reset_password = st.text_input("New password", type="password")
            confirm_reset_password = st.text_input("Confirm new password", type="password")
            reset_admin_password = st.text_input(
                "Confirm your administrator password",
                type="password",
            )
            reset_submitted = st.form_submit_button("Reset password")
        if reset_submitted and _confirm_admin_password(reset_admin_password):
            if reset_password != confirm_reset_password:
                st.error("The passwords do not match.")
            else:
                try:
                    iam.reset_user_password(
                        selected["username"],
                        reset_password,
                        current_account["username"],
                    )
                    st.success("Password reset. Share the new password securely with the account owner.")
                except (iam.IAMError, ValueError) as exc:
                    st.error(str(exc))
                except sqlite3.Error:
                    logger.exception("Could not reset local account password.")
                    st.error("The password could not be reset. Check the local database and try again.")

    with st.expander("Recent account activity"):
        try:
            st.dataframe(pd.DataFrame(iam.list_audit_events()), width="stretch", hide_index=True)
        except sqlite3.Error:
            logger.exception("Could not load local account activity.")
            st.error("The account activity could not be loaded from the local database.")


PAGE_FUNCS = {
    "Overview": page_overview,
    "Live Analyzer": page_live_analyzer,
    "PCAP Analyzer": page_pcap_analyzer,
    "Communication Fingerprint": page_fingerprint,
    "AI Analysis": page_ai_analysis,
    "What Changed?": page_what_changed,
    "Traffic Statistics": page_traffic_statistics,
    "Analysis History": page_history,
    "Help Assistant": page_help_assistant,
    "User Management": page_user_management,
}

current_page_func = PAGE_FUNCS.get(st.session_state["active_page"], page_overview)
current_page_func()