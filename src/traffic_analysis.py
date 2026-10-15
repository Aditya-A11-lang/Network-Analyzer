"""Compute overall traffic statistics and build Plotly figures for the
Traffic Statistics dashboard page."""
from __future__ import annotations

from typing import Dict

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from .utils import safe_div


def compute_summary_stats(df: pd.DataFrame) -> Dict[str, object]:
    """High-level traffic statistics for the Overview / Traffic Statistics pages."""
    if df is None or df.empty:
        return {
            "total_packets": 0,
            "total_bytes": 0,
            "duration_seconds": 0.0,
            "packets_per_second": 0.0,
            "bytes_per_second": 0.0,
            "unique_devices": 0,
            "protocol_counts": {},
        }

    duration = max(float(df["timestamp"].max() - df["timestamp"].min()), 1e-6)
    total_packets = len(df)
    total_bytes = float(df["length"].sum())

    return {
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "duration_seconds": duration,
        "packets_per_second": safe_div(total_packets, duration),
        "bytes_per_second": safe_div(total_bytes, duration),
        "unique_devices": df["src_ip"].nunique(),
        "protocol_counts": df["protocol"].value_counts().to_dict(),
    }


def top_n(df: pd.DataFrame, column: str, n: int = 10) -> pd.DataFrame:
    if df is None or df.empty or column not in df.columns:
        return pd.DataFrame(columns=[column, "count"])
    counts = df[column].dropna().value_counts().head(n).reset_index()
    counts.columns = [column, "count"]
    return counts


def protocol_distribution_figure(df: pd.DataFrame) -> go.Figure:
    counts = df["protocol"].value_counts().reset_index() if not df.empty else pd.DataFrame(columns=["protocol", "count"])
    counts.columns = ["protocol", "count"] if not counts.empty else counts.columns
    fig = px.pie(counts, names="protocol", values="count", hole=0.45, title="Protocol Distribution")
    fig.update_layout(margin=dict(t=50, b=10, l=10, r=10))
    return fig


def traffic_over_time_figure(df: pd.DataFrame, bucket_seconds: int = 5) -> go.Figure:
    if df is None or df.empty:
        fig = go.Figure()
        fig.update_layout(title="Traffic Over Time (no data)")
        return fig

    bucketed = df.copy()
    bucketed["bucket"] = (bucketed["timestamp"] // bucket_seconds) * bucket_seconds
    grouped = bucketed.groupby("bucket").agg(packets=("length", "count"), bytes=("length", "sum")).reset_index()

    fig = go.Figure()
    fig.add_trace(go.Scatter(x=grouped["bucket"], y=grouped["packets"], mode="lines", name="Packets"))
    fig.update_layout(
        title="Traffic Over Time",
        xaxis_title="Seconds since capture start",
        yaxis_title="Packets per interval",
        margin=dict(t=50, b=10, l=10, r=10),
    )
    return fig


def top_talkers_figure(df: pd.DataFrame, column: str, title: str, n: int = 10) -> go.Figure:
    counts = top_n(df, column, n)
    fig = px.bar(counts, x=column, y="count", title=title)
    fig.update_layout(margin=dict(t=50, b=10, l=10, r=10))
    return fig
