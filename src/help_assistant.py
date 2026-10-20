"""Local, context-aware help for operating the network analyzer."""
from __future__ import annotations

PAGE_GUIDES = {
    "Overview": "Start here for current session metrics. Use Live Analyzer for an authorized local capture or PCAP Analyzer to inspect a saved capture.",
    "Live Analyzer": "Select a local interface, start capture, wait for metadata to arrive, then stop and analyze. Live capture requires local OS permissions and (on Windows) Npcap.",
    "PCAP Analyzer": "Upload a .pcap or .pcapng file and choose Analyze. Only packet metadata is extracted; payload contents are not stored.",
    "Communication Fingerprint": "Choose a source device to inspect its behavioral feature profile and project-level fingerprint ID.",
    "AI Analysis": "Review the Isolation Forest result and explainable risk summary. A statistical anomaly is not proof of malicious activity.",
    "What Changed?": "Compare a completed analysis with the saved baseline. Use the baseline control to explicitly save the current traffic profile.",
    "Traffic Statistics": "Explore packet counts, protocol distribution, timing, and most active source and destination addresses.",
    "Analysis History": "Review recent analysis metadata. Packet payloads are never persisted.",
    "IAM & Settings": "Administrators can create local accounts, change user/admin roles, disable accounts, and reset passwords.",
    "Help assistant": "Ask how to use the dashboard, interpret an analysis, or resolve a local capture setup issue.",
}


def answer_user_query(query: str, context: dict | None = None) -> str:
    """Answer common operational questions without external services."""
    normalized = " ".join(query.casefold().split())
    active_page = (context or {}).get("active_page", "Overview")

    if any(term in normalized for term in ("live", "capture", "interface", "npcap", "permission")):
        return PAGE_GUIDES["Live Analyzer"] + " Run the terminal with capture privileges only when required by your operating system."
    if any(term in normalized for term in ("pcap", "upload", "file")):
        return PAGE_GUIDES["PCAP Analyzer"]
    if any(term in normalized for term in ("risk", "anomaly", "isolation forest", "ai score")):
        return PAGE_GUIDES["AI Analysis"] + " Scores are project-defined analytical indicators, not industry thresholds."
    if any(term in normalized for term in ("fingerprint", "device", "signature")):
        return PAGE_GUIDES["Communication Fingerprint"]
    if any(term in normalized for term in ("baseline", "changed", "compare", "delta")):
        return PAGE_GUIDES["What Changed?"]
    if any(term in normalized for term in ("login", "admin", "role", "account", "iam", "permission")):
        return PAGE_GUIDES["IAM & Settings"]
    if any(term in normalized for term in ("history", "previous", "saved analysis")):
        return PAGE_GUIDES["Analysis History"]
    if any(term in normalized for term in ("protocol", "statistics", "chart", "traffic stats")):
        return PAGE_GUIDES["Traffic Statistics"]
    if any(term in normalized for term in ("current", "status", "this analysis", "packet count")):
        details = context or {}
        if details.get("has_data"):
            return (
                f"The current session contains {details.get('packet_count', 0):,} analyzed packets. "
                f"Classification: {details.get('classification', 'not available')}; "
                f"risk score: {details.get('risk_score', 'not available')}."
            )
        return "No traffic has been analyzed in this session yet. Start a local capture or upload a PCAP file."
    return (
        f"{PAGE_GUIDES.get(active_page, PAGE_GUIDES['Overview'])} "
        "This assistant uses built-in operating guidance only; it does not call an external AI service."
    )
