# Network Analyzer with AI

### AI-Based Network Communication Fingerprinting and Anomaly Detection

A beginner-friendly, privacy-preserving cybersecurity education tool that
learns the normal communication behavior of network devices, builds a
behavioral **communication fingerprint**, detects significant deviations
using a lightweight AI model, and explains what changed — without ever
claiming an anomaly automatically proves an attack.

---

## 1. Project Overview

Network Analyzer with AI observes **authorized** network traffic (either a
local live capture or an uploaded PCAP file), extracts metadata-level
behavioral features per device, and applies an unsupervised machine
learning model (Isolation Forest) to flag traffic that statistically
deviates from what a device normally does. Results are shown through a
Streamlit dashboard with plain-language, explainable output.

## 2. Problem Statement

Most consumer and small-network users have no easy way to understand
"what does normal traffic from this device even look like?" — and
therefore no way to notice when something changes. Enterprise network
detection tools are complex, expensive, and payload-inspecting. There is
a gap for a simple, explainable, privacy-respecting educational tool that
works from metadata alone.

## 3. Proposed Solution

Build each device a behavioral fingerprint from traffic *metadata*
(packet rate, byte rate, destination/port diversity, protocol mix, DNS
activity, etc.), learn a baseline of "normal" for that traffic sample,
and use an Isolation Forest to score how much current behavior deviates
from that baseline — then explain the result in plain language with a
project-defined risk score and severity.

## 4. Objectives

- Analyze authorized network traffic without capturing payload contents.
- Represent device behavior as a visual, understandable fingerprint.
- Detect behavioral anomalies using lightweight, local, unsupervised ML.
- Quantify and explain *what changed* versus an established baseline.
- Communicate results without overstating certainty ("anomalous" ≠
  "malicious").
- Work both locally (with live capture) and in the cloud (PCAP upload).

## 5. Key Features

1. **Network Traffic Analyzer** — local live packet capture (Scapy).
2. **PCAP Analyzer** — upload and analyze `.pcap` / `.pcapng` files.
3. **Communication Fingerprint** — per-device behavioral profile + short ID.
4. **AI Anomaly Detection** — Isolation Forest over numerical features.
5. **What Changed?** — baseline vs. current comparison with deltas.
6. **Explainable AI Traffic Review** — plain-language interpretation.
7. Supporting dashboard statistics and persistent analysis history.

## 6. Unique Contribution

The **Communication Fingerprint** concept: a compact, visual, per-device
behavioral signature built purely from traffic metadata, paired with a
project-level (not globally unique) short identifier, that is then used
both for human interpretation and as direct model input for anomaly
detection and baseline comparison — unifying visualization and detection
around the same feature vector.

## 7. System Architecture

```
Streamlit UI (app.py)
   ├── src/capture.py            local live capture (Scapy)
   ├── src/packet_parser.py      PCAP/live packets -> metadata DataFrame
   ├── src/feature_engineering.py per-device numeric feature vectors
   ├── src/fingerprint.py        behavioral fingerprint + short ID
   ├── src/baseline.py           baseline storage + "What Changed?"
   ├── src/anomaly_model.py      Isolation Forest train/load/predict
   ├── src/risk_scoring.py       0-100 risk score + severity
   ├── src/ai_review.py          explainable text review
   ├── src/traffic_analysis.py   aggregate stats + Plotly charts
   ├── src/database.py           SQLite persistence
   └── src/utils.py              shared helpers, safe error handling
```

See `PROJECT_SPEC.md` for the full data flow and module-by-module detail.

## 8. Technology Stack

- **UI:** Streamlit
- **Packet capture/parsing:** Scapy
- **Data handling:** pandas, numpy
- **Machine learning:** scikit-learn (Isolation Forest), joblib
- **Visualization:** Plotly
- **Storage:** SQLite (standard library `sqlite3`)

No external AI APIs, no API keys, no deep learning, no Docker, no
microservices — a single Streamlit application.

## 9. AI Methodology

An unsupervised **Isolation Forest** is trained on a table of per-device
numerical features (packet rate, byte rate, protocol ratios, destination
and port diversity, connection count, etc.). Isolation Forest isolates
observations via random recursive partitioning; points that are isolated
in fewer splits are scored as more anomalous. This requires **no labelled
attack data** — it only needs a representative sample of traffic to learn
what "typical" looks like. The model and its feature scaler are persisted
with `joblib` so a baseline model can be reused across sessions.

## 10. Communication Fingerprint Explanation

For each source device, key features are min-max normalized across the
devices seen in the session and rendered as percentage bars (e.g. TCP
usage, DNS activity, destination diversity, port diversity, packet rate).
A short identifier such as `7A-F2-91` is derived from a hash of the
device's rounded feature vector — this is explicitly a **project/session
behavioral label**, not a claim of unique global device identity.

## 11. What Changed Explanation

The app maintains a stored baseline snapshot (aggregated traffic
features). Each new analysis is compared against it, metric by metric:
`baseline`, `current`, `absolute change`, `percentage change`. A metric is
flagged **significant** when its absolute percentage change is 50% or
more. The page never labels a change an "attack" — it reports "significant
behavioral deviation detected" and leaves interpretation to the reviewer.

## 12. Risk Scoring Explanation

`calculate_risk_score()` combines (weighted):
- Anomaly score from the Isolation Forest — 40%
- Packet/byte rate deviation from baseline — 25%
- Destination/port diversity deviation — 20%
- Protocol-mix deviation (TCP/UDP/DNS) — 15%

The result is clamped to **0–100** and mapped to a severity band:
`0–24 INFO · 25–49 LOW · 50–74 MEDIUM · 75–100 HIGH`.
These thresholds are **project-defined analytical conventions**, not
industry-standard cybersecurity thresholds. A related **Network Health**
score (0–100) is shown on the Overview page as a project-level summary
metric, not an industry rating.

## 13. Explainable AI Explanation

The **AI Traffic Review** combines the classification (Normal/Anomalous),
anomaly score, risk score, severity, and any significant baseline
deviations into a short, plain-language report: what was observed, what
it might mean, and what to check next — always paired with a disclaimer
that an anomalous classification is a statistical deviation, not
confirmed malicious activity.

## 14. Privacy Approach

- No packet payloads are captured or stored by default.
- No passwords, authentication tokens, or cookies are inspected.
- No application-layer message content is parsed.
- Only IP addresses, ports, protocols, packet sizes, and timestamps are
  used and stored.
- A privacy notice is shown in the app sidebar at all times.

## 15. Project Structure

```
Network-Packet-Analyzer/
├── app.py
├── requirements.txt
├── README.md
├── PROJECT_SPEC.md
├── .gitignore
├── .streamlit/
│   └── config.toml
├── src/
│   ├── __init__.py
│   ├── capture.py
│   ├── packet_parser.py
│   ├── feature_engineering.py
│   ├── fingerprint.py
│   ├── anomaly_model.py
│   ├── risk_scoring.py
│   ├── ai_review.py
│   ├── baseline.py
│   ├── traffic_analysis.py
│   ├── database.py
│   └── utils.py
├── models/         # trained model artifacts (.gitignored, .gitkeep kept)
├── data/           # SQLite DB (.gitignored, .gitkeep kept)
└── tests/
    ├── test_parser.py
    ├── test_features.py
    ├── test_fingerprint.py
    └── test_risk.py
```

## 16. Installation Instructions

```bash
git clone <this-repository-url>
cd Network-Packet-Analyzer
python -m venv .venv
# activate the environment (see OS-specific steps below)
pip install -r requirements.txt
```

## 17. Windows Instructions

1. Install Python 3.10+ from python.org.
2. For **live capture only**, install
   [Npcap](https://npcap.com/#download) (Npcap is a system driver, not a
   Python package — it is not listed in `requirements.txt`). During
   installation, enable "Support raw 802.11 traffic" only if needed; the
   default options are sufficient for this project.
3. Create and activate a virtual environment:
   ```powershell
   python -m venv .venv
   .venv\Scripts\activate
   pip install -r requirements.txt
   ```
4. Run the app (see Section 19). Live capture on Windows typically
   requires running your terminal **as Administrator**.

## 18. Linux Instructions

1. Install Python 3.10+ and `libpcap`:
   ```bash
   sudo apt-get update && sudo apt-get install -y python3-venv libpcap-dev
   ```
2. Create and activate a virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```
3. Live capture requires elevated permissions:
   ```bash
   sudo -E env PATH="$PATH" streamlit run app.py
   ```
   or grant the capture capability directly to your Python interpreter
   with `setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))`.

## 19. Local Execution Instructions

```bash
streamlit run app.py
```

Then open the printed local URL (typically `http://localhost:8501`) in
your browser. Use the sidebar to navigate between pages.

## 20. PCAP Analysis Instructions

1. Open the **PCAP Analyzer** page.
2. Upload a `.pcap` or `.pcapng` file (max size set in
   `.streamlit/config.toml`, default 200 MB).
3. Click **Analyze PCAP**. The app parses metadata, builds features and
   fingerprints, runs anomaly detection, compares against the stored
   baseline, and displays the AI Traffic Review.
4. Visit **Communication Fingerprint**, **AI Analysis**, **What
   Changed?**, and **Traffic Statistics** to see the full results.

## 21. Streamlit Cloud Deployment Instructions

1. Push this repository to GitHub (already an existing repo:
   `Network-Packet-Analyzer`).
2. In [Streamlit Community Cloud](https://share.streamlit.io), create a
   new app pointing at this repository, branch, and entry point `app.py`.
3. Cloud deployment supports the full **PCAP Analyzer** workflow,
   fingerprinting, AI analysis, What Changed?, statistics, and history.
4. The **Live Analyzer** page automatically detects the cloud environment
   and displays an explanatory notice instead of attempting to capture
   traffic (see Section 22).

## 22. Live Capture Limitations

A cloud-hosted Streamlit application has no access to a website visitor's
local network interface — it can only see traffic that reaches the cloud
server itself, which is not the traffic a person wants to monitor on
their own network. Therefore:

- **Local execution**: both Live Analyzer and PCAP Analyzer are available.
- **Cloud deployment**: only PCAP Analyzer is available; Live Analyzer
  displays: *"Live capture requires running the application locally on
  an authorized machine. Cloud deployments support PCAP upload and
  analysis."*

This project does **not** simulate or fake live capture in the cloud.

## 23. Testing

Run the automated test suite (packet parsing, feature extraction,
fingerprint generation, risk scoring):

```bash
pip install pytest
pytest tests/ -v
```

The app is also designed to handle, without crashing: empty PCAPs,
invalid PCAPs, very small captures, missing ports/protocols/IPs,
insufficient data for ML, model training failures, capture permission
errors, and unsupported interfaces — each surfaced as a plain-language
message rather than a raw traceback.

## 24. Limitations

- Isolation Forest identifies **statistical outliers**, not confirmed
  attacks; results require human review.
- Small or short captures (few devices/packets) produce low-confidence
  baselines and anomaly scores — the UI communicates this via
  "insufficient data" messages rather than guessing.
- DNS activity is detected heuristically (DNS layer presence or port 53
  traffic), not via full DNS message parsing.
- Fingerprint identifiers are project/session-level behavioral labels,
  not cryptographically unique or globally persistent device identities.
- Live capture requires local execution and OS-level permissions (and
  Npcap on Windows); it cannot run in a cloud deployment.

## 25. Future Enhancements

- Optional persistent, cross-session baselines per specific device (by
  MAC or user-assigned label) rather than per analysis run.
- Configurable contamination/sensitivity controls in the UI.
- Exportable PDF/CSV summaries of an AI Traffic Review.
- Optional scheduled PCAP ingestion for periodic local monitoring.

## 26. Ethical / Legal Usage

This project is strictly for **authorized** network monitoring and
educational analysis. Only capture or analyze traffic on networks and
devices you own or are explicitly authorized to monitor. This project
does **not** implement, and must not be extended to implement, offensive
capabilities such as port scanning, vulnerability exploitation, packet
injection, credential harvesting, password interception, malware,
persistence, evasion, or attack automation. An "anomalous" classification
describes a statistical behavioral deviation — it does not, by itself,
prove malicious activity, and should always be paired with human
judgment and further investigation before any action is taken.

## 27. Author

Built as an educational cybersecurity + applied machine learning project.
