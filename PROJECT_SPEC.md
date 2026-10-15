# PROJECT_SPEC.md — AI-Based Network Communication Fingerprinting and Anomaly Detection

## 1. Project Goal
Build an authorized-network educational tool that learns the normal
communication behavior of devices on a network, builds a per-device
behavioral "communication fingerprint," and uses a lightweight
unsupervised ML model (Isolation Forest) to flag traffic that deviates
from that fingerprint. The tool never claims a deviation is proof of an
attack — it flags behavior that *requires investigation*.

## 2. Functional Requirements
- FR1: Capture live traffic locally via Scapy (local execution only).
- FR2: Parse uploaded `.pcap` / `.pcapng` files (works in the cloud).
- FR3: Extract per-packet metadata (IPs, ports, protocol, size, time) —
  never payload content.
- FR4: Aggregate metadata into per-device numerical traffic features.
- FR5: Generate a visual + numeric "communication fingerprint" per device.
- FR6: Train/load an Isolation Forest model over numerical features.
- FR7: Score anomalies and convert to a 0–100 project-defined risk score.
- FR8: Compare current behavior against a stored baseline ("What
  Changed?").
- FR9: Produce a plain-language, explainable AI Traffic Review.
- FR10: Persist analysis history, fingerprints, and baselines in SQLite.
- FR11: Present all of the above in a multi-page Streamlit dashboard.

## 3. Non-Functional Requirements
- Must run on Streamlit Community Cloud using PCAP upload only (no live
  capture in the cloud).
- Must degrade gracefully on empty/invalid/small PCAPs, missing fields,
  and ML training failures — no raw tracebacks shown to the user.
- Must not store packet payloads, passwords, or cookies.
- Dependencies limited to: streamlit, scapy, pandas, numpy, scikit-learn,
  plotly, joblib.
- No deep learning, no external AI API, no Docker/FastAPI/React/microservices.

## 4. Architecture
```
Streamlit UI (app.py)
   │
   ├── src/capture.py         (local live capture only)
   ├── src/packet_parser.py   (pcap + live packet -> DataFrame of metadata)
   ├── src/feature_engineering.py (per-device numerical features)
   ├── src/fingerprint.py     (visual + hash fingerprint per device)
   ├── src/baseline.py        (store/retrieve/compare baselines)
   ├── src/anomaly_model.py   (Isolation Forest train/load/predict)
   ├── src/risk_scoring.py    (0-100 risk score + severity)
   ├── src/ai_review.py       (explainable text review)
   ├── src/traffic_analysis.py(aggregate stats + Plotly figures)
   ├── src/database.py        (SQLite persistence)
   └── src/utils.py           (shared helpers, safe-error wrapper)
```

## 5. Data Flow
1. Packets arrive (live capture or PCAP upload).
2. `packet_parser.py` converts them into a pandas DataFrame of metadata
   only (no payload).
3. `feature_engineering.py` groups by source IP and computes numerical
   behavioral features per device.
4. `fingerprint.py` converts those features into a normalized visual
   fingerprint + short hash ID.
5. `anomaly_model.py` scores each device's feature vector with Isolation
   Forest (trained on the current session, or loaded from `models/`).
6. `baseline.py` compares the current features to a stored baseline (if
   one exists) and computes deltas.
7. `risk_scoring.py` combines anomaly score + deltas into a 0–100 risk
   score and severity band.
8. `ai_review.py` turns the numbers into a plain-language, non-alarmist
   explanation.
9. `database.py` writes a row to `analysis_history`, plus fingerprint and
   baseline tables.
10. `app.py` renders everything across the 8 dashboard pages.

## 6. AI Pipeline
- **Model**: `sklearn.ensemble.IsolationForest`, unsupervised, trained on
  the numerical feature matrix of all observed devices in a session (or a
  previously saved baseline set).
- **Features** (see `feature_engineering.py`): packets_per_second,
  bytes_per_second, unique_destination_ips, unique_destination_ports,
  unique_source_ports, tcp_ratio, udp_ratio, icmp_ratio,
  average_packet_size, connection_count, protocol_diversity,
  destination_diversity, port_diversity.
- **Output**: `-1` (anomalous) / `1` (normal) plus a continuous
  `decision_function` score, rescaled to 0–1 as `anomaly_score`.
- Model persisted via `joblib` to `models/isolation_forest.joblib`.

## 7. Fingerprint Generation
Per source IP, normalize each feature to a 0–100% bar using min-max
scaling against the observed session range (or baseline range when
available). A short fingerprint ID is derived from a truncated SHA-256
hash of the rounded feature vector, formatted like `7A-F2-91`. This ID is
explicitly a **project-level behavioral identifier**, not a device
identity claim.

## 8. Anomaly Detection
See Section 6. Handles: single-device sessions (falls back to
rule-based deviation instead of ML when fewer than
`MIN_SAMPLES_FOR_ML` rows exist), NaNs (imputed to 0), and constant
columns (dropped before fitting to avoid degenerate variance).

## 9. Risk Calculation
`risk_scoring.calculate_risk_score()` blends:
- anomaly_score (40%)
- normalized packet/byte rate deviation vs baseline (25%)
- destination/port diversity deviation (20%)
- protocol ratio deviation (15%)

Result clipped to [0, 100]. Severity bands: 0–24 INFO, 25–49 LOW,
50–74 MEDIUM, 75–100 HIGH. These are **project-defined analytical
thresholds**, not industry standards.

## 10. What Changed?
`baseline.compare_to_baseline()` returns, per metric: baseline value,
current value, absolute change, percentage change, and a boolean
`significant` flag (>50% relative change or >3x absolute for near-zero
baselines).

## 11. Dashboard
8 pages: Overview, Live Analyzer, PCAP Analyzer, Communication
Fingerprint, AI Analysis, What Changed?, Traffic Statistics, Analysis
History. See `app.py`.

## 12. Database
SQLite file `data/network_analyzer.db` with tables:
`analysis_history`, `device_fingerprints`, `baselines`. Schema in
`src/database.py`. No payload data stored in any table.

## 13. Privacy
Only metadata is ever parsed or stored: IPs, ports, protocol, packet
size, timestamp, and derived statistics. Application-layer payload
bytes are never read, stored, or displayed.

## 14. Deployment
- Cloud (Streamlit Community Cloud): PCAP Analyzer, Fingerprint, AI
  Analysis, What Changed, Traffic Statistics, and History pages all
  work fully. Live Analyzer page detects it's non-local and shows an
  explanatory notice instead of attempting capture.
- Local: all pages work, including live capture (requires Npcap on
  Windows, or root/libpcap on Linux/macOS).

## 15. Limitations
- Isolation Forest is unsupervised and session/baseline dependent; it
  does not "know" what an attack is — it only flags statistical
  deviation from prior behavior.
- Small sample sizes reduce model reliability; the app displays a
  confidence caveat in that case.
- DNS activity detection is best-effort (based on UDP/TCP port 53 and
  Scapy DNS layer parsing where present).
