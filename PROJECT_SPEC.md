# Project specification

## 1. Purpose

Network Analyzer with AI is a local-first educational dashboard for authorized network monitoring. It summarizes traffic metadata, builds per-device behavioral fingerprints, detects statistical deviations, and explains results without treating an anomaly as proof of an attack.

## 2. Functional requirements

- **FR1 — Live capture:** capture packets on the local host through Scapy, with selectable interfaces, start/stop controls, and a bounded capture duration. Live capture is unavailable in hosted environments.
- **FR2 — PCAP input:** parse uploaded `.pcap` and `.pcapng` files.
- **FR3 — Metadata only:** extract timestamp, source/destination IPs, ports, protocol, packet length, and DNS indicator. Do not retain packet payloads.
- **FR4 — Feature engineering:** aggregate metadata into per-source-device numerical behavior features.
- **FR5 — Fingerprinting:** create normalized feature visualizations and short project-level behavior IDs.
- **FR6 — Anomaly analysis:** train/load an Isolation Forest where enough distinct devices and feature variation exist; state limitations when scoring is unavailable.
- **FR7 — Risk summary:** present a project-defined 0–100 risk score and severity label, without asserting that anomalies are confirmed incidents.
- **FR8 — Baseline comparison:** allow users to establish a baseline and compare subsequent feature values and deviations.
- **FR9 — Explainability:** provide a plain-language traffic review with findings, interpretation, recommendations, and caveats.
- **FR10 — Persistence:** store analysis history, fingerprints, baselines, IAM accounts, and IAM audit events in SQLite.
- **FR11 — Dashboard:** provide overview, live analyzer, PCAP analyzer, fingerprint, AI analysis, baseline comparison, traffic statistics, and history views.
- **FR12 — Authentication:** provide a simple local username/password sign-in and first-run administrator setup. Store salted password hashes, never plaintext passwords.
- **FR13 — Authorization:** the first local account receives the `admin` role. Administrators can create accounts, change roles, disable accounts, and reset passwords. Prevent removal of the final active administrator.
- **FR14 — Operational help:** provide a page-aware assistant using built-in guidance and current session status. It must not send packet data or user questions to an external service.
- **FR15 — Usability:** provide responsive layouts, technical iconography rather than emoji decoration, clear status/errors, subtle transitions, and reduced-motion support.

## 3. Non-functional requirements

- Run locally on Windows, macOS, and Linux. The local username/password setup is intended for a trusted workstation, not a public or multi-tenant hosted deployment.
- Require Python 3.10 or later.
- Keep the application monolithic and local-first; no external AI API or hosted packet-analysis service.
- Handle empty/invalid captures, missing fields, small samples, capture permission errors, invalid local credentials, and unavailable models with clear user-facing messages.
- Never store passwords, cookies, or packet payloads.
- Use parameterized SQL for application data and persistent role changes.

## 4. Architecture

```text
Streamlit UI (app.py)
  ├── src/capture.py              local metadata-only packet capture
  ├── src/packet_parser.py        PCAP/live data -> metadata rows
  ├── src/feature_engineering.py  per-device numerical features
  ├── src/fingerprint.py          normalized behavior profile + short ID
  ├── src/anomaly_model.py        Isolation Forest model
  ├── src/baseline.py             baseline storage and comparison
  ├── src/risk_scoring.py         project-defined risk and health scores
  ├── src/ai_review.py            explainable analysis text
  ├── src/traffic_analysis.py     aggregate statistics and charts
  ├── src/database.py             SQLite persistence and schema migration
  ├── src/iam.py                  local account authentication and role checks
  └── src/help_assistant.py       local operational guidance
```

## 5. Data flow

1. Capture authorized local traffic or accept an uploaded PCAP/PCAPNG.
2. Convert each packet directly into a metadata-only row; discard the packet object.
3. Group records by source IP and compute numerical features.
4. Generate behavioral fingerprints and, where model constraints permit, anomaly predictions.
5. Compare aggregate traffic features with the explicitly saved baseline.
6. Calculate project-defined risk and health summaries and generate an explainable review.
7. Persist analysis summaries, feature fingerprints, and actor identity in SQLite.

No raw packet content is written to the database or model files.

## 6. Identity and roles

The first-run setup form creates a local administrator. That administrator provisions other users through the dashboard. Passwords are hashed with PBKDF2-HMAC-SHA256 and a random per-account salt. Roles, account status, sign-ins, and administrative actions are stored in SQLite. The final active administrator cannot be demoted or disabled. Analyses and baselines use a shared local database rather than per-account data isolation.

## 7. Privacy and deployment

- Only metadata and derived statistics are retained.
- The web server binds to `127.0.0.1` so local sign-in is not exposed to the network by default.
- Local live capture requires suitable OS permissions and Npcap on Windows or libpcap on macOS/Linux.
- SQLite, model files, and capture metadata should be treated as sensitive and protected accordingly.
- No default users, passwords, or external identity-provider setup are required.

## 8. Limitations

- Isolation Forest identifies statistical outliers, not confirmed threats.
- Small samples, a single device, or constant feature columns can prevent reliable ML scoring.
- Fingerprint IDs are project-level behavior labels, not globally unique identities.
- Risk and severity thresholds are project-defined conventions, not industry standards.
- The built-in help assistant is an operational guide, not a generative AI model.
