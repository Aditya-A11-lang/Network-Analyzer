# Network Analyzer with AI

A local Streamlit dashboard for analyzing authorized network traffic. It extracts packet metadata (not payload contents), builds device behavior fingerprints, compares traffic with a baseline, and summarizes statistical outliers.

## Quick start on Windows

1. Install Python 3.10 or newer. During setup, enable **Add Python to PATH**.
2. Open the project folder in File Explorer: `Your Folder Path `.
3. Double-click **`START_APP.bat`**. The first run creates a private Python environment and installs the required packages; allow a few minutes for this step.
4. Leave the black terminal window open. Open the local URL printed there, usually `http://localhost:8501`.
5. On first launch, create your administrator username and password in the setup form.
6. On later launches, enter that username and password on the sign-in screen.

There is **no OIDC, provider registration, secrets file, or external account required**. The app creates no default account or shared password. The first account created on a new local database becomes the administrator. From **User Management**, the administrator can add user/admin accounts, disable accounts, and reset passwords.

Use a password with at least 12 characters. Passwords are salted and hashed before they are saved in the local SQLite database; they are never stored as readable text. Keep your database file private. If you forget the only administrator password, there is no online recovery service; preserve a backup of the database.

The app listens on this computer only (`127.0.0.1`). It is designed for personal/local use; do not expose the local login app to the public internet or a shared network.

To stop the app, focus the terminal window and press **Ctrl+C**. Double-click `START_APP.bat` again when you want to run it later.

## Manual setup

If you prefer using PowerShell, open a terminal in the project folder and run:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m streamlit run app.py
```

If `py` is not recognized, install Python from [python.org](https://www.python.org/downloads/) and reopen the terminal. You do not need to activate the environment.

## Analyze traffic

- **PCAP file:** open **PCAP Analyzer**, select a `.pcap` or `.pcapng` file, and choose **Analyze PCAP File**.
- **Live traffic:** install [Npcap](https://npcap.com/#download), run the app on the computer whose network you are authorized to monitor, and choose **Start live analysis** on the dashboard to open the interface and duration selector. The **Live Analyzer** page also has interface and start/stop controls. When a capture stops (including its automatic timeout), choose **Analyze captured traffic** to analyze the collected packets. Capture errors are shown on that page. If Windows denies capture access, close the terminal, start VS Code or the terminal with the required permissions, and run the app again.

Live capture can only see the network interface of the machine running the app. It cannot capture a visitor's computer from a hosted website. Uploaded PCAP analysis does not require Npcap.

## Dashboard features

- Network overview with saved scan metrics, recent activity, and protocol/risk charts.
- Analysis summaries are stored in the local SQLite history and remain available when switching dashboard features or signing out.
- Grouped navigation for traffic analysis, AI insights, baselines, history, help, and administration.
- Dark appearance by default, with light and system-default choices saved per local account.
- Local Scapy capture and PCAP/PCAPNG parsing.
- Per-device communication fingerprints and traffic statistics.
- Isolation Forest anomaly scoring and plain-language review.
- Baseline comparison.
- Floating, page-aware help popover and full help page; guidance stays local with no external AI service or API key.
- Local username/password sign-in with user/admin roles and an admin account-management page.

The first administrator account is created during first-run setup. Additional accounts are created by an administrator from the Administration section; public self-registration is intentionally not enabled for this local security tool. Creating accounts, changing roles or account status, and resetting passwords require the current administrator password again.

## Privacy and interpretation

The capture worker extracts timestamp, IP addresses, ports, protocol, packet length, and a DNS indicator, then discards each packet. Packet payloads, passwords, and cookies are not saved or displayed. The database and trained model are local files (`data/network_analyzer.db` and `models/`); protect them because traffic metadata can still be sensitive.

Use the tool only on networks you own or are explicitly authorized to monitor. An anomaly means behavior differs statistically from the sample or baseline; it does not prove malicious activity. Risk scores and severity labels are project-defined, not industry standards. Small samples can limit model results.

## Run tests

```powershell
.\.venv\Scripts\python.exe -m pytest tests -v
```

## Project layout

```text
app.py                    Streamlit dashboard
START_APP.bat             Windows setup and launch helper
src/capture.py            Local packet capture
src/packet_parser.py      PCAP parsing and metadata extraction
src/feature_engineering.py Per-device feature calculation
src/fingerprint.py        Behavioral fingerprints
src/anomaly_model.py      Isolation Forest analysis
src/baseline.py           Baseline comparison
src/risk_scoring.py       Project-defined risk scoring
src/ai_review.py          Explainable review text
src/traffic_analysis.py   Statistics and charts
src/database.py           SQLite storage
src/iam.py                Local accounts and role management
src/help_assistant.py     Built-in local help
tests/                    Automated tests
```
