# Network Traffic Analyzer

A Python-based network traffic monitoring and analysis application developed as part of the SkillOrbit Cyber Security Capstone Project.

The application captures network packet metadata, stores records in SQLite, analyzes traffic behavior, identifies potentially suspicious patterns using heuristic rules, and presents results through a Streamlit dashboard with CSV export functionality.

## Table of Contents

- [Project Overview](#project-overview)
- [Project Objectives](#project-objectives)
- [Features](#features)
- [Technology Stack](#technology-stack)
- [Project Modules](#project-modules)
- [Project Structure](#project-structure)
- [System Requirements](#system-requirements)
- [Installation](#installation)
- [Running the Application](#running-the-application)
- [Using the Dashboard](#using-the-dashboard)
- [Database Design](#database-design)
- [Detection Rules and Alert Interpretation](#detection-rules-and-alert-interpretation)
- [CSV Report Generation](#csv-report-generation)
- [Verification and Testing](#verification-and-testing)
- [Security and Responsible Use](#security-and-responsible-use)
- [Limitations](#limitations)
- [Future Improvements](#future-improvements)
- [Capstone Deliverables](#capstone-deliverables)
- [License](#license)

## Project Overview

Network traffic monitoring helps administrators and security analysts understand communication between devices, identify unusual activity, and investigate potential security concerns.

This project demonstrates a basic network traffic analysis workflow using Python and open-source technologies. Captured packet metadata is stored in a local SQLite database, analyzed by monitoring and detection modules, and displayed through a Streamlit dashboard.

The project is intended for educational use, demonstrations, and authorized network analysis. It is not intended to replace an enterprise-grade network monitoring or intrusion detection system.

## Project Objectives

- Capture network packets using Scapy.
- Record relevant packet metadata in an SQLite database.
- Monitor traffic volume, protocols, IP addresses, and communication flows.
- Identify potentially unusual network behavior using heuristic detection rules.
- Present traffic statistics and detection alerts in a dashboard.
- Export traffic and security analysis results as CSV reports.
- Demonstrate the integration of packet capture, database storage, analysis, visualization, and reporting.

## Features

### 1. Packet Capture

Uses Scapy to capture packets on the selected network interface. Available metadata can include timestamps, source and destination IP addresses, protocol labels, port numbers, packet lengths, capture-session identifiers, and TCP flags.

Packet visibility depends on the selected interface, operating system permissions, and the network configuration.

### 2. Traffic Monitoring

Analyzes captured records to calculate traffic statistics, protocol distribution, IP activity, traffic timelines, communication flows, and traffic direction.

### 3. Heuristic Detection

The detection module evaluates selected traffic patterns and produces alerts for behaviors that may warrant investigation. These alerts are indicators, not definitive proof of malicious activity.

### 4. Interactive Dashboard

The Streamlit dashboard presents traffic metrics, charts, communication information, and detection alerts. It is configured to refresh dashboard content periodically.

### 5. CSV Report Export

The dashboard provides download controls for these reports:

- `traffic_summary.csv`
- `connection_report.csv`
- `security_analysis.csv`

These are suggested download filenames from the application. The files are created when exported by the user; they should not be assumed to exist in the project directory beforehand.

## Technology Stack

| Technology | Purpose |
|---|---|
| Python 3 | Application logic |
| Scapy | Packet capture and packet parsing |
| SQLite | Local packet metadata storage |
| SQLite WAL mode | Improved concurrent database access |
| Streamlit | Interactive web dashboard |
| Pandas | Tabular data handling and reporting |
| Plotly | Data visualization |
| Bash | Application launcher and process management |

## Project Modules

### Module 1 — Packet Capture

**File:** `packet_capture.py`

Captures network packets with Scapy, extracts relevant metadata, and writes records to the SQLite database. Raw packet capture generally requires elevated privileges on Linux.

### Module 2 — Traffic Monitoring

**File:** `monitoring.py`

Calculates traffic statistics, protocol and IP summaries, traffic timelines, direction analysis, and communication-flow information from stored packet records.

### Module 3 — Detection

**File:** `detection.py`

Applies heuristic rules to identify selected traffic patterns that may warrant investigation, including traffic spikes, repeated communication, TCP activity, connection requests, and possible port scans.

### Module 4 — Dashboard

**File:** `dashboard.py`

Uses Streamlit to display traffic metrics, charts, communication flows, detection alerts, and CSV download controls.

### Module 5 — Report Generation and Documentation

The dashboard's CSV export controls support traffic and security reporting. Project documentation, screenshots, demonstration material, and the final capstone report can be prepared using the application's output and verified project evidence.

## Project Structure

The main application files are:

```text
network-traffic-analyzer/
├── database.py
├── packet_capture.py
├── monitoring.py
├── detection.py
├── dashboard.py
├── run.sh
├── requirements.txt
├── .gitignore
├── data/
│   └── traffic.db
└── venv/
```

The `data/traffic.db` and `venv/` entries represent local runtime artifacts. A source repository may intentionally omit them. Local backup files and Python cache directories may also exist in a development copy and should generally be excluded from a public source submission.

## System Requirements

- Kali Linux or another compatible Linux distribution.
- Python 3.
- Python virtual-environment support (`venv`).
- `sudo` privileges for packet capture.
- A working network interface.
- Internet access when dependencies need to be installed from a package index.

The project is developed for a Kali Linux virtual machine. Network interface names, available traffic, and permissions may differ across systems.

## Installation

### Step 1 — Install system prerequisites

On Kali Linux, run:

```bash
sudo apt update
sudo apt install -y python3-venv python3-pip
```

### Step 2 — Open the project directory

```bash
cd ~/network-traffic-analyzer
```

If you obtained the source code from a repository or archive, change into the directory where you extracted it.

### Step 3 — Create a virtual environment

If the project does not already have a virtual environment, create one:

```bash
python3 -m venv venv
```

Activate it:

```bash
source venv/bin/activate
```

If the existing virtual environment is already configured and working, you can continue using it.

### Step 4 — Install Python dependencies

With the virtual environment activated, run:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

The `requirements.txt` file records Python package versions from the development environment. Installation may require internet access.

## Running the Application

From the project directory, run:

```bash
cd ~/network-traffic-analyzer
chmod +x run.sh
./run.sh
```

The launcher is configured to request sudo authentication, initialize the SQLite database, start the packet capture process in the background, and launch the Streamlit dashboard.

When Streamlit starts, open the local address displayed in the terminal. The default local address is commonly:

**http://localhost:8501**

If Streamlit reports a different port, use the address printed in the terminal.

### Stopping the Application

Press `Ctrl+C` in the terminal running the launcher. The launcher has a cleanup trap intended to stop the background packet capture process when it exits.

If a process does not stop as expected, inspect the running processes before terminating anything manually.

## Desktop Launcher

If the project submission includes a `Network-Traffic-Analyzer.desktop` file, it can be configured to launch the application from the Kali Linux desktop.

The desktop launcher is separate from the core Python modules. Ensure its configured command points to the correct project directory and invokes `run.sh`. Desktop launchers may require executable permission and desktop-environment trust confirmation.

The desktop launcher should only be described as included in the submission if the actual `.desktop` file is present.

## Using the Dashboard

1. Start the application using `./run.sh`.
2. Open the Streamlit URL printed in the terminal.
3. Allow packet capture to collect traffic from the selected interface.
4. Review the traffic metrics, protocol charts, IP activity, timelines, communication flows, and alerts.
5. Use the dashboard's download controls to export the available CSV reports.
6. Stop the application with `Ctrl+C` in the launcher terminal.

Available traffic depends on the network interface, system permissions, virtual-machine networking mode, and current network activity. A quiet dashboard does not necessarily indicate a malfunction.

## Database Design

The application stores packet metadata in:

```text
data/traffic.db
```

The database initialization code creates the `packets` table if it does not exist and configures SQLite Write-Ahead Logging (WAL) mode.

WAL mode generally allows database readers and writers to work more effectively at the same time. It does not eliminate every possible locking, concurrency, or permissions issue.

### Packets Table

| Column | Description |
|---|---|
| `id` | Unique integer record identifier |
| `timestamp` | Recorded packet timestamp |
| `source_ip` | Source IP address, when available |
| `destination_ip` | Destination IP address, when available |
| `protocol` | Recorded protocol label |
| `source_port` | Source port, when applicable |
| `destination_port` | Destination port, when applicable |
| `packet_length` | Recorded packet length |
| `session_id` | Capture-session identifier |
| `tcp_flags` | TCP flags, when applicable |

Fields that do not apply to a particular packet may be empty. The database stores packet metadata for analysis; this README does not claim that full packet payloads are stored.

### Database and File Permissions

The launcher adjusts permissions on the data directory to allow the capture process and dashboard to access the database. Broad write permissions can create security risks on shared or production systems. Review permissions before deploying the application outside a controlled educational environment.

Do not commit captured databases or their SQLite WAL/SHM sidecar files to a public repository. Packet metadata can reveal internal IP addresses and network activity.

## Detection Rules and Alert Interpretation

The detection engine contains heuristic rule categories for:

- Unknown or unexpected IP addresses.
- High traffic volume or traffic spikes.
- Repeated communication between endpoints.
- Repeated TCP activity.
- Connection requests and SYN activity.
- Possible port scanning based on destination-port activity.

The rules use configured thresholds and behavioral indicators to flag traffic for review. For example, a source contacting many destination ports may indicate port-scanning behavior, while high traffic volume may indicate a burst of activity.

**An alert is an indicator for investigation, not proof of an attack.** Legitimate activity, including DNS traffic and normal router or application communication, can trigger heuristic rules. Results should be interpreted in network context and, where possible, corroborated with additional evidence.

## CSV Report Generation

The dashboard provides download controls for the following reports:

| Report filename | Intended purpose |
|---|---|
| `traffic_summary.csv` | Summary of observed traffic statistics |
| `connection_report.csv` | Connection or communication-flow information |
| `security_analysis.csv` | Security alerts and analysis results |

The exact rows and fields depend on the application's current export implementation and the traffic collected during the session. Export the reports from the running dashboard and review them before including them in a submission.

Before sharing reports publicly, remove sensitive internal addresses or other identifying network details where appropriate.

## Verification and Testing

The five core Python files have passed a Python syntax compilation check in the project environment.

To repeat the check from the project directory, run:

```bash
./venv/bin/python -m py_compile \
  database.py packet_capture.py monitoring.py detection.py dashboard.py
```

A successful compilation checks Python syntax. It does not independently prove that live packet capture, all detection rules, dashboard refresh, process cleanup, database permissions, or CSV exports work correctly in every environment.

For an end-to-end demonstration, verify that:

1. The launcher starts without errors.
2. The database is initialized and packet records are written.
3. The dashboard opens and displays collected traffic.
4. Detection alerts appear when applicable.
5. CSV reports can be downloaded.
6. The application stops without leaving unwanted capture processes running.

Only report tests as completed when they have actually been performed.

## Security and Responsible Use

- Capture traffic only on systems and networks you own or are explicitly authorized to monitor.
- Treat captured network metadata as potentially sensitive.
- Do not publish real packet databases, private network information, credentials, or unredacted screenshots.
- Avoid broad file permissions on shared or production systems.
- Review exported CSV files and screenshots before sharing them.
- Keep backups of project files before making substantial changes.

This project is an educational capstone and is not a replacement for a production network monitoring or intrusion detection platform.

## Limitations

- Detection is heuristic and can produce false positives or false negatives.
- Packet visibility depends on the selected interface, permissions, and network configuration.
- Traffic patterns and suitable thresholds vary between networks.
- A syntax check alone does not establish runtime correctness or detection accuracy.
- The application is intended for learning, demonstration, and authorized analysis.

## Future Improvements

Potential future improvements include:

- Configurable detection thresholds.
- Expanded automated testing.
- More precise capture-process lifecycle management.
- Stricter database and file permissions.
- Additional protocol analysis.
- More detailed reporting and historical comparisons.
- Improved setup automation for clean installations.

## Capstone Deliverables

The final capstone submission may include the following items, as required by the course:

1. Source code.
2. Formal project report in PDF format.
3. Presentation slide deck in PPTX format.
4. GitHub repository URL.
5. Dashboard screenshots.
6. Demonstration video.
7. Exported traffic analysis CSV reports.

These are submission deliverables, not claims that every item is already present in the source directory. Check the course submission instructions and ensure each required item is prepared before submission.

## License

No license is specified in this README. Add a license only after deciding which terms should govern use and redistribution of the project.
