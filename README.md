# IP Reputation Pipeline

An AI-enhanced desktop application for cybersecurity analysts to scan and classify IP addresses as Block, Review, or Allow using a two-stage decision engine backed by the AbuseIPDB threat intelligence API.

Built as a senior capstone project to streamline daily SIEM review workflows.

---

## What It Does

Security engineers regularly review SIEM alerts triggered by external IP addresses. Manually investigating each one is time-consuming and inconsistent. This tool automates that process by:

1. Accepting up to 1,000 IP addresses per run via a paste interface
2. Querying the AbuseIPDB API for each IP's global reputation score
3. Running the data through a two-stage decision pipeline:
   - Stage 1 — Rule Engine: Hard thresholds based on abuse confidence score, report count, whitelist status, and usage type
   - Stage 2 — AI Heuristic Layer: Catches edge cases the rules miss — repeat offenders, data center IPs with unusual patterns, extremely high-risk scores
4. Outputting a decision of BLOCK, REVIEW, or ALLOW with a full rationale for each IP
5. Saving results to a CSV file for documentation and audit trails
6. Maintaining a local history database to track IP activity over time

---

## Features

- No Python required for end users — distributed as a standalone `.app` (Mac)
- API key never stored — entered at runtime on every session for security
- Local SQLite cache — IPs seen within 24 hours skip the API call to preserve daily quota
- History & Database tab — view, search, filter, export, and wipe scan history
- Color-coded results — BLOCK /  REVIEW /  ALLOW /  SKIP
- **Sortable results table — click any column header to sort
- Detail panel — click any result row to see the full decision rationale

---

## Tech Stack

| Technology | Purpose |

| Python | Core language |
| PyQt5 | Desktop UI framework |
| SQLite | Local IP history database |
| AbuseIPDB API | External threat intelligence source |
| Requests | HTTP library for API calls |
| PyInstaller | Packages app into standalone executable |

---

## Requirements

- Python 3.8+
- An AbuseIPDB account and API key (free tier supports 1,000 checks/day) — [get one here](https://www.abuseipdb.com/register)

Install dependencies:
```bash
pip3 install -r requirements.txt
```

---

## Running from Source

```bash
git clone https://github.com/johnnyweber14/ip_reputation_pipeline_app.py.git
cd ip_reputation_pipeline_app.py
pip3 install -r requirements.txt
python3 app.py
```

---

## Building the Standalone App

**Mac (.app):**
```bash
pip3 install pyinstaller
pyinstaller --windowed --name "IP Reputation Pipeline" --add-data "header.jpg:." app.py
```

The `.app` will appear in the `dist/` folder.


## How to Use

1. Launch the app
2. Enter your AbuseIPDB API key (not saved — entered fresh each session)
3. Paste IP addresses into the input box — one per line
4. Click Choose Save Location to select where your CSV output will be saved
5. Click Run Pipeline**
6. Review color-coded results in the table — click any row for full rationale
7. Switch to the **History tab** to manage past scan data

---

## Project Structure

```
ip_reputation_pipeline_app.py/
├── app.py              # Desktop UI — PyQt5 window, tabs, worker thread
├── pipeline.py         # Backend engine — API calls, rule engine, AI layer, DB
├── header.jpg          # Header image bundled into the app
├── requirements.txt    # Python dependencies
└── README.md           # This file
```

---

## Decision Logic

| Score | Decision |
|---|---|
| 75 and above | BLOCK |
| 40 – 74 | REVIEW |
| Below 40 | ALLOW |

Scores are calculated from the AbuseIPDB confidence score, adjusted by report count, whitelist status, usage type, and local scan history. The AI heuristic layer I hardcoded then applies additional rules to catch edge cases.

---
