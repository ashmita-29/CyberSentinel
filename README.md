# CyberSentinel AI

An educational cybersecurity dashboard that visualizes **simulated** network threats and classifies network-flow events, with an optional Python backend that trains a Random Forest on synthetic data.

> **DEMO DATA — Simulated network events.** CyberSentinel does not monitor your network, query external threat-intelligence services, scan hosts or send any traffic. Nothing it shows is a real attack.

**Live demo (rule-based mode):** https://cybersentinel-tau.vercel.app/

## Features

| Page | What it does |
|---|---|
| Overview | KPIs, attack distribution, activity timeline, top source locations and recent alerts, all computed from the loaded data |
| Global Threat Map | Stylized SVG world map with animated simulated attack paths, clickable markers, legend, filters (type, severity, region), zoom/reset, pause/resume |
| Live Event Simulation | Start, pause, stop, generate one or a batch of events, pick a category and speed, reset demo data |
| Threat Detection | Edit or load a sample flow, classify it into 7 classes with severity, explanation and recommended response |
| Alerts & Incidents | Search, filters, detail panel, acknowledge / investigate / resolve (saved in `localStorage`) |
| Dataset & Model | 560 labeled synthetic records (seed 42), searchable preview, CSV copy/download, validated CSV upload, data dictionary, rule evaluation, and ML results when the backend runs |
| Analytics | Filter-aware charts and a table of synthetic indicators |
| Settings & About | Problem statement, objective, methodology, limitations |

**Classes:** Normal Traffic, DDoS / DoS, Port Scanning / Reconnaissance, Brute-Force Login, Suspicious Malware-Related Traffic, Suspicious Phishing Indicators, Data Exfiltration / Unusual Outbound Traffic. When features are elevated but no pattern matches, the result is *"Suspicious — Further Investigation Required"*.

## Tech stack

- **Front end:** a single `index.html` (plain HTML, CSS, JavaScript, inline SVG). No build step, no dependencies.
- **Back end (optional):** Python 3.12, Flask, scikit-learn, pandas, NumPy, joblib.

## Project structure

```
CyberSentinel/
├── index.html          # the whole dashboard
├── README.md
├── requirements.txt    # optional Python backend
├── .gitignore
└── backend/
    ├── app.py          # Flask API (binds to 127.0.0.1)
    ├── model.py        # Random Forest training and prediction
    └── dataset.py      # seeded synthetic dataset generator
```

## Quick start

**Front end only (no installation):**
**With real ML training:**


## How it works

1. **Data.** A seeded generator creates 80 records per class using RFC 5737 documentation IP ranges. About 15% of rows are low-intensity "stealth" variants that overlap with normal traffic.
2. **Rule-based classifier (browser).** Transparent thresholds on failed logins, destination-port diversity, packet count, response bytes, duration, byte ratio and destination port. It gives no confidence score.
3. **Random Forest (backend).** Features: destination port, protocol, duration, packet count, bytes sent/received, failed logins, unique destination ports, byte ratio. Timestamps, IP addresses and source ports are excluded to avoid leakage, exact duplicates are removed before a stratified 75/25 split, and all metrics come from the held-out test set. Confidence is the forest's vote share, not a calibrated probability; below 0.5 the result is "Suspicious — Further Investigation Required".
4. **Severity.** Assigned per predicted class (Critical, High, Medium, None).
5. **Investigation.** Alerts carry a status (New, Acknowledged, Investigating, Resolved).

### Rule thresholds (first match wins)

| Class | Condition |
|---|---|
| Brute-Force Login | failed logins ≥ 5 |
| Port Scanning | unique destination ports ≥ 15 and packets ≤ 300 |
| DDoS / DoS | packets ≥ 3000, bytes received < 5000, duration < 60 s |
| Data Exfiltration | outbound/inbound ratio ≥ 10 and bytes sent ≥ 2 MB |
| Malware-related | port in {4444, 6667, 31337, 1337}, duration ≥ 300 s, bytes sent < 10 KB |
| Phishing indicators | port in {8080, 8443, 8888}, ≥ 1 failed login, duration < 10 s, bytes sent < 5 KB |

## Results from a test run

Trained on the 560-record generated dataset (140 held-out test records): test accuracy **100%**, with 5-fold cross-validation on the training split of about **99.5%**. These scores show that the synthetic classes are separable. They do **not** show how the model would perform on real traffic.

## API (backend)

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/health` | Status and whether a model is trained |
| POST | `/api/train` | Train on posted CSV text (`{"csv": "..."}`) or the built-in dataset |
| GET | `/api/metrics` | Latest held-out metrics |
| POST | `/api/predict` | Classify one flow event |
| GET | `/api/dataset.csv` | Download the generated dataset |

## Limitations

- Without the backend, classification is **rule-based**; no ML model is involved and no confidence scores are shown.
- The "Rule evaluation" panel measures hand-written rules against generator labels; it is not a held-out ML evaluation.
- All data, locations and attack paths are synthetic. Good scores on synthetic data do not establish real-world detection performance.
- Malware and phishing outputs are indicators only; reliable detection needs host, URL or content evidence.
- The map is a stylized SVG, not live tiles.
- Browser downloads may be blocked in sandboxed environments; use "Copy CSV" instead.

## Future work

Train and evaluate on a public labeled flow dataset such as CIC-IDS2017, add a Threat Intelligence page and a time-range filter, and calibrate model confidence.

## Ethics

Use this project only for learning. Do not point it at systems you do not own, and do not treat its output as security advice.

## Author

Ashmita ([@ashmita-29](https://github.com/ashmita-29)). 

