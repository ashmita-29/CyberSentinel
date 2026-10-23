# CyberSentinel AI

An intelligent cyber threat detection and visualization dashboard, built as a final-year cybersecurity project prototype.

> **DEMO DATA — Simulated network events.** Nothing in this application is live threat intelligence. It does not monitor your network, query external services, scan hosts or send any traffic.

## Features

- **Overview**: KPIs, attack distribution, activity timeline, top source locations and recent alerts, all computed from the loaded data.
- **Global Threat Map**: stylized SVG world map with animated simulated attack paths, clickable markers, legend, filters (attack type, severity, region), zoom/reset and pause/resume.
- **Live Event Simulation**: start, pause, stop, generate one or a batch of events, choose category and speed, reset demo data.
- **Threat Detection**: edit or load a sample network event and classify it into 7 classes, with severity, explanation and recommended response.
- **Alerts & Incidents**: search, filters, detail side panel, acknowledge / investigate / resolve actions (saved in the browser's `localStorage`).
- **Dataset & Model**: 560 labeled synthetic flow records (seed 42), searchable paginated preview, CSV copy/download, CSV upload with validation, data dictionary, and rule-based evaluation metrics with a confusion matrix.
- **Analytics**: filter-aware charts and a table of synthetic indicators.
- **Settings & About**: problem statement, objective, methodology and limitations.

## Classes

Normal Traffic, DDoS / DoS, Port Scanning / Reconnaissance, Brute-Force Login, Suspicious Malware-Related Traffic, Suspicious Phishing Indicators, Data Exfiltration / Unusual Outbound Traffic. When evidence matches no rule but features are elevated, the result is "Suspicious — Further Investigation Required".

## Architecture

The whole application is a single static file, `index.html`, written in plain HTML, CSS and JavaScript with no build step and no dependencies.

1. **Data generation**: a seeded PRNG (mulberry32) creates 80 records per class using RFC 5737 documentation IP ranges, then shuffles them.
2. **Classification**: a transparent rule-based classifier uses failed-login count, destination-port diversity, packet count, response bytes, duration, outbound/inbound byte ratio and destination port.
3. **Severity**: assigned per predicted class (Critical, High, Medium, None).
4. **Visualization**: SVG map and charts rendered from the event list.
5. **Investigation**: alerts carry a status that persists in the browser.

## Optional: real ML training with Python

The `backend/` folder adds a scikit-learn **Random Forest** trained through a Flask API.

```bash
pip install -r requirements.txt
python backend/app.py          # serves http://127.0.0.1:5000
```

Open `http://127.0.0.1:5000`, go to **Dataset & Model** and press **Train Model**. The page shows the backend status, then the held-out test accuracy, per-class precision/recall/F1, confusion matrix and feature importances. On **Threat Detection**, each classified event also shows the Random Forest label with its vote-share confidence once the model is trained.

- Features: destination port, protocol, duration, packet count, bytes sent/received, failed logins, unique destination ports, byte ratio.
- Identifiers (timestamp, IP addresses, source port) are excluded to avoid leakage; exact duplicates are removed before a stratified 75/25 split.
- Confidence is the forest's vote share, not a calibrated probability; below 0.5 the result is "Suspicious — Further Investigation Required".
- `python backend/dataset.py` writes the seeded dataset (a share of attack rows overlap with normal ranges). The Python and in-browser generators are separate, so their records differ.
- The backend binds to 127.0.0.1 only, so the hosted/published page cannot reach it; use the local run above.

## Run the front end only

No installation is needed. Either:

```bash
# Option 1: open the file directly
open index.html          # macOS; on Windows double-click it, on Linux use xdg-open

# Option 2: serve it locally
python3 -m http.server 8000
# then visit http://localhost:8000
```

## Deploy

- **Vercel**: import the repository as a project, framework preset "Other", no build command, output directory left at the root.
- **GitHub Pages**: Settings → Pages → deploy from branch `main`, folder `/ (root)`.

## Limitations

- Without the Python backend, this is a **Rule-Based Demo Classifier**: no ML model, no confidence scores, and "Train Model" is disabled.
- The "Rule evaluation" panel measures the hand-written rules against the labels of the loaded dataset. They are **not** held-out ML test-set metrics and do not indicate real-world detection performance.
- The synthetic classes are intentionally well separated, so reported metrics are optimistic.
- Malware and phishing outputs are indicators only; real detection would need host, URL or content evidence.
- The map is a stylized SVG, not OpenStreetMap tiles, and all locations and paths are simulated.
- Even the Random Forest is trained on synthetic data, so near-perfect test scores show the classes are separable, not that it would detect real attacks.
- The Threat Intelligence page, time-range filter and React/Tailwind/Recharts stack are not included in this version.
- Browser downloads may be blocked in some hosted/sandboxed environments; use "Copy CSV" as a fallback.

## Possible future work

Train on a public labeled flow dataset (for example CIC-IDS2017) for realistic evaluation, add a dedicated Threat Intelligence page, and add a time-range filter.

## Licence

Add a licence of your choice (for example MIT) before publishing.
