# VAPT Scanner

**AI-Augmented Vulnerability Assessment & Penetration Testing Platform**

VAPT Scanner is a Flask-based web application security scanner that combines
traditional DAST (Dynamic Application Security Testing) with SAST (Static
Application Security Testing), zero-day anomaly detection, and an AI-driven
risk-scoring layer. It crawls a target site, actively probes for common web
vulnerabilities, correlates findings with source-code analysis, and produces
a prioritized, business-context-aware security report — complete with a live
dashboard and downloadable PDF reports.

> ⚠️ **For authorized security testing only.** Only scan applications you own
> or have explicit written permission to test. See [Disclaimer](#disclaimer).

---

## Features

- **Active DAST scanning** — SQL Injection, XSS (reflected & DOM-based),
  IDOR, Command Injection, Directory Traversal, CORS misconfiguration,
  CSRF, Open Redirect, Business Logic flaws, Rate Limiting, and more.
- **Reconnaissance** — TLS/SSL inspection, HTTP security header auditing,
  server banner grabbing, and technology fingerprinting.
- **SAST module** — Scans local source directories for hardcoded secrets,
  insecure configurations, and dangerous coding patterns.
- **Hybrid Intelligence Layer** — Correlates SAST + DAST findings to reduce
  false positives and surface confirmed, high-confidence issues.
- **AI Autonomous Analyzer** — Generates exploitability likelihood scores and
  benign proof-of-concept notes for each finding.
- **Zero-Day / Anomaly Detection** — Statistical response-timing and
  behavioral analysis to flag unusual, potentially unknown vulnerabilities.
- **Self-Learning Feedback Loop** — Persists analyst feedback to refine
  future risk weighting.
- **Contextual Risk Model** — Converts raw CVSS scores into business-aware
  priority scores (data sensitivity, compliance scope, public exposure).
- **CVSS / OWASP / CWE mapping** — Every finding is enriched with severity,
  CWE ID, OWASP category, description, and remediation guidance.
- **Distributed Orchestrator** — Multi-target, multi-threaded scan execution.
- **Reporting** — Interactive web dashboard, severity distribution chart,
  and exportable PDF reports.

## Architecture

```
                ┌───────────────────┐
   Target(s) ──►│   Orchestrator     │  (multi-threaded, multi-target)
                └────────┬──────────┘
                         │
        ┌────────────────┼─────────────────┐
        ▼                ▼                 ▼
   crawler.py        recon.py         detection.py
   (site map,       (SSL, headers,    (SQLi, XSS, IDOR,
    forms)           banners)          CSRF, etc.)
        │                │                 │
        └────────┬───────┴────────┬────────┘
                  ▼                ▼
          core/zero_day.py   hybrid/sast_analyzer.py
        (anomaly detection)   (static source scan)
                  │                │
                  └───────┬────────┘
                           ▼
              core/intelligence_layer.py
              (correlate SAST + DAST findings)
                           ▼
                core/ai_analyzer.py
             (exploitability & PoC scoring)
                           ▼
             core/feedback_loop.py
            (self-learning weighting)
                           ▼
                  cvss.py (OWASP/CWE/CVSS mapping)
                           ▼
               core/risk_model.py
          (contextual priority scoring)
                           ▼
             app.py → dashboard.html / PDF report
```

## Tech Stack

| Layer            | Technology                          |
|-------------------|--------------------------------------|
| Web framework      | Flask                                |
| HTTP / crawling    | requests, BeautifulSoup4             |
| Charts             | matplotlib                           |
| PDF reports        | ReportLab                            |
| Crypto / TLS       | cryptography                         |
| Optional proxy     | python-owasp-zap-v2.4 (OWASP ZAP)    |

## Getting Started

### Prerequisites

- Python 3.10+
- pip

### Installation

```bash
git clone https://github.com/ramKarthik57/VAPT_Scanner.git
cd VAPT_Scanner
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Running

```bash
python app.py
```

The dashboard will be available at `http://127.0.0.1:5000`.

### Usage

1. Open the dashboard in your browser.
2. Enter one or more target URLs (comma-separated) that you are authorized
   to test.
3. Choose a scan mode:
   - **Quick** — fast, shallow crawl (10 pages, 5 threads).
   - **Deep** — thorough crawl with deep payloads (30 pages, 10 threads).
   - **Research** — maximum coverage for research purposes (50 pages, 15 threads).
4. (Optional) Provide a local source directory path to enable SAST scanning.
5. (Optional) Flag whether the target handles critical data assets or is in
   scope for GDPR to enable contextual risk scoring.
6. Review results on the live dashboard, including the security score,
   severity distribution chart, and per-finding remediation guidance.
7. Download the auto-generated PDF report from the `static/` output folder.

## Project Structure

```
VAPT_Scanner/
├── app.py                     # Flask app, scan pipeline, PDF/chart generation
├── crawler.py                  # Site crawling & form discovery
├── recon.py                    # SSL/TLS, header, and banner reconnaissance
├── detection.py                  # DAST vulnerability detection modules
├── cvss.py                        # CVSS/OWASP/CWE knowledge base & mapping
├── orchestrator.py                 # Multi-target, multi-threaded scan orchestration
├── core/
│   ├── ai_analyzer.py                # AI exploitability scoring & PoC notes
│   ├── zero_day.py                    # Anomaly / zero-day detection
│   ├── feedback_loop.py                 # Self-learning feedback persistence
│   ├── intelligence_layer.py             # SAST + DAST correlation
│   ├── risk_model.py                      # Contextual business risk scoring
│   └── waf_evasion.py                      # Payload mutation / WAF evasion engine
├── hybrid/
│   └── sast_analyzer.py                     # Static source-code analysis
├── templates/
│   └── dashboard.html                        # Web dashboard UI
├── static/                                    # Generated charts & PDF reports
├── requirements.txt
└── test_scanner.py                             # Test suite
```

## Testing

```bash
python test_scanner.py
```

## Benchmarking

```bash
python run_benchmarks.py
```

## Roadmap

- [ ] Authentication-aware scanning (session/token support)
- [ ] REST API for CI/CD pipeline integration
- [ ] Dockerized deployment
- [ ] Pluggable detection module system

## Disclaimer

This tool is intended strictly for **educational purposes and authorized
security assessments**. Scanning systems without explicit permission from
their owner is illegal in most jurisdictions. The authors and contributors
assume no liability for misuse or damage caused by this tool.

## License

Released under the [MIT License](LICENSE).
