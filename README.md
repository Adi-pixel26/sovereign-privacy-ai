# SovereignGuard AI — Sovereign Personal Privacy & Digital Identity Agent

> Proactive personal privacy protection platform with autonomous agents that actively monitor web data leaks, automate Right-to-be-Forgotten (RTBF) legal takedown requests under GDPR/CCPA/PIPEDA, deploy anti-scraping honeytoken canary meshes, and provide synthetic identity masking.

---

## Key Features

1. **Web & Dark Web Data Leak Monitor**:
   - Continuously scans public breach indices, dark web pastebins, and data broker leak datasets for monitored email targets.
   - Calculates a real-time **Sovereign Privacy Health Score (0–100)** based on exposure type, severity (passwords, PII, financial metadata), and leak age.

2. **Automated Right-To-Be-Forgotten (RTBF) Legal Request Engine**:
   - Legally binding takedown notice generation supporting:
     - **GDPR (EU/UK)**: Article 17 (Right to Erasure) & Article 21 (Right to Object).
     - **CCPA / CPRA (California)**: §1798.105 (Right to Delete) & §1798.120 (Do Not Sell/Share).
     - **PIPEDA (Canada)** & **VCDPA (Virginia)** state privacy laws.
   - Indexed database of major Data Brokers (Acxiom, Spokeo, Whitepages, LexisNexis, Intelius, Radaris) with 1-click opt-out generation.
   - SHA-256 cryptographic identity ownership proof tokens attached to legal demands.
   - Lifecycle tracking (`DRAFT` -> `DISPATCHED` -> `ACKNOWLEDGED` -> `VERIFIED_REMOVED`).

3. **Invasive Data-Scraping Defense & Honeytoken Mesh**:
   - Deploy dynamic canary web beacons (`HONEY_URL`), decoy emails (`HONEY_EMAIL`), and synthetic PII tags (`DECOY_PII`) to track unauthorized scrapers and LLM training crawlers in real time.
   - Anti-AI & bot shield generator for `robots.txt` (blocking GPTBot, CCBot, ClaudeBot, Bytespider, Scrapy).
   - Global Privacy Control (GPC `Sec-GPC: 1`) security header generator.

4. **Zero-Knowledge Identity Vault & Masking**:
   - Service-bound virtual email alias routing generator (`service.abcd@shield.sovereignprivacy.io`).
   - Synthetic persona builder for low-trust registrations.
   - Zero-Knowledge (ZK) attribute proof hash generator (proving age/jurisdiction without revealing raw identity PII).

5. **Autonomous Agent Loop**:
   - Evaluates breach risk automatically; auto-generates and dispatches RTBF legal notices when severe leaks exceed configured risk thresholds.

---

## Quick Start & Installation

### 1. Requirements
- Python 3.10+
- Installed dependencies: `fastapi`, `uvicorn`, `pydantic`, `httpx`, `pytest`, `jinja2`, `python-multipart`.

### 2. Running Unit Tests
```bash
python -m pytest tests/
```

### 3. CLI Usage

- **Run Leak Scan**:
  ```bash
  python -m sovereign_privacy.cli scan
  ```

- **Generate RTBF Legal Request**:
  ```bash
  python -m sovereign_privacy.cli rtbf --target "Acxiom" --law GDPR
  ```

- **Deploy Anti-Scraping Honeytoken**:
  ```bash
  python -m sovereign_privacy.cli honeytoken --type HONEY_URL --label "Blog Footer"
  ```

- **Run Autonomous Defense Cycle**:
  ```bash
  python -m sovereign_privacy.cli cycle
  ```

- **Launch Web Dashboard & REST Server**:
  ```bash
  python -m sovereign_privacy.cli serve --port 8000
  ```

Access the interactive web dashboard at: `http://localhost:8000`

---

## Architecture Overview

```
sovereign_privacy_agent/
├── sovereign_privacy/
│   ├── core/
│   │   ├── leak_monitor.py     # Leak detection & Privacy Health scoring
│   │   ├── rtbf_agent.py        # Legal RTBF request generator & broker index
│   │   ├── anti_scraper.py      # Honeytokens, canary web beacons, robots.txt AI shield
│   │   ├── identity_masker.py   # Disposable aliases, synthetic profiles, ZK proofs
│   │   └── orchestrator.py      # Autonomous defense loop controller
│   ├── db/
│   │   └── storage.py           # Persistent JSON/SQLite storage layer
│   ├── web/
│   │   ├── app.py               # FastAPI REST API backend
│   │   └── templates/
│   │       └── index.html       # SPA Dashboard UI (Tailwind + Alpine.js)
│   └── cli.py                   # Terminal power-user CLI
├── tests/
│   └── test_sovereign_privacy.py# Pytest test suite (100% pass)
├── requirements.txt
└── README.md
```
