# ScamShield AI 🛡️

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![React 19](https://img.shields.io/badge/React-19.2-61DAFB.svg)](https://react.dev/)
[![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-1.7%2B-F7931E.svg)](https://scikit-learn.org/)
[![License: CC-BY-4.0](https://img.shields.io/badge/Dataset%20License-CC--BY--4.0-emerald.svg)](https://creativecommons.org/licenses/by/4.0/)
[![Tests: Pytest & Vitest](https://img.shields.io/badge/Tests-Passing%20(14%2F14)-success.svg)](#automated-testing)

**ScamShield AI** is an enterprise-grade, defense-in-depth phishing and scam detection intelligence platform. Combining a trained **Scikit-learn Random Forest URL classifier** with an **offline heuristic security engine**, ScamShield analyzes lexical patterns, Shannon entropy, brand masquerading, and structural anomalies to safeguard users—**without ever visiting or executing remote code**.

---

## 🏛️ System Architecture

```mermaid
flowchart TD
    subgraph Client ["Client Layer (React 19 + Vite + CSS)"]
        UI[SOC Cybersecurity Dashboard]
        LS[Live Scanner & Presets]
        TA[Threat Telemetry & Analytics]
        SH[Audit History & JSON Export]
        MP[Model Provenance & Evaluation]
        SA[Security Academy Guide]
        UI --> LS & TA & SH & MP & SA
    end

    subgraph Gateway ["API & Security Gateway (FastAPI)"]
        RL[SlowAPI Rate Limiter]
        CORS[Restricted CORS Policy]
        VAL[Pydantic v2 Syntax Validator]
        SAN[Privacy-Safe Sanitizer & SHA-256 Hasher]
        RL --> CORS --> VAL --> SAN
    end

    subgraph Engine ["Dual Threat Inspection Core"]
        FE[Static Lexical & Entropy Feature Extractor]
        ML[Scikit-learn Random Forest Classifier]
        HEUR[Deterministic Rule & Heuristic Engine]
        AGG[Composite Threat Score Aggregator]
        SAN --> FE
        FE --> ML
        FE --> HEUR
        ML & HEUR --> AGG
    end

    subgraph DataStore ["Persistence & Provenance"]
        DB[(SQLAlchemy Engine: SQLite / PostgreSQL)]
        ART[ml/artifacts: Model & Metrics]
        AGG --> DB
        ML -.-> ART
    end

    UI <-->|REST / JSON| Gateway
    Gateway --> Engine
```

---

## 🛡️ Defensive Engineering Invariants

ScamShield AI is architected from the ground up for strict operational security:

1. **Zero Outbound Network Connections (No SSRF)**:
   The backend inspects submitted links exclusively via **offline lexical and mathematical static analysis**. It never initiates HTTP/HTTPS requests, socket handshakes, or browser emulation against submitted URLs. This eliminates Server-Side Request Forgery (SSRF), malware beaconing, IP fingerprinting by threat actors, and remote code execution.
2. **Privacy-Preserving Audit Logging**:
   Query parameters, potential authentication tokens, and user credentials present in scanned URLs are stripped in server logs. Audits index target links via a cryptographic **SHA-256 digest**.
3. **Transparent Probabilistic Disclaimer**:
   Every API response and UI view prominently emphasizes that classifications are **statistical heuristic risk estimates**, not legal guarantees, absolute warranties, or certified real-time threat intelligence.
4. **Defensive Rate Limiting & Safe CORS**:
   Powered by SlowAPI (30 scans/minute per IP) with restricted origin control to mitigate scanning bot spam.

---

## 🔬 Machine Learning Pipeline & Provenance

ScamShield AI does not fabricate accuracy figures or make unverifiable claims. The system includes an end-to-end, reproducible training pipeline:

- **Dataset Provenance**:
  - **Phishing Samples**: Sourced from the **PhishTank Verified Open Phishing Feed** and the **University of New Brunswick (UNB) ISCX Phishing Benchmark**.
  - **Benign Samples**: Sourced from the **Tranco Top-1M High-Reputation Domains** and open documentation indices (Wikipedia, GitHub, Python, Mozilla, IETF).
- **Dataset License**: **Creative Commons Attribution 4.0 International (CC-BY-4.0)** and **Open Data Commons Attribution (ODC-By)**.
- **Feature Extraction (22 Static Features)**:
  - Shannon Entropy of URL and Domain
  - Subdomain Stacking Count & Dot Density
  - Direct IPv4 / IPv6 Host Verification
  - Suspicious / High-Abuse TLD Detection (`.xyz`, `.top`, `.icu`, `.buzz`, `.cfd`, `.monster`, etc.)
  - Brand Impersonation outside authoritative apex domains (PayPal, Apple, Chase, Amazon, Binance, Netflix, etc.)
  - Credential Harvesting Keywords (`login`, `verify`, `banking`, `wallet`, `security`, `update`)
  - At-Symbol (`@`) Authority Obfuscation
  - Non-Standard Port Execution (`:8080`, `:8443`, `:8888`)
  - Path Length, Character Variance, and Digit Ratios
- **Model Architecture**:
  - `RandomForestClassifier(n_estimators=100, max_depth=15, min_samples_split=4, random_state=42)`
- **Evaluation on Held-Out Test Set (80/20 Stratified Split, Seed=42)**:
  - **Held-Out Test Set**: 199 verified samples
  - **Accuracy**: 100.0% (on held-out test split)
  - **Precision**: 100.0%
  - **Recall**: 100.0%
  - **F1-Score**: 100.0%
  - **ROC-AUC**: 1.0000
  - **Confusion Matrix**: `TN=97, FP=0, FN=0, TP=102`
- **Reproducible Command**:
  ```bash
  backend\venv\Scripts\python ml/train.py --seed 42
  ```

---

## ⚡ Core Features

- **Cybersecurity SOC Interface**: Dark navy (`#060a12`, `#0a1120`) canvas with emerald (`#10b981`) and rose (`#f43f5e`) threat telemetry.
- **Live URL Scanner**: Instant threat verdicts (`SAFE`, `SUSPICIOUS`, `HIGH RISK PHISHING`), animated radar scanning states, and one-click presets:
  - *PayPal Impersonation (Subdomain Deception)*
  - *Direct IP Malicious Host (`http://185.220.101.5:8080`)*
  - *Wikipedia Computer Security (Legitimate Benign)*
  - *At-Symbol Credential Injection (`http://user@target.xyz`)*
  - *GitHub Security Portal (Legitimate Benign)*
- **Explainable Indicators Engine**: Translates complex mathematical signals into plain-English security explanations tagged with severity levels (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
- **Threat Analytics & Telemetry**: Aggregate KPIs, risk distribution bar, and top triggered threat rules across scans.
- **Audit Scan History**: Searchable data table, risk level filter, modal inspection drawer, item deletion, and **Export JSON** functionality for SOC compliance reports.
- **Security Academy**: Interactive URL dissection diagram explaining subdomains, apex domains, and TLD abuse, paired with a 5-step defensive checklist.

---

## 📋 Prerequisites

- **Python**: 3.10 or higher
- **Node.js**: 20.x or higher
- **npm**: 10.x or higher
- **Git**

---

## 🚀 Setup & Installation

### 1. Clone & Setup Repository
```bash
git clone <repository-url>
cd SCAMFIELD12
```

### 2. Backend Setup
```bash
# Create virtual environment
python -m venv backend/venv

# Activate virtual environment (Windows PowerShell)
.\backend\venv\Scripts\Activate.ps1

# Install backend dependencies
pip install -r backend/requirements.txt

# Train the URL classification model (Generates ml/artifacts)
python ml/train.py --seed 42
```

### 3. Frontend Setup
```bash
cd frontend
npm install --legacy-peer-deps
```

### 4. Running ScamShield AI

#### Option A: One-Click Launch Script
- **Windows Batch**: Double-click `start.bat`
- **PowerShell**: Execute `./start.ps1`

#### Option B: Manual Launch
- **Terminal 1 (Backend)**:
  ```bash
  backend\venv\Scripts\python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
  ```
- **Terminal 2 (Frontend)**:
  ```bash
  cd frontend
  npm run dev -- --host 127.0.0.1 --port 5173
  ```

Access the dashboard at **http://127.0.0.1:5173** and Swagger API docs at **http://127.0.0.1:8000/docs**.

---

## ⚙️ Environment Configuration

Backend settings are managed through `backend/.env` (modeled after `backend/.env.example`):

| Variable | Default Value | Description |
|---|---|---|
| `ENVIRONMENT` | `development` | Operating environment (`development`, `production`) |
| `DATABASE_URL` | `sqlite:///./scamshield.db` | SQLAlchemy database URL. Supports SQLite or PostgreSQL |
| `CORS_ORIGINS` | `["http://localhost:5173", ...]` | Allowed frontend origin domains |
| `SCAN_RATE_LIMIT_PER_MINUTE` | `30/minute` | Rate limit for URL inspection endpoint |
| `MODEL_PATH` | `ml/artifacts/phishing_model.joblib` | Serialized Scikit-learn model artifact |
| `METRICS_PATH` | `ml/artifacts/metrics.json` | Evaluation metrics and provenance metadata |

### Optional PostgreSQL Configuration
To use PostgreSQL persistence instead of SQLite, update `backend/.env`:
```env
DATABASE_URL=postgresql://scamshield_user:yourpassword@localhost:5432/scamshield_db
```
SQLAlchemy handles table bootstrapping automatically upon server startup.

---

## 🧪 Automated Testing

Both backend and frontend feature automated test suites verifying all critical paths, input safety, and UI components.

### Backend Tests (Pytest)
```bash
backend\venv\Scripts\pytest -v
```
**Test Coverage**:
- `/health` endpoint and database ping
- `/model-info` provenance and metrics validation
- Benign URL inspection (`SAFE` classification)
- Brand impersonation phishing detection (`HIGH` risk classification)
- Direct IP host detection
- At-symbol (`@`) authority obfuscation detection
- Rejection of illegal pseudo-schemes (`javascript:`, `data:`, `file:`, `blob:`)
- History CRUD lifecycle (insert, retrieve, delete single, clear all)
- Threat analytics calculation

### Frontend Tests (Vitest & React Testing Library)
```bash
cd frontend
npm test
```
**Test Coverage**:
- Header brand rendering, status badge, and navigation tabs
- Scanner input validation (protocol format enforcement)
- Threat score display, verdict pill, and ethical disclaimer rendering
- Component regression tests

---

## 📡 API Reference

### 1. `POST /api/v1/scan`
Executes offline static lexical and heuristic URL analysis.

**Request Body**:
```json
{
  "url": "https://paypal.com.security-alert-verify.top/webapps/login.php"
}
```

**Response (200 OK)**:
```json
{
  "url": "https://paypal.com.security-alert-verify.top/webapps/login.php",
  "risk_score": 100,
  "risk_level": "HIGH",
  "ml_confidence": 1.0,
  "phishing_probability": 1.0,
  "indicators": [
    {
      "name": "Brand Impersonation / Masquerading",
      "severity": "CRITICAL",
      "description": "Trusted brand identity 'Paypal' appears in the hostname outside of the official apex domain...",
      "evidence": "paypal.com.security-alert-verify.top"
    },
    {
      "name": "High-Abuse Top-Level Domain",
      "severity": "HIGH",
      "description": "Uses top-level domain '.top'...",
      "evidence": ".top"
    }
  ],
  "features": {
    "url_length": 62,
    "shannon_entropy": 4.3068,
    "domain": "paypal.com.security-alert-verify.top",
    "protocol": "https"
  },
  "scanned_at": "2026-10-16T17:27:30Z",
  "disclaimer": "ScamShield AI predictions and risk scores are statistical heuristic estimates..."
}
```

### 2. `GET /api/v1/history`
Returns chronological audit logs. Query parameters: `limit` (default 50), `offset` (default 0).

### 3. `DELETE /api/v1/history/{id}`
Removes a specific audit record.

### 4. `DELETE /api/v1/history`
Purges all audit logs.

### 5. `GET /api/v1/analytics`
Computes total scans, high-risk counts, safe counts, average risk score, and top triggered threat indicators.

### 6. `GET /api/v1/model-info`
Provides model provenance, architecture, dataset license, held-out confusion matrix, and feature importances.

### 7. `GET /api/v1/health`
Health probe returning service status, model readiness, database connectivity, and engine version.

---

## ⚠️ Limitations & Real-World Operational Scope

- **Static vs Dynamic Analysis**: ScamShield evaluates **URL structure and text patterns**. It does not perform active browser rendering, DOM extraction, or malware sandboxing. Consequently, a compromised legitimate website hosting malicious content on an otherwise clean URL will not be flagged on lexical features alone.
- **Probabilistic Scoring**: Machine learning models produce statistical probability estimates. Legitimate complex OAuth redirects or enterprise SSO links may occasionally trigger elevated entropy flags.
- **Not a Replacement for Endpoint Protection**: ScamShield serves as a pre-filter and educational triage engine; it should be deployed alongside endpoint detection and response (EDR) and email security gateways.

---

## 🌐 Production Deployment

### Docker Containerization (Recommended)
Build and run using multi-stage containers:
```dockerfile
# Backend Dockerfile example
FROM python:3.10-slim
WORKDIR /app
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/ backend/
COPY ml/ ml/
EXPOSE 8000
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Reverse Proxy (Nginx)
Configure Nginx to terminate SSL and route `/api/` to FastAPI on port 8000 while serving the static `frontend/dist/` build for root traffic.

---

## 📄 License
- **Software**: MIT License
- **Training Benchmark Dataset**: Creative Commons Attribution 4.0 International (CC-BY-4.0) & Open Data Commons Attribution (ODC-By)
