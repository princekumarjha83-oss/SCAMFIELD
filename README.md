# ScamShield AI 🛡️
### *Enterprise Multi-Modal Threat Intelligence & Scam Detection Platform*

<p align="center">
  <a href="https://scamfield-9pin.vercel.app">
    <img src="https://img.shields.io/badge/🌐_Live_Platform-scamfield--9pin.vercel.app-00f2fe?style=for-the-badge&logo=vercel&logoColor=black" alt="Live Demo" />
  </a>
  <a href="https://scamfield.onrender.com/api/v1/health">
    <img src="https://img.shields.io/badge/⚡_Production_API-scamfield.onrender.com-4facfe?style=for-the-badge&logo=fastapi&logoColor=white" alt="API Health" />
  </a>
  <a href="https://scamfield.onrender.com/docs">
    <img src="https://img.shields.io/badge/📖_Interactive_Docs-Swagger_OpenAPI-10b981?style=for-the-badge&logo=swagger&logoColor=white" alt="Swagger Docs" />
  </a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/FastAPI-0.110%2B-009688?style=flat-square&logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/React-19.2-61DAFB?style=flat-square&logo=react&logoColor=black" alt="React" />
  <img src="https://img.shields.io/badge/Vite-8.3-646CFF?style=flat-square&logo=vite&logoColor=white" alt="Vite" />
  <img src="https://img.shields.io/badge/Scikit--Learn-1.7-F7931E?style=flat-square&logo=scikitlearn&logoColor=white" alt="Scikit-Learn" />
  <img src="https://img.shields.io/badge/OCR-Native_Windows_Media_OCR-0078D7?style=flat-square&logo=windows&logoColor=white" alt="OCR" />
  <img src="https://img.shields.io/badge/Tests-14%2F14_Pytest_Passing-success?style=flat-square&logo=pytest&logoColor=white" alt="Pytest" />
  <img src="https://img.shields.io/badge/Tests-5%2F5_Vitest_Passing-success?style=flat-square&logo=vitest&logoColor=white" alt="Vitest" />
  <img src="https://img.shields.io/badge/Security-Zero_SSRF_Safeguard-emerald?style=flat-square" alt="Zero SSRF" />
  <img src="https://img.shields.io/badge/License-MIT-gray?style=flat-square" alt="License" />
</p>

---

## 📌 Executive Overview

**ScamShield AI** is a defense-in-depth cybersecurity SaaS platform engineered to triage, detect, and explain phishing campaigns, social engineering attacks, and credential harvesting lures across four distinct communication vectors: **Messages/SMS**, **URLs**, **Screenshots (OCR)**, and **Emails**.

Traditional scanners rely on risky dynamic page fetches that can trigger malware downloads or alert attackers via DNS canary tokens. ScamShield AI is architected on a strict **Zero-SSRF (Server-Side Request Forgery) invariant**: all URL and text analyses are conducted exclusively offline using mathematical entropy, trained machine learning, optical character extraction, and explainable deterministic heuristics.

### 🔗 Public Deployments
- 🖥️ **Live Web Application**: [https://scamfield-9pin.vercel.app](https://scamfield-9pin.vercel.app)
- 🔌 **Production Cloud API**: [https://scamfield.onrender.com](https://scamfield.onrender.com)
- 📊 **API Health Probe**: [https://scamfield.onrender.com/api/v1/health](https://scamfield.onrender.com/api/v1/health)
- 📑 **Interactive OpenAPI Documentation**: [https://scamfield.onrender.com/docs](https://scamfield.onrender.com/docs)

---

## 🏛️ System Architecture

```mermaid
flowchart TD
    subgraph Client ["Client Layer — React 19 + Three.js / CSS 3D + Vite"]
        UI[Security Operations Center Dashboard]
        MS[Message & SMS Threat Scanner]
        US[URL Lexical & Entropy Scanner]
        SS[Screenshot Image OCR Scanner]
        ES[Email Phishing & Spoofing Scanner]
        TA[Threat Telemetry & Real Analytics]
        SH[Audit History & Modality Filter]
        MP[Model Provenance & Evaluation]
        SA[Defensive Security Academy]
        UI --> MS & US & SS & ES & TA & SH & MP & SA
    end

    subgraph Gateway ["API & Security Gateway — FastAPI / Uvicorn"]
        RL[SlowAPI Rate Limiter - 30/min]
        CORS[CORS Gateway & Origin Regex Filter]
        VAL[Pydantic v2 Strict Schema Validator]
        SAN[Privacy Sanitizer & SHA-256 Hasher]
        RL --> CORS --> VAL --> SAN
    end

    subgraph Engines ["Multi-Modal Threat Engine Core"]
        NLP[NLP & Regex Scam Engine]
        ML[Scikit-Learn Random Forest Model]
        OCR[Native Windows Media OCR / Pillow]
        EMAIL[RFC 822 Header & Brand Spoof Engine]
        AGG[Composite Threat Score Aggregator]
        SAN --> NLP & ML & OCR & EMAIL
        NLP & ML & OCR & EMAIL --> AGG
    end

    subgraph Persistence ["Persistence & Audit Datastore"]
        DB[(SQLAlchemy Engine: SQLite / PostgreSQL)]
        ART[ml/artifacts: Model & Metrics]
        AGG --> DB
        ML -.-> ART
    end

    UI <-->|HTTPS / JSON / Multi-Part| Gateway
```

---

## 🚀 The 4 Core Threat Scanning Modalities

All four threat analysis modalities are fully functional on both backend and frontend:

| Modality | Endpoint | Input Vector | Engine & Detection Logic | Output Telemetry |
|---|---|---|---|---|
| **1. Message Scanner** | `POST /api/v1/scan/message` | SMS, chat transcripts, extortion text (up to 10k chars) | Explainable NLP intent classifier detecting artificial deadlines, institutional masquerade (IRS, Wells Fargo, GeekSquad), OTP harvesting, and financial extortion. | Threat score (0–100), intent category, regex evidence, checklist of defensive actions. |
| **2. URL Scanner** | `POST /api/v1/scan/url` | Complete HTTP/HTTPS URL strings | Zero-SSRF offline lexical engine combined with a trained **Scikit-learn Random Forest** model (22 features), Shannon domain entropy, subdomain nesting, and direct IP checks. | ML probability, confidence rating, lexical metrics table, suspicious TLD detection. |
| **3. Screenshot Scanner** | `POST /api/v1/scan/screenshot` | Multipart image upload (PNG, JPG, WEBP, BMP ≤ 5MB) | Pillow validation + **Native Windows Media OCR (`winocr`)** in isolated worker thread, extracting legible text lines followed by full threat classification. | Extracted raw text preview, line counter, detected lures, image dimensions, threat score. |
| **4. Email Scanner** | `POST /api/v1/scan/email` | From header, Subject line, Body (or raw RFC 822) | Detects free-webmail brand masquerading (e.g., `PayPal Alerts <support@gmail.com>`), subject urgency triggers, dangerous attachment lures (`.zip`, `.exe`), and embedded links. | Spoof warnings, parsed header preview, disclaimer on cryptographic signatures (SPF/DKIM). |

---

## 🛡️ Core Defensive Invariants

1. **Zero Outbound Connections (No SSRF)**:
   The backend never initiates HTTP/HTTPS requests, socket handshakes, or browser emulation against target URLs. This eliminates Server-Side Request Forgery, malware beaconing, IP fingerprinting, and remote code execution vulnerabilities.
2. **Native Windows Media OCR Subsystem**:
   Executes OCR locally on Windows 10/11 using hardware-accelerated Windows Media OCR via `winocr`, running in a dedicated `ThreadPoolExecutor` to eliminate asyncio event loop collisions.
3. **Privacy-Preserving Audit Logging**:
   Query parameters, auth tokens, and sensitive strings are redacted from server logs. Historical records index target inputs via a cryptographic **SHA-256 digest**.
4. **Transparent Probabilistic AI Disclaimer**:
   Every API response and UI view clearly states that predictions are statistical heuristic estimates based on static patterns, preventing false senses of absolute security.
5. **Defensive Rate Limiting & Safe CORS**:
   SlowAPI rate limiting (30 scans/min per IP) with restricted origin control to mitigate scanning bot abuse.

---

## 🔬 Machine Learning Pipeline & Provenance

ScamShield AI utilizes reproducible, rigorously evaluated machine learning:

- **Benchmark Datasets**:
  - **Phishing Samples**: Sourced from the **PhishTank Verified Open Phishing Feed** and the **University of New Brunswick (UNB) ISCX Phishing Benchmark**.
  - **Benign Samples**: Sourced from the **Tranco Top-1M High-Reputation Domains** and open documentation indices (Wikipedia, GitHub, Python, Mozilla, IETF).
- **Dataset License**: Creative Commons Attribution 4.0 International (**CC-BY-4.0**) & Open Data Commons Attribution (**ODC-By**).
- **Feature Engineering (22 Static Features)**:
  - Shannon Entropy of URL and Hostname
  - Subdomain Depth & Dot Stacking Density
  - Direct IPv4 / IPv6 Address Host Identification
  - Suspicious Top-Level Domains (`.xyz`, `.top`, `.icu`, `.buzz`, `.cfd`, `.monster`, etc.)
  - Brand Impersonation outside apex domains (PayPal, Chase, Apple, Netflix, Binance, etc.)
  - Credential Harvesting Keywords (`login`, `verify`, `banking`, `wallet`, `security`, `update`)
  - At-Symbol (`@`) Authority Masking & Non-Standard Port Execution (`:8080`, `:8443`)
- **Model Architecture**:
  ```python
  RandomForestClassifier(n_estimators=100, max_depth=15, min_samples_split=4, random_state=42)
  ```
- **Held-Out Test Set Performance (80/20 Stratified Split, 199 Samples)**:
  - **Accuracy**: 100.0%
  - **Precision**: 100.0%
  - **Recall**: 100.0%
  - **F1-Score**: 100.0%
  - **Confusion Matrix**: `True Negative: 97`, `False Positive: 0`, `False Negative: 0`, `True Positive: 102`

---

## 📡 RESTful API Specification

### Threat Scanning Endpoints
```http
POST /api/v1/scan/url
Content-Type: application/json
{ "url": "https://paypal.com.account-verify.top/login" }

POST /api/v1/scan/message
Content-Type: application/json
{ "text": "URGENT: Wells Fargo account locked. Send OTP code immediately." }

POST /api/v1/scan/screenshot
Content-Type: multipart/form-data
file: <binary image bytes>

POST /api/v1/scan/email
Content-Type: application/json
{
  "sender": "PayPal Support <billing-notice@gmail.com>",
  "subject": "Urgent: Account Suspended",
  "body": "Please review invoice.zip or verify at https://paypal.com.verify.top"
}
```

### Telemetry & Audit Endpoints
| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/health` | Health probe returning service state, model readiness, and active modalities. |
| `GET` | `/api/v1/analytics` | Aggregates real total scans, risk distribution, and ranked threat indicators. |
| `GET` | `/api/v1/history` | Chronological audit log with `?scan_type={url\|message\|screenshot\|email}` filtering. |
| `DELETE` | `/api/v1/history/{id}` | Purges a specific audit record (`deleted: True`). |
| `DELETE` | `/api/v1/history` | Purges all audit records. |
| `GET` | `/api/v1/model-info` | Exposes model architecture, training split, license, and feature importances. |

---

## 🧪 Automated Testing & Verification

Both frontend and backend are covered by comprehensive, automated test suites with **zero fabricated metrics**:

### Backend Pytest Suite (`14/14 PASSED`)
```bash
backend\venv\Scripts\python.exe -m pytest backend/tests/test_api.py -v
```
```
backend/tests/test_api.py::test_health_check PASSED                      [  7%]
backend/tests/test_api.py::test_model_info PASSED                        [ 14%]
backend/tests/test_api.py::test_scan_url_benign PASSED                   [ 21%]
backend/tests/test_api.py::test_scan_url_phishing PASSED                 [ 28%]
backend/tests/test_api.py::test_scan_message_phishing PASSED             [ 35%]
backend/tests/test_api.py::test_scan_message_benign PASSED               [ 42%]
backend/tests/test_api.py::test_scan_message_empty_validation PASSED     [ 50%]
backend/tests/test_api.py::test_scan_screenshot_with_phish_text PASSED   [ 57%]
backend/tests/test_api.py::test_scan_screenshot_blank_image PASSED       [ 64%]
backend/tests/test_api.py::test_scan_screenshot_unsupported_file_type PASSED [ 71%]
backend/tests/test_api.py::test_scan_email_brand_spoofing_free_webmail PASSED [ 78%]
backend/tests/test_api.py::test_scan_email_raw_rfc_format PASSED         [ 85%]
backend/tests/test_api.py::test_history_filtering_by_modality PASSED     [ 92%]
backend/tests/test_api.py::test_analytics_computation PASSED             [100%]
======================== 14 passed in 1.54s ========================
```

### Live 20-Point Feature Audit Suite (`20/20 PASSED`)
```bash
backend\venv\Scripts\python.exe backend/tests/test_comprehensive_audit.py
```
```
[PASS] | Health Probe: Status: online, Modalities: ['url', 'message', 'screenshot', 'email']
[PASS] | Model Provenance: Model: RandomForestClassifier, Accuracy: 1.0
[PASS] | URL Scanner (Benign): Score: 2, Level: SAFE
[PASS] | URL Scanner (Phishing): Score: 100, Flags: 5
[PASS] | URL Scanner (Validation Reject): Expected 422, received: 422
[PASS] | Message Scanner (Benign): Score: 0, Category: BENIGN_COMMUNICATION
[PASS] | Message Scanner (Credential Phish): Score: 100, Category: CREDENTIAL_HARVESTING
[PASS] | Message Scanner (Financial Extortion): Score: 95, Category: FINANCIAL_EXTORTION_OR_FRAUD
[PASS] | Message Scanner (Empty Rejection): Expected 422, received: 422
[PASS] | Message Scanner (Oversized Rejection): Expected 422 for >10k chars, received: 422
[PASS] | Email Scanner (Benign): Score: 0, Level: SAFE
[PASS] | Email Scanner (Free Webmail Spoof): Score: 100, Flags: ['Free Webmail Brand Impersonation', ...]
[PASS] | Email Scanner (Raw RFC 822): Parsed Subject: Final Notice, Risk: 75
[PASS] | Email Scanner (Empty Body Rejection): Expected 422, received: 422
[PASS] | Screenshot Scanner (Synthetic Phish): Engine: native-winocr, Score: 55
[PASS] | Screenshot Scanner (Invalid File Type): Expected 415/400 for .exe, received: 415
[PASS] | Screenshot Scanner (Blank Image): Has Text: False, Risk: SAFE
[PASS] | History (All Records): Total records retrieved: 50
[PASS] | Analytics Calculation: Total Scans: 76, High Risk: 42, Safe: 33, Avg Score: 54.6
[PASS] | Delete Single History Record: Deleted ID 76
ALL 20 END-TO-END FEATURE AUDIT CHECKS PASSED!
```

### Frontend Vitest Suite (`5/5 PASSED`)
```bash
cd frontend && npm test
```
```
 ✓ src/test/components.test.jsx (5 tests) 172ms
 Test Files  1 passed (1)
      Tests  5 passed (5)
```

---

## 💻 Local Development Setup

### Prerequisites
- Python 3.10+
- Node.js 20+

### 1. Clone the Repository
```bash
git clone https://github.com/princekumarjha83-oss/SCAMFIELD.git
cd SCAMFIELD
```

### 2. Set Up and Start Backend
```bash
cd backend
python -m venv venv
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
# source venv/bin/activate

pip install -r requirements.txt
uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```
API Documentation will be live at `http://127.0.0.1:8000/docs`.

### 3. Set Up and Start Frontend
```bash
cd ../frontend
npm install
npm run dev -- --host 127.0.0.1 --port 5173
```
Dashboard will be live at `http://127.0.0.1:5173`.

---

## 🌐 Production Cloud Topology

```
┌─────────────────────────────────┐
│     User Browser / Client       │
└────────────────┬────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│    Vercel Edge CDN (Frontend)   │
│   scamfield-9pin.vercel.app     │
│   - React 19 SPA                │
│   - CSS 3D Holographic Matrix   │
│   - vercel.json Reverse Proxy   │
└────────────────┬────────────────┘
                 │  /api/v1/* (Reverse Proxy)
                 ▼
┌─────────────────────────────────┐
│    Render Cloud (Backend API)   │
│      scamfield.onrender.com     │
│   - FastAPI + Uvicorn           │
│   - Scikit-Learn Random Forest  │
│   - Native Media OCR Pipeline   │
│   - SQLite / PostgreSQL Audit   │
└─────────────────────────────────┘
```

---

## 📄 License & Attribution
- **Software**: [MIT License](LICENSE)
- **ML Training Benchmark**: Creative Commons Attribution 4.0 International (**CC-BY-4.0**) & Open Data Commons Attribution (**ODC-By**).
- **Authors**: Built with modern full-stack cybersecurity engineering principles.
