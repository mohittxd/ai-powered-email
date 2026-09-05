# 🛡️ ForensicAI — AI-Powered Email Threat Detection & Forensic Intelligence Platform

> **ForensicAI** is an enterprise defensive security application designed for SOC analysts, incident response teams, and security researchers to analyze suspicious email evidence, extract IOCs, trace network origin paths, evaluate authentication parameters (SPF/DKIM/DMARC), run Transformer ML risk classification, execute NetworkX campaign correlation, and export legal-grade PDF forensic reports.

---

## 🚀 Quickstart: Reproducible Docker Deployment

To launch the complete platform (Frontend, FastAPI Backend, PostgreSQL Database, Healthchecks, and Automatic Schema Migrations) in containerized mode:

```bash
# 1. Clone or navigate to repository root
cd "<your current folder name>"

# 2. Copy environment configuration
cp .env.example .env

# 3. Build and launch all services with Docker Compose
docker compose up --build
```

Once started, access the application interfaces:
- **Analyst Web Dashboard**: [http://localhost:3000](http://localhost:3000)
- **FastAPI REST API Docs (Swagger UI)**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **API Health Check**: [http://localhost:8000/api/v1/health](http://localhost:8000/api/v1/health)

---

## 📥 Supported Email Evidence Formats

ForensicAI ingests raw email evidence and normalizes it before analysis, rather than being limited to a single source format.

| Format | Extension | Status |
| :--- | :--- | :--- |
| Internet Message Format | `.eml` | ✅ Parsed and analyzed |
| Outlook Message Format | `.msg` | ✅ Parsed and analyzed (via `extract-msg`) |

Uploaded evidence is parsed into a normalized internal email representation (headers, MIME body parts, attachments) so the rest of the forensic pipeline — authentication checks, IOC extraction, ML classification, and reporting — runs identically regardless of the original source format.

> **Note:** Only the formats listed above are parsed by the current backend. If your deployment's upload UI presents additional file types, treat any format not listed here as **not yet supported for forensic analysis** until the backend parsing layer is extended.

---

## 🏛️ Platform Architecture

```text
                  ┌─────────────────────────────────┐
                  │   ForensicAI Web Dashboard      │
                  │       (React + Vite UI)         │
                  └────────────────┬────────────────┘
                                   │ HTTP / API (Port 3000 -> 8000)
                                   ▼
                  ┌─────────────────────────────────┐
                  │       FastAPI REST Engine       │
                  │   (Authentication, RBAC, ML)    │
                  └────────┬───────────────┬────────┘
                           │               │
         SQLAlchemy / asyncpg│               │ NetworkX / ML Classifier
                           ▼               ▼
      ┌──────────────────────────┐   ┌──────────────────────────┐
      │   PostgreSQL 16 Engine   │   │ HuggingFace / XGBoost    │
      │  (Cases, Audits, IOCs)   │   │  Defensive NLP Model     │
      └──────────────────────────┘   └──────────────────────────┘
```

### Evidence Ingestion Workflow

```text
User uploads email evidence (.eml / .msg)
       ↓
File type detection
       ↓
Format-specific email parser (email.parser / extract-msg)
       ↓
Normalized email representation (headers, MIME body, attachments)
       ↓
Forensic analysis pipeline
       ↓
Authentication / header / IP / URL / attachment analysis
       ↓
Fraud / risk assessment (Transformer + XGBoost classifier)
       ↓
Dashboard and forensic report
```

---

## 🔐 Default Access Credentials (RBAC)

The system comes pre-configured with 3 role-based accounts for SOC demonstration:

| Role | Username | Email | Password | Permissions |
| :--- | :--- | :--- | :--- | :--- |
| **ADMIN** | `admin` | `admin@forensic.local` | `Admin123!` | All permissions, User Management, Immutable Audit Logs |
| **INVESTIGATOR** | `investigator` | `investigator@forensic.local` | `Investigator123!` | Case view, Forensic PDF Report export, IOC Database query |
| **ANALYST** | `analyst` | `analyst@forensic.local` | `Analyst123!` | Upload email evidence (`.eml`, `.msg`), Run threat analysis, View assigned cases |

---

## 💻 Local Development Setup (Without Docker)

### 1. Backend Setup
```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Run database migrations / seed default accounts
python main.py

# Or start with Uvicorn
uvicorn main:app --reload --port 8000
```

### 2. Frontend Setup
```bash
cd frontend
npm install
npm run dev
```
Access local development dashboard at [http://localhost:5173](http://localhost:5173).

---

## 🧪 Testing & Model Evaluation

### Run Complete Backend Unit Test Suite (238+ Tests)
```bash
cd backend
./.venv/bin/pytest -v
```

### Run Defensive ML Model Benchmark Evaluation
```bash
cd backend
python scripts/evaluate_ml.py
```

---

## 📋 Features Checklist & Key Capabilities

- [x] **Multi-Format Email Evidence Ingestion**: Accepts `.eml` and `.msg` email evidence, detects the source format, calculates SHA-256 hashes, and extracts MIME bodies and headers into a normalized representation.
- [x] **Header Forensics & Trace Route**: Reconstruct Received hop chains, flag anomalies, identify earliest public sender IP.
- [x] **Authentication Engine**: Strict SPF, DKIM, and DMARC verification.
- [x] **IOC Extraction & IP Intel**: Automated URL/Domain/IP extraction, AbuseIPDB threat lookup, and GeoIP mapping.
- [x] **AI / NLP Defensive Classifier**: Transformer feature extraction combined with an explainable XGBoost risk model.
- [x] **NetworkX Campaign Correlation**: Multigraph infrastructure clustering (Senders, Reply-Tos, Domains, IPs, ASNs).
- [x] **Interactive Investigation Timeline**: 11-step interactive event sequence for evidence tracking.
- [x] **Role-Based Access Control (RBAC)**: Secure JWT authentication with immutable PostgreSQL audit trail.
- [x] **ReportLab PDF Export**: Legal-grade forensic case report PDF generation with attribution disclaimers.

---

## ⚠️ Limitations

- Forensic parsing currently covers `.eml` and `.msg` email evidence only. Other document or archive types (e.g. PDF, DOCX, images, ZIP, CSV) are **not** parsed as email evidence, even if such files are accepted elsewhere in the platform.
- Technical indicators represent observed structural evidence and network correlations. They do not by themselves establish the identity of a human actor.

---

## ⚠️ Disclaimer

*Technical indicators represent observed structural evidence and network correlations. They do not by themselves establish the identity of a human actor.*
