# 🛡️ ForensicAI — AI-Powered Email Threat Detection & Forensic Intelligence Platform

> **ForensicAI** is an enterprise defensive security application designed for SOC analysts, incident response teams, and security researchers to analyze suspicious `.eml` evidence, extract IOCs, trace network origin paths, evaluate authentication parameters (SPF/DKIM/DMARC), run Transformer ML risk classification, execute NetworkX campaign correlation, and export legal-grade PDF forensic reports.

---

## 🚀 Quickstart: Reproducible Docker Deployment

To launch the complete platform (Frontend, FastAPI Backend, PostgreSQL Database, Healthchecks, and Automatic Schema Migrations) in containerized mode:

```bash
# 1. Clone or navigate to repository root
cd "new s"

# 2. Copy environment configuration
cp .env.example .env

# 3. Build and launch all services with Docker Compose
docker compose up --build
```

Once started, access the application interfaces:
- **ForensicAI dashboard**: [http://localhost:3000](http://localhost:3000)
- **FastAPI REST API Docs (Swagger UI)**: [http://localhost:8001/docs](http://localhost:8001/docs)
- **API Health Check**: [http://localhost:8001/api/v1/health](http://localhost:8001/api/v1/health)

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

---

## 🔐 Authentication

The website provides two separate authentication options: ForensicAI email/password
login for local accounts, and **Continue with Google**. Google identity login
requests only `openid`, `email`, and `profile`; ForensicAI never receives or
stores a Google password. Password login does not provide Gmail mailbox access;
Gmail is connected separately from the dashboard.

Authorization remains enforced server-side so existing administrator functions
continue to work. Roles are not a login choice.

### Gmail authorization and synchronization

Gmail mailbox access is a separate, explicit action from the dashboard. Clicking
**Connect Gmail** requests only
`https://www.googleapis.com/auth/gmail.readonly`. The default **All Mail** query
is:

```text
in:anywhere -in:sent -in:spam -in:trash
```

This includes received archived mail, excludes Sent/Spam/Trash, follows all
`nextPageToken` pages, and stops at `GMAIL_SYNC_MAX_MESSAGES` (default `1000`).
Use the Inbox option (`in:inbox`) when only Inbox messages are required. Each
message is retrieved as raw MIME and passed through the existing ingestion and
SHA-256 deduplication path. Failed messages do not stop the remaining import.

Disconnecting Gmail revokes the access token when possible and removes local
credentials without deleting imported forensic evidence, cases, reports, or IOCs.

### Google Cloud Console checklist

Configure the OAuth web client with these redirect URIs:

```text
http://localhost:8001/api/v1/auth/google/callback
http://localhost:8001/api/integrations/gmail/callback
```

Use `http://localhost:3000` as an authorized JavaScript origin when required by
the client configuration. Enable the Gmail API, configure the OAuth consent
screen and test users, and complete Google's publishing/verification process
for the restricted Gmail read-only scope before production use. Provide the
required application name, privacy policy, and support information.

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

- [x] **Email Evidence Ingestion**: Parse `.eml` attachments, calculate SHA-256 hashes, extract MIME bodies and headers.
- [x] **Header Forensics & Trace Route**: Reconstruct Received hop chains, flag anomalies, identify earliest public sender IP.
- [x] **Authentication Engine**: Strict SPF, DKIM, and DMARC verification.
- [x] **IOC Extraction & IP Intel**: Automated URL/Domain/IP extraction, AbuseIPDB threat lookup, and GeoIP mapping.
- [x] **AI / NLP Defensive Classifier**: Transformer feature extraction combined with an explainable XGBoost risk model.
- [x] **NetworkX Campaign Correlation**: Multigraph infrastructure clustering (Senders, Reply-Tos, Domains, IPs, ASNs).
- [x] **Interactive Investigation Timeline**: 11-step interactive event sequence for evidence tracking.
- [x] **Authorization**: Server-side authorization with secure JWT authentication and immutable PostgreSQL audit trail.
- [x] **ReportLab PDF Export**: Legal-grade forensic case report PDF generation with attribution disclaimers.

---

## ⚠️ Disclaimer

*Technical indicators represent observed structural evidence and network correlations. They do not by themselves establish the identity of a human actor.*
