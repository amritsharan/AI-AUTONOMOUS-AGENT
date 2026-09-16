# QuantumShield AI — Autonomous Classical & Post-Quantum Security Platform

> **AI-Powered Dual-Engine Autonomous Security Scanner & Quantum Cryptographic Risk Assessment Platform**

---

## Overview

**QuantumShield AI** is an advanced full-stack security testing platform that unites **autonomous classical web application vulnerability analysis** with **quantum cryptographic threat modeling and local quantum circuit simulation**.

Targeting **explicitly authorized lab and staging environments**, QuantumShield AI autonomously explores attack surfaces, detects critical vulnerabilities (IDOR, SQLi, XSS, broken auth, sensitive exposure), maps cryptographic inventories, and benchmarks quantum vulnerability timelines against Shor's and Grover's algorithms using local **Qiskit** quantum circuit simulations.

---

## Key Features

### 1. Dual Security Engine
- **Classical Security Engine**:
  - Autonomous crawling and attack surface discovery.
  - Authentication testing (weak credentials, brute-force indicators, username enumeration).
  - Authorization & IDOR testing (cross-tenant object access verification).
  - Injection testing (SQLi, reflected XSS, template injection with benign payloads).
  - Security configuration & headers audit (CORS, cookies, debug exposure).
- **Quantum Cryptographic & Hardware Lab Engine**:
  - **IBM Quantum Runtime & Real QPU Execution**: Live IBM Quantum Cloud authentication and QPU execution (`ibm_brisbane`, `ibm_kyoto`, `ibm_sherbrooke` 127-qubit processors) via Qiskit Runtime `SamplerV2`.
  - **3-Tier Comparative Benchmark**: Side-by-side execution across **Ideal Simulator**, **Thermal/Decoherence Noisy Simulator**, and **Real Physical QPU**.
  - **Hardware Telemetry HUD**: Live reporting on T1 relaxation, T2 dephasing, 2-qubit ECR gate error rates, and readout accuracy.
  - **Shor's Algorithm & Factorization**: Factoring $N=15, 21, 35$ with period extraction ($r=4$) linked directly to **RSA-2048 HNDL risk** and **NIST FIPS 203 ML-KEM** migration.
  - **Simon's Algorithm**: Exponential quantum period finding ($O(2^{n/2}) \rightarrow O(n)$) targeting Even-Mansour ciphers and GCM tag generation.
  - **Quantum Phase Estimation (QPE) Primitive**: Interactive eigenvalue estimation for unitary $U|\psi\rangle = e^{2\pi i \theta}|\psi\rangle$ with Inverse QFT.
  - **Quantum Key Distribution (QKD) Station**: BB84 single-photon polarization with Eve Intercept-Resend / QBER threshold testing, plus E91 Bell State entanglement testing (CHSH $S > 2.0$).
  - **Grover's Algorithm**: Search space key exhaustion demonstrating quadratic speedup on symmetric key sizes (AES-128 vs AES-256).
  - **NIST Post-Quantum Cryptography (PQC) Readiness**: Automated CBOM (Cryptographic Bill of Materials) and migration roadmaps for ML-KEM (FIPS 203), ML-DSA (FIPS 204), and SLH-DSA (FIPS 205).

### 2. Strictly Deterministic Policy Engine
- **LLM-independent boundary control**: Every security test and outbound payload must pass algorithmic allow-list checks.
- Hard blocks on production domains, unlisted IPs, destructive exploits, and DDoS vectors.
- Fine-grained per-target scope enforcement (rate limits, allowed ports, test account boundaries).

### 3. AI Security Orchestrator
- Intelligent multi-phase scanning pipeline:
  `RECON` $\rightarrow$ `CRYPTO_AUDIT` $\rightarrow$ `VULN_TESTING` $\rightarrow$ `VERIFICATION` $\rightarrow$ `RISK_SCORING` $\rightarrow$ `REMEDIATION_GEN`
- Built-in deterministic fallback when no LLM API key is supplied (`LLM_PROVIDER=none`).
- Support for OpenAI, Anthropic, and Google Gemini models.

### 4. Bundled Security Lab Target
- Includes an intentionally vulnerable containerized web application (`security-lab`, port 8080) seeded with 14 benchmark vulnerabilities to safely demonstrate scanning, proof-of-concept verification, and false-positive filtering.

### 5. Real-Time Telemetry & Operations Dashboard
- Live WebSocket streaming (`/api/scans/{id}/stream`) with terminal logs, state transitions, and step-by-step reasoning.
- Interactive Quantum Center with live Shor & Grover circuit runners and quantum circuit visualization.
- Complete PDF/HTML and JSON compliance reports.

---

## Platform Architecture

```
                       ┌──────────────────────────────────────────────┐
                       │  QuantumShield Frontend (React + Vite + TS)  │
                       │   - Security Dashboard & Quantum Center      │
                       │   - Live WebSocket Scan Stream Telemetry    │
                       └──────────────────────┬───────────────────────┘
                                              │ HTTP / WebSocket
                                              ▼
                       ┌──────────────────────────────────────────────┐
                       │     FastAPI Gateway (Port 8000)              │
                       │   - REST API & WebSocket Connection Mgr      │
                       │   - Policy Engine (Deterministic Bounds)    │
                       └──────────────┬───────────────────────────────┘
                                      │
               ┌──────────────────────┴──────────────────────┐
               ▼                                             ▼
┌──────────────────────────────┐              ┌──────────────────────────────┐
│  Classical Security Engine   │              │   Quantum Security Engine    │
│  - Reconnaissance & Crawl    │              │   - TLS & Cryptographic DB   │
│  - Auth & IDOR Analysis      │              │   - Shor / Grover Simulation │
│  - Injection Testing (SQLi)  │              │   - NIST PQC Readiness Score │
└──────────────┬───────────────┘              └──────────────┬───────────────┘
               └──────────────────────┬──────────────────────┘
                                      │
                                      ▼
                       ┌──────────────────────────────┐
                       │    Evidence & Risk Engine    │
                       │  - PoC Verification & Scoring│
                       │  - Remediation Generator     │
                       └──────────────┬───────────────┘
                                      │
                ┌─────────────────────┴─────────────────────┐
                ▼                                           ▼
┌──────────────────────────────┐             ┌──────────────────────────────┐
│ PostgreSQL 16 (Relational DB)│             │ Redis 7 (Pub/Sub & Message)  │
└──────────────────────────────┘             └──────────────────────────────┘
```

---

## Quickstart with Docker Compose

### Prerequisites
- Docker Engine $\ge 24.0$
- Docker Compose v2

### 1. Clone & Configure Environment
```bash
git clone https://github.com/amritsharan/Q-NEXUS.git
cd "AI AGENT AUTONOMOUS/quantumshield-ai"

# Copy example environment configuration
cp .env.example .env
```

### 2. Build & Launch Containers
```bash
docker compose up --build -d
```

Services started:
| Service | Internal Port | Host Port | Description |
| :--- | :--- | :--- | :--- |
| **Frontend** | 80 | `3000` | React Web Dashboard |
| **Backend** | 8000 | `8000` | FastAPI REST & WebSocket Server |
| **Security Lab**| 8080 | `8080` | Intentionally Vulnerable Target App |
| **PostgreSQL** | 5432 | `5432` | Relational Storage |
| **Redis** | 6379 | `6379` | Event Broker & Task Queue |

### 3. Open the Application
- **Frontend Dashboard**: [http://localhost:3000](http://localhost:3000)
- **FastAPI Interactive Docs (Swagger)**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **Vulnerable Security Lab**: [http://localhost:8080](http://localhost:8080)

---

## Local Development (Without Docker)

### Backend Setup
```bash
cd backend

# Install Python dependencies
pip install -r requirements.txt

# Run backend test suite
python -m pytest tests -v

# Start FastAPI dev server
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Security Lab Setup
```bash
cd security-lab

# Install dependencies
pip install -r requirements.txt

# Seed the vulnerable database
python seed.py

# Start the vulnerable Flask application
python -m gunicorn --bind 0.0.0.0:8080 app.main:app
```

### Frontend Setup
```bash
cd frontend

# Install Node dependencies
npm install

# Run production build validation
npm run build

# Start Vite development server
npm run dev
```

---

## Verification & Testing

The platform includes full automated test suites across API endpoints, deterministic policy engine boundaries, quantum circuit execution, and scoring engines.

### Running Backend Unit & Integration Tests
```bash
cd backend
python -m pytest tests -v
```
**Test Coverage Includes:**
- `tests/test_policy.py`: Prohibited action blocking, unauthorized external host blocking, production environment gating, destructive test verification.
- `tests/test_quantum.py`: Shor RSA/ECC assessments, Grover AES assessments, live Qiskit circuit execution ($N=15$ Shor, $N=4$ Grover), PQC readiness scoring.
- `tests/test_engines.py`: Evidence building, multi-factor risk calculation, quantum security score aggregation, automated remediation templating.
- `tests/test_api.py`: FastAPI endpoints, health check, algorithm registry, PQC standards catalogue, live simulation endpoints.

### Running Frontend Typecheck & Build
```bash
cd frontend
npm run build
```

---

## Security Policy & Authorized Use

> [!WARNING]
> QuantumShield AI is built exclusively for authorized security audits, penetration testing of explicitly owned infrastructure, and educational research. The integrated Policy Engine actively blocks non-allowlisted network addresses, external public IP ranges, and unauthorized actions.
