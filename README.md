# 🛡️ Security Suite — Penetration Testing Platform

> **Graduation Project** — Web-based cybersecurity penetration testing platform with AI-powered analysis (Google Gemini), Docker-isolated scanning tools, and professional report generation.

---

## ⚠️ AI MODIFICATION RULES (MUST READ BEFORE EDITING)

```
╔══════════════════════════════════════════════════════════════════════╗
║  🚫  DO NOT delete, rename, or modify any working file without     ║
║      explicit user instruction to do so.                           ║
║  🚫  DO NOT change API keys, credentials, or .env values unless    ║
║      the user provides new ones.                                   ║
║  🚫  DO NOT modify database schema (models.py) unless asked.       ║
║  🚫  DO NOT remove or rewrite existing API endpoints in app.py     ║
║      unless specifically instructed.                               ║
║  🚫  DO NOT change the Docker network or service names — other     ║
║      services depend on internal DNS resolution.                   ║
║  🚫  DO NOT delete scan data, reports, or the database file.       ║
║  🚫  DO NOT modify auth-helper.js without understanding that       ║
║      ALL pages depend on it — breakage here breaks everything.     ║
║  ✅  ONLY modify the specific component the user asks about.       ║
║  ✅  ALWAYS preserve existing comments and docstrings.             ║
║  ✅  TEST changes against the existing file structure below.       ║
╚══════════════════════════════════════════════════════════════════════╝
```

---

## 📁 Complete Project Structure

```
Graduation-project-main/
│
├── docker-compose.yml              # 🐳 Orchestrates ALL services (backend, db, dvwa, tools, nginx)
├── start.sh                        # Linux startup script
├── start_platform.sh               # Full platform startup with health checks
├── reorganize.bat                   # Windows file reorganization helper
├── test_nmap_integrity.sh           # Nmap tool integrity test
├── test_ping.py                     # Quick ping test script
├── test_scan.py                     # Quick scan test script
├── .gitignore                       # Git ignore rules
│
├── Backend/                         # ⚙️ Flask API Server
│   ├── app.py                       # 🔴 MAIN SERVER — 1800+ lines, ALL API endpoints
│   │                                #    Auth, Scan, Reports, Admin, Statistics
│   ├── Dockerfile                   # Docker image for the backend
│   ├── requirements.txt             # Python dependencies
│   ├── .env                         # 🔑 Environment variables (API keys, passwords)
│   ├── .env.template                # Template for .env setup
│   ├── .gitignore                   # Backend-specific ignores
│   │
│   ├── ai/                          # 🤖 AI Analysis Module (Google Gemini)
│   │   ├── __init__.py              # Module exports
│   │   ├── gemini_client.py         # Gemini API client wrapper
│   │   ├── report_generator.py      # AI report generation logic
│   │   ├── classifier.py            # Vulnerability classifier
│   │   ├── summarizer.py            # Scan results summarizer
│   │   ├── prompts.py               # AI prompt templates
│   │   ├── owasp_mapper.py          # OWASP Top 10 category mapper
│   │   ├── nvd_client.py            # NVD (CVE database) client
│   │   └── ollama_client.py         # Alternative: Ollama local LLM client
│   │
│   ├── database/                    # 🗄️ Database Layer (SQLAlchemy + SQLite)
│   │   ├── __init__.py              # Exports: init_db, get_db_session, User, Scan, etc.
│   │   ├── db.py                    # Database connection and session management
│   │   ├── models.py                # 🔴 ORM Models: User, Scan, ScanResult, Vulnerability
│   │   ├── cve_seed.py              # CVE seed data for initial database
│   │   └── pentest.db               # 🔴 SQLite database file (DO NOT DELETE)
│   │
│   ├── scanners/                    # 🔍 Scanner Modules (run inside Docker containers)
│   │   ├── nmap_scanner.py          # Nmap scanner wrapper (Python)
│   │   ├── nmap_scan.sh             # Nmap scanner wrapper (Shell)
│   │   ├── sql_scanner.py           # SQL injection scanner
│   │   ├── sqlmap_scanner.py        # SQLMap wrapper
│   │   ├── nikto_scanner.py         # Nikto web scanner wrapper
│   │   ├── wfuzz_scanner.py         # Wfuzz fuzzer wrapper
│   │   ├── harvester_scanner.py     # theHarvester OSINT wrapper
│   │   ├── test_scanners.py         # Scanner unit tests
│   │   └── README.md                # Scanner module documentation
│   │
│   ├── utils/                       # 🔧 Utility Modules
│   │   ├── __init__.py              # Module exports
│   │   ├── validators.py            # Target URL/domain validation & DNS resolution
│   │   ├── pdf_generator.py         # 🔴 PDF report generator (ReportLab)
│   │   └── owasp_mapper.py          # OWASP category mapping utility
│   │
│   ├── fonts/                       # 🔤 Fonts for PDF Generation
│   │   └── Amiri-Regular.ttf        # Arabic font for bilingual PDF reports
│   │
│   └── data/                        # 📊 Scan Data Storage
│       └── scans/                   # Scan results (JSON files per scan)
│           └── reports/             # Generated reports (PDF, JSON, CSV)
│
├── Frontend/                        # 🖥️ Web Interface (HTML + Tailwind CSS + Vanilla JS)
│   ├── signin.html                  # 🔑 Login page (entry point)
│   ├── Register.html                # 📝 User registration page
│   ├── Dashbord.html                # 📊 Admin dashboard (stats, user management)
│   ├── UserDashboard.html           # 📊 User dashboard (personal stats, scan history)
│   ├── Ping.html                    # 📡 Connectivity test page (test before scanning)
│   ├── Nmap.html                    # 🔍 Nmap port scanner page
│   ├── SQL.html                     # 💉 SQLMap SQL injection scanner page
│   ├── Wfuzz.html                   # 📂 Wfuzz web fuzzer page
│   ├── Harvester.html               # 🌐 theHarvester OSINT page
│   ├── Nikto.html                   # 🐛 Nikto web vulnerability scanner page
│   ├── Reports.html                 # 📄 Reports listing & download page
│   ├── Results.html                 # 📋 Scan results viewer
│   │
│   └── js/                          # JavaScript
│       └── auth-helper.js           # 🔴 CRITICAL — Auth guard, API_URL, logout, getUser
│                                    #    ALL pages depend on this file
│
├── Dockerfiles/                     # 🐳 Docker Images for Scanning Tools
│   ├── nmap/Dockerfile              # Nmap container (Alpine + nmap + nse scripts)
│   ├── sqlmap/Dockerfile            # SQLMap container
│   ├── nikto/Dockerfile             # Nikto container
│   ├── wfuzz/Dockerfile             # Wfuzz container
│   └── harvester/Dockerfile         # theHarvester container
│
├── components/                      # 🧩 Shared HTML Components
│   └── tool_header.html             # Reusable tool page header
│
├── js/                              # 📜 Root-level JavaScript (legacy)
│   ├── auth-helper.js               # Full auth helper (same as Frontend/js/)
│   └── vulnerability-classifier.js  # Client-side vulnerability classifier
│
└── scripts/                         # 📜 Utility Scripts
    ├── README.md                    # Scripts documentation
    ├── nmap_scan.sh                 # Standalone nmap scan script
    ├── nmap_scanner.py              # Standalone nmap scanner
    └── test_scan.json               # Sample scan output for testing
```

---

## 🏗️ Architecture Overview

```
┌────────────────────────────────────────────────────────────────┐
│                        BROWSER (User)                          │
│  signin.html → Dashboard → Nmap/SQL/Wfuzz/Nikto/Harvester    │
│                   ↕ fetch() API calls                          │
├────────────────────────────────────────────────────────────────┤
│                    Flask Backend (port 5000)                    │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌─────────────────┐  │
│  │ Auth API │ │ Scan API │ │Report API│ │  Admin API      │  │
│  └──────────┘ └──────────┘ └──────────┘ └─────────────────┘  │
│       ↕              ↕            ↕                            │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐                      │
│  │ SQLite/  │ │ Scanner  │ │Gemini AI │                      │
│  │PostgreSQL│ │ Workers  │ │ Analysis │                      │
│  └──────────┘ └──────────┘ └──────────┘                      │
├────────────────────────────────────────────────────────────────┤
│               Docker Network (pentest_net)                     │
│  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐     │
│  │ Nmap │ │SQLMap│ │Nikto │ │Wfuzz │ │Harv. │ │ DVWA │     │
│  │      │ │      │ │      │ │      │ │      │ │:8080 │     │
│  └──────┘ └──────┘ └──────┘ └──────┘ └──────┘ └──────┘     │
└────────────────────────────────────────────────────────────────┘
```

---

## 🔑 Key API Endpoints (Backend/app.py)

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| POST | `/api/auth/login` | User login | No |
| POST | `/api/auth/register` | User registration | No |
| POST | `/api/auth/logout` | Logout | Yes |
| GET | `/api/auth/me` | Get current user | Yes |
| POST | `/api/ping` | Ping/connectivity check | Yes |
| POST | `/api/scan` | Start Nmap scan | Yes |
| GET | `/api/scan/<id>` | Get scan results | Yes |
| GET | `/api/scan-history` | List user's scans | Yes |
| GET | `/api/statistics` | Dashboard statistics | Yes |
| POST | `/api/sql-scan` | Start SQLMap scan | Yes |
| POST | `/api/scan/nikto` | Start Nikto scan | Yes |
| POST | `/api/wfuzz` | Start Wfuzz scan | Yes |
| POST | `/api/scan/harvester` | Start Harvester scan | Yes |
| POST | `/api/reports/generate` | Generate PDF/JSON/CSV report | Yes |
| GET | `/api/reports/list` | List all reports | Yes |
| GET | `/api/admin/users` | List all users | Admin |
| GET | `/api/admin/stats` | Admin statistics | Admin |
| POST | `/api/admin/users/<id>/toggle` | Enable/disable user | Admin |
| DELETE | `/api/admin/users/<id>` | Delete user | Admin |

---

## 🚀 Quick Start

### Option 1: Docker (Recommended — Full Stack)
```powershell
cd "C:\Users\katana\Desktop\Security Suite\Graduation-project-main\Graduation-project-main"
docker-compose up -d --build
```
- Frontend + Backend: http://localhost:5000
- DVWA: http://localhost:8080
- PgAdmin: http://localhost:5050

### Option 2: Local Development (Backend only)
```powershell
cd Backend
pip install -r requirements.txt
python app.py
```
- Backend serves frontend at: http://localhost:5000

### Default Admin Account
- **Email:** admin@security.com
- **Password:** Set in `.env` → `ADMIN_PASSWORD` (default: `admin123`)

---

## 🧪 Testing Targets

| Tool | Legal Test Target | Notes |
|------|-------------------|-------|
| Nmap | `scanme.nmap.org` | Official Nmap test target |
| Nmap | `dvwa` (Docker) | Internal DVWA container |
| SQLMap | `http://dvwa/vulnerabilities/sqli/?id=1&Submit=Submit` | DVWA SQL Injection |
| Nikto | `http://dvwa` | DVWA web server |
| Wfuzz | `http://dvwa/FUZZ` | DVWA path discovery |
| Harvester | `google.com` | Any public domain |
| Ping | `dvwa` or `scanme.nmap.org` | Connectivity check |

---

## 🔐 Environment Variables (Backend/.env)

| Variable | Description | Default |
|----------|-------------|---------|
| `GEMINI_API_KEY` | Google Gemini API key | Required |
| `SECRET_KEY` | Flask session signing key | Auto-generated |
| `ADMIN_PASSWORD` | Admin account password | Auto-generated |
| `CORS_ORIGINS` | Allowed CORS origins | `*` |
| `HTTPS_ENABLED` | Enable HTTPS cookies | `false` |
| `DATABASE_URL` | PostgreSQL connection string | SQLite fallback |
| `SCANS_DIR` | Persistent scan storage path | `data/scans` |

---

## 📝 Important Notes

1. **DVWA** is included in `docker-compose.yml` as a **legal testing target**
2. **Never scan real websites** without explicit written authorization
3. The frontend is served by Flask as static files from the `Frontend/` directory
4. All scan tools run in **isolated Docker containers** on the `pentest_net` network
5. Reports are stored in `Backend/data/scans/reports/`
6. The database (`pentest.db`) contains all users, scans, and vulnerabilities
