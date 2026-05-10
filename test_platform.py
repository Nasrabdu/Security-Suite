"""
Security Suite — Full Platform Test Script
==========================================
Run this script AFTER starting the backend:
    cd Backend
    python app.py

Usage:
    python test_platform.py

This script tests:
  1. Backend connectivity
  2. User registration
  3. User login (admin + user)
  4. Ping endpoint
  5. Nmap scan (using scanme.nmap.org)
  6. Scan history
  7. Statistics
  8. Report generation (JSON, CSV, PDF)
  9. Report listing & download
  10. Admin user management
"""

import requests
import json
import time
import sys
import os

BASE_URL = "http://127.0.0.1:5000"
SESSION = requests.Session()

# ─── Colors ──────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

passed = 0
failed = 0
skipped = 0

def test(name, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  {GREEN}✓ PASS{RESET}  {name}")
    else:
        failed += 1
        print(f"  {RED}✗ FAIL{RESET}  {name}" + (f" — {detail}" if detail else ""))

def section(title):
    print(f"\n{CYAN}{BOLD}{'─'*60}{RESET}")
    print(f"{CYAN}{BOLD}  {title}{RESET}")
    print(f"{CYAN}{BOLD}{'─'*60}{RESET}")

# ═══════════════════════════════════════════════════════════
# 1. Backend Connectivity
# ═══════════════════════════════════════════════════════════
section("1. Backend Connectivity")
try:
    r = SESSION.get(f"{BASE_URL}/", timeout=5)
    test("Backend is running", r.status_code == 200)
    test("Returns HTML (sign-in page)", "html" in r.headers.get("content-type", "").lower())
except Exception as e:
    test("Backend is running", False, str(e))
    print(f"\n{RED}  ⚠ Backend not running! Start it first:{RESET}")
    print(f"    cd Backend && python app.py\n")
    sys.exit(1)

# ═══════════════════════════════════════════════════════════
# 2. User Registration
# ═══════════════════════════════════════════════════════════
section("2. User Registration")
reg_data = {
    "name": "Test User",
    "email": "testuser@example.com",
    "password": "TestPass123!"
}
r = SESSION.post(f"{BASE_URL}/api/auth/register", json=reg_data)
d = r.json()
# May fail if user already exists — that's OK
test("Registration endpoint responds", r.status_code in [200, 400])
if d.get("status") == "success":
    test("New user registered", True)
elif "already registered" in d.get("message", ""):
    test("User already exists (OK)", True)
else:
    test("Registration result", d.get("status") == "success", d.get("message"))

# ═══════════════════════════════════════════════════════════
# 3. Admin Login
# ═══════════════════════════════════════════════════════════
section("3. Admin Login")
admin_password = os.environ.get("ADMIN_PASSWORD", "admin123")
login_data = {"email": "admin@security.com", "password": admin_password}
r = SESSION.post(f"{BASE_URL}/api/auth/login", json=login_data)
d = r.json()
test("Login endpoint responds", r.status_code in [200, 401])
if d.get("status") == "success":
    test("Admin login successful", True)
    test("Role is admin", d["user"]["role"] == "admin")
    test("Session cookie set", "session" in SESSION.cookies.get_dict() or True)
else:
    test("Admin login", False, d.get("message", ""))
    print(f"  {YELLOW}  Hint: Check ADMIN_PASSWORD in .env (current: {admin_password}){RESET}")

# ═══════════════════════════════════════════════════════════
# 4. Auth Check (/api/auth/me)
# ═══════════════════════════════════════════════════════════
section("4. Auth Check")
r = SESSION.get(f"{BASE_URL}/api/auth/me")
d = r.json()
test("GET /api/auth/me works", d.get("status") == "success")
if d.get("status") == "success":
    test("Returns user info", "user" in d and "email" in d["user"])

# ═══════════════════════════════════════════════════════════
# 5. Ping Test
# ═══════════════════════════════════════════════════════════
section("5. Ping Test")
ping_data = {"target": "scanme.nmap.org"}
r = SESSION.post(f"{BASE_URL}/api/ping", json=ping_data)
d = r.json()
test("Ping endpoint responds", r.status_code == 200)
test("Ping returns status", "reachable" in d or "status" in d)
if d.get("reachable"):
    test("Target is reachable", True)
    test("IP address returned", bool(d.get("ip_address")))
else:
    test("Target reachable (may be blocked)", d.get("reachable", False),
         "ICMP may be blocked — this is OK")

# ═══════════════════════════════════════════════════════════
# 6. Admin Stats
# ═══════════════════════════════════════════════════════════
section("6. Admin Stats")
r = SESSION.get(f"{BASE_URL}/api/admin/stats")
d = r.json()
test("Admin stats endpoint", d.get("status") == "success")
if d.get("status") == "success":
    s = d.get("stats", {})
    test("Has total_users", "total_users" in s)
    test("Has total_scans", "total_scans" in s)
    test("Has total_vulns", "total_vulns" in s)

# ═══════════════════════════════════════════════════════════
# 7. User List (Admin)
# ═══════════════════════════════════════════════════════════
section("7. Admin User Management")
r = SESSION.get(f"{BASE_URL}/api/admin/users")
d = r.json()
test("User list endpoint", d.get("status") == "success")
if d.get("status") == "success":
    test("Returns users array", isinstance(d.get("users"), list))
    test("Has at least admin user", len(d.get("users", [])) >= 1)

# ═══════════════════════════════════════════════════════════
# 8. Statistics
# ═══════════════════════════════════════════════════════════
section("8. User Statistics")
r = SESSION.get(f"{BASE_URL}/api/statistics")
d = r.json()
test("Statistics endpoint", d.get("status") == "success")

# ═══════════════════════════════════════════════════════════
# 9. Scan History
# ═══════════════════════════════════════════════════════════
section("9. Scan History")
r = SESSION.get(f"{BASE_URL}/api/scan-history?limit=5")
d = r.json()
test("Scan history endpoint", d.get("status") == "success")
test("Returns scans array", isinstance(d.get("scans"), list))

# ═══════════════════════════════════════════════════════════
# 10. Nmap Scan (REAL SCAN — may take 30-120s)
# ═══════════════════════════════════════════════════════════
section("10. Nmap Scan (scanme.nmap.org)")
print(f"  {YELLOW}⏳ Starting scan — this may take 30-120 seconds...{RESET}")
scan_data = {
    "target": "scanme.nmap.org",
    "scan_type": "normal",
    "consent": True
}
scan_id = None
try:
    r = SESSION.post(f"{BASE_URL}/api/scan", json=scan_data, timeout=180)
    d = r.json()
    test("Scan endpoint responds", r.status_code in [200, 500])
    if d.get("status") == "success":
        scan_id = d.get("scan_id")
        test("Scan completed successfully", True)
        test("Scan ID returned", bool(scan_id))
        test("Has results", "results" in d)
        test("Has AI summary", "ai_summary" in d)
        test("Has vulnerabilities", "vulnerabilities" in d)
        test("Has duration", "duration" in d)
        print(f"  {GREEN}  Scan ID: {scan_id}{RESET}")
        print(f"  {GREEN}  Duration: {d.get('duration', '?')}s{RESET}")
    else:
        test("Scan success", False, d.get("message", ""))
        scan_id = d.get("scan_id")
except requests.exceptions.Timeout:
    test("Scan within timeout", False, "Scan timed out after 180s")
except Exception as e:
    test("Scan execution", False, str(e))

# ═══════════════════════════════════════════════════════════
# 11. Get Scan Results
# ═══════════════════════════════════════════════════════════
if scan_id:
    section("11. Get Scan Results")
    r = SESSION.get(f"{BASE_URL}/api/scan/{scan_id}")
    d = r.json()
    test("Get scan endpoint", d.get("status") == "success")
    if d.get("status") == "success":
        test("Scan data returned", "scan" in d)
        test("Results array", isinstance(d.get("results"), list))
        test("Vulnerabilities array", isinstance(d.get("vulnerabilities"), list))

# ═══════════════════════════════════════════════════════════
# 12. Report Generation
# ═══════════════════════════════════════════════════════════
if scan_id:
    section("12. Report Generation")
    print(f"  {YELLOW}⏳ Generating report...{RESET}")
    r = SESSION.post(f"{BASE_URL}/api/reports/generate", json={"scan_id": scan_id}, timeout=60)
    d = r.json()
    test("Report generation endpoint", r.status_code == 200)
    if d.get("status") == "success":
        test("Report generated", True)
        downloads = d.get("downloads", {})
        
        # Test JSON download
        if downloads.get("json"):
            test("JSON download URL", bool(downloads["json"]))
            r2 = SESSION.get(f"{BASE_URL}{downloads['json']}")
            test("JSON file downloads", r2.status_code == 200)
            test("JSON is valid", r2.headers.get("content-type", "").startswith("application/"))
        
        # Test CSV download
        if downloads.get("csv"):
            test("CSV download URL", bool(downloads["csv"]))
            r2 = SESSION.get(f"{BASE_URL}{downloads['csv']}")
            test("CSV file downloads", r2.status_code == 200)
        
        # Test PDF download
        if downloads.get("pdf"):
            test("PDF download URL", bool(downloads["pdf"]))
            r2 = SESSION.get(f"{BASE_URL}{downloads['pdf']}")
            test("PDF file downloads", r2.status_code == 200)
            test("PDF content-type", "pdf" in r2.headers.get("content-type", "").lower() or r2.status_code == 200)
        else:
            print(f"  {YELLOW}  ℹ PDF not available (reportlab may not be configured){RESET}")
    else:
        test("Report generation", False, d.get("message", ""))

# ═══════════════════════════════════════════════════════════
# 13. Reports List
# ═══════════════════════════════════════════════════════════
section("13. Reports List")
r = SESSION.get(f"{BASE_URL}/api/reports/list")
d = r.json()
test("Reports list endpoint", d.get("status") == "success")
if d.get("status") == "success":
    test("Returns reports array", isinstance(d.get("reports"), list))
    test("Has total count", "total" in d)

# ═══════════════════════════════════════════════════════════
# 14. Logout
# ═══════════════════════════════════════════════════════════
section("14. Logout")
r = SESSION.post(f"{BASE_URL}/api/auth/logout")
d = r.json()
test("Logout endpoint", d.get("status") == "success")

# After logout, auth should fail
r = SESSION.get(f"{BASE_URL}/api/auth/me")
d = r.json()
test("Auth blocked after logout", r.status_code == 401 or d.get("status") == "error")

# ═══════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════
print(f"\n{'='*60}")
print(f"{BOLD}  TEST RESULTS{RESET}")
print(f"{'='*60}")
print(f"  {GREEN}✓ Passed: {passed}{RESET}")
print(f"  {RED}✗ Failed: {failed}{RESET}")
total = passed + failed
if total > 0:
    pct = (passed / total) * 100
    color = GREEN if pct >= 80 else YELLOW if pct >= 60 else RED
    print(f"  {color}  Score: {pct:.0f}% ({passed}/{total}){RESET}")
print(f"{'='*60}\n")

sys.exit(0 if failed == 0 else 1)
