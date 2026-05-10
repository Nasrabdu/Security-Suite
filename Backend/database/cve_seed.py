"""
CVE cache table + seed data for offline / slow-NVD fallback.
Integrates with the existing SQLAlchemy Base and SQLite engine.
"""

import json
from datetime import datetime

from sqlalchemy import Column, Integer, String, Text, Float, DateTime, or_
from sqlalchemy.orm import declarative_base

from .models import Base
from .db import get_db_session, engine


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------

class CveCache(Base):
    __tablename__ = "cve_cache"

    id                = Column(Integer, primary_key=True)
    cve_id            = Column(String(20),  unique=True, nullable=False, index=True)
    description       = Column(Text,        nullable=False)
    cvss_score        = Column(Float)
    severity          = Column(String(20),  nullable=False)
    affected_software = Column(Text)   # JSON list stored as text
    created_at        = Column(DateTime, default=datetime.utcnow, nullable=False)

    def to_dict(self) -> dict:
        return {
            "cve_id":            self.cve_id,
            "description":       self.description,
            "cvss_score":        self.cvss_score,
            "severity":          self.severity,
            "affected_software": json.loads(self.affected_software or "[]"),
            "created_at":        self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self):
        return f"<CveCache(cve_id={self.cve_id}, severity={self.severity})>"


# ---------------------------------------------------------------------------
# Seed data  (30 well-known CVEs across 6 service families)
# ---------------------------------------------------------------------------

_SEED_CVES = [
    # Apache httpd 2.4.x ────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2021-41773",
        "description": "Path traversal and RCE in Apache HTTP Server 2.4.49 via mod_cgi.",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "affected_software": ["apache httpd 2.4.49"],
    },
    {
        "cve_id": "CVE-2021-42013",
        "description": "Path traversal bypass in Apache HTTP Server 2.4.49 and 2.4.50.",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "affected_software": ["apache httpd 2.4.49", "apache httpd 2.4.50"],
    },
    {
        "cve_id": "CVE-2022-22720",
        "description": "HTTP request smuggling in Apache HTTP Server 2.4.52 and earlier.",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "affected_software": ["apache httpd 2.4.52"],
    },
    {
        "cve_id": "CVE-2022-31813",
        "description": "Apache HTTP Server may not send X-Forwarded-* headers to backend, "
                       "allowing IP-based authentication bypass.",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "affected_software": ["apache httpd 2.4.53"],
    },
    {
        "cve_id": "CVE-2021-26690",
        "description": "Null pointer dereference via malicious request in mod_session of "
                       "Apache HTTP Server 2.4.x.",
        "cvss_score": 7.5,
        "severity": "HIGH",
        "affected_software": ["apache httpd 2.4"],
    },
    {
        "cve_id": "CVE-2023-25690",
        "description": "HTTP request splitting / smuggling in Apache HTTP Server 2.4.0–2.4.55 "
                       "via mod_proxy with certain RewriteRule patterns.",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "affected_software": ["apache httpd 2.4.0", "apache httpd 2.4.55"],
    },

    # OpenSSH ────────────────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2023-38408",
        "description": "Remote code execution in OpenSSH ssh-agent via forwarded agent "
                       "connection on a malicious host.",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "affected_software": ["openssh 9.3p1"],
    },
    {
        "cve_id": "CVE-2024-6387",
        "description": "regreSSHion: unauthenticated RCE in OpenSSH server (sshd) on "
                       "glibc-based Linux due to signal handler race condition.",
        "cvss_score": 8.1,
        "severity": "HIGH",
        "affected_software": ["openssh 8.5p1", "openssh 9.7p1"],
    },
    {
        "cve_id": "CVE-2023-51767",
        "description": "Row hammer attack allows authentication bypass in OpenSSH in "
                       "rare hardware configurations.",
        "cvss_score": 7.0,
        "severity": "HIGH",
        "affected_software": ["openssh"],
    },
    {
        "cve_id": "CVE-2021-41617",
        "description": "Privilege escalation in OpenSSH sshd when AuthorizedKeysCommand "
                       "or AuthorizedPrincipalsCommand is configured.",
        "cvss_score": 7.0,
        "severity": "HIGH",
        "affected_software": ["openssh 8.7"],
    },
    {
        "cve_id": "CVE-2016-20012",
        "description": "OpenSSH allows username enumeration via timing differences during "
                       "the authentication process.",
        "cvss_score": 5.3,
        "severity": "MEDIUM",
        "affected_software": ["openssh"],
    },

    # MySQL ──────────────────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2023-21980",
        "description": "MySQL Server optimizer vulnerability allows a low-privileged "
                       "remote attacker to cause a hang or crash.",
        "cvss_score": 8.0,
        "severity": "HIGH",
        "affected_software": ["mysql 8.0.32"],
    },
    {
        "cve_id": "CVE-2022-21351",
        "description": "MySQL Server optimizer component allows unauthenticated remote "
                       "attacker to cause denial of service.",
        "cvss_score": 6.5,
        "severity": "MEDIUM",
        "affected_software": ["mysql 8.0.27"],
    },
    {
        "cve_id": "CVE-2021-2154",
        "description": "MySQL Server DDL vulnerability allows high-privileged attacker "
                       "to cause server hang or crash.",
        "cvss_score": 4.9,
        "severity": "MEDIUM",
        "affected_software": ["mysql 8.0.23", "mysql 5.7.33"],
    },
    {
        "cve_id": "CVE-2022-21417",
        "description": "MySQL InnoDB vulnerability allows high-privileged attacker to "
                       "cause repeated server crash.",
        "cvss_score": 4.9,
        "severity": "MEDIUM",
        "affected_software": ["mysql 8.0.28", "mysql 5.7.37"],
    },
    {
        "cve_id": "CVE-2023-22005",
        "description": "MySQL Server replication vulnerability allows high-privileged "
                       "remote attacker to cause server crash.",
        "cvss_score": 4.4,
        "severity": "MEDIUM",
        "affected_software": ["mysql 8.0.33"],
    },

    # PHP ────────────────────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2024-4577",
        "description": "Argument injection in PHP CGI mode on Windows allows remote "
                       "unauthenticated RCE via locale-specific encoding.",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "affected_software": ["php 8.1.28", "php 8.2.18", "php 8.3.6"],
    },
    {
        "cve_id": "CVE-2023-3824",
        "description": "Buffer overflow in PHP phar extension when reading PHAR directory "
                       "entries, leading to potential RCE.",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "affected_software": ["php 8.0.30", "php 8.1.22", "php 8.2.8"],
    },
    {
        "cve_id": "CVE-2022-31625",
        "description": "Use-after-free in PHP Postgres extension leading to potential "
                       "RCE when handling prepared statements.",
        "cvss_score": 8.1,
        "severity": "HIGH",
        "affected_software": ["php 8.1.7", "php 7.4.30"],
    },
    {
        "cve_id": "CVE-2021-21703",
        "description": "Local privilege escalation in PHP-FPM via an out-of-bounds write "
                       "in the SAPI FastCGI module.",
        "cvss_score": 7.0,
        "severity": "HIGH",
        "affected_software": ["php 7.3.31", "php 7.4.24", "php 8.0.11"],
    },
    {
        "cve_id": "CVE-2023-0662",
        "description": "Denial of service via excessive parsing time in PHP for multipart "
                       "forms with malformed boundary strings.",
        "cvss_score": 7.5,
        "severity": "HIGH",
        "affected_software": ["php 8.0.28", "php 8.1.16", "php 8.2.3"],
    },

    # nginx ──────────────────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2021-23017",
        "description": "1-byte memory overwrite in nginx DNS resolver allows remote "
                       "attacker with control over DNS to execute code or crash.",
        "cvss_score": 7.7,
        "severity": "HIGH",
        "affected_software": ["nginx 1.20.0"],
    },
    {
        "cve_id": "CVE-2022-41741",
        "description": "Memory corruption in nginx ngx_http_mp4_module when processing "
                       "specially crafted MP4 files.",
        "cvss_score": 7.8,
        "severity": "HIGH",
        "affected_software": ["nginx 1.23.2"],
    },
    {
        "cve_id": "CVE-2022-41742",
        "description": "Memory disclosure in nginx ngx_http_mp4_module allows local "
                       "attacker to read memory or crash the worker process.",
        "cvss_score": 7.1,
        "severity": "HIGH",
        "affected_software": ["nginx 1.23.2"],
    },
    {
        "cve_id": "CVE-2023-44487",
        "description": "HTTP/2 Rapid Reset Attack allows remote DoS via stream "
                       "cancellation, affecting nginx and many other servers.",
        "cvss_score": 7.5,
        "severity": "HIGH",
        "affected_software": ["nginx 1.25.2"],
    },
    {
        "cve_id": "CVE-2021-3618",
        "description": "ALPACA attack: cross-protocol request forgery via TLS certificate "
                       "confusion affecting nginx and other TLS servers.",
        "cvss_score": 7.4,
        "severity": "HIGH",
        "affected_software": ["nginx"],
    },

    # Linux kernel ───────────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2022-0847",
        "description": "Dirty Pipe: local privilege escalation in Linux kernel >= 5.8 "
                       "via overwriting read-only files in page cache.",
        "cvss_score": 7.8,
        "severity": "HIGH",
        "affected_software": ["linux kernel 5.8", "linux kernel 5.16.11"],
    },
    {
        "cve_id": "CVE-2021-4034",
        "description": "PwnKit: local privilege escalation in pkexec (polkit) present "
                       "on most Linux distributions since 2009.",
        "cvss_score": 7.8,
        "severity": "HIGH",
        "affected_software": ["polkit 0.105", "linux"],
    },
    {
        "cve_id": "CVE-2022-27666",
        "description": "Heap buffer overflow in Linux kernel IPsec esp6 module allowing "
                       "local user to escalate privileges.",
        "cvss_score": 7.8,
        "severity": "HIGH",
        "affected_software": ["linux kernel 5.17"],
    },
    {
        "cve_id": "CVE-2023-0386",
        "description": "OverlayFS privilege escalation in Linux kernel: unprivileged user "
                       "can execute SUID files via fuse-overlayfs mount.",
        "cvss_score": 7.8,
        "severity": "HIGH",
        "affected_software": ["linux kernel 6.2"],
    },
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def init_cve_cache():
    """Create the cve_cache table if it does not exist."""
    Base.metadata.create_all(bind=engine, tables=[CveCache.__table__])


def seed_cve_cache(skip_if_populated: bool = True):
    """Insert seed CVEs. By default skips if the table already has rows."""
    init_cve_cache()

    with get_db_session() as session:
        if skip_if_populated and session.query(CveCache).count() > 0:
            return

        existing_ids = {row.cve_id for row in session.query(CveCache.cve_id)}

        for entry in _SEED_CVES:
            if entry["cve_id"] in existing_ids:
                continue
            session.add(CveCache(
                cve_id=entry["cve_id"],
                description=entry["description"],
                cvss_score=entry["cvss_score"],
                severity=entry["severity"],
                affected_software=json.dumps(entry["affected_software"]),
            ))


def get_cached_cves(service_name: str) -> list[dict]:
    """
    Search cve_cache by service name against the affected_software JSON field.
    Returns a list of CVE dicts matching the service keyword (case-insensitive).
    """
    if not service_name:
        return []

    keyword = f"%{service_name.lower()}%"

    with get_db_session() as session:
        rows = (
            session.query(CveCache)
            .filter(CveCache.affected_software.ilike(keyword))
            .order_by(CveCache.cvss_score.desc())
            .all()
        )
        return [row.to_dict() for row in rows]


if __name__ == "__main__":
    seed_cve_cache(skip_if_populated=False)
    print(f"Seeded {len(_SEED_CVES)} CVEs into cve_cache.")
