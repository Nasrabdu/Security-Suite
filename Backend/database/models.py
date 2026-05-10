"""
Database models for Pentest Platform
SQLAlchemy models for scan history, results, and statistics
"""

from sqlalchemy import Column, Integer, String, Text, DateTime, Float, ForeignKey, Boolean
from sqlalchemy.orm import declarative_base, relationship
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

Base = declarative_base()


class User(Base):
    """User account with role-based access"""
    __tablename__ = 'users'

    id            = Column(Integer, primary_key=True)
    user_id       = Column(String(36),  unique=True, nullable=False, index=True)
    email         = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(256), nullable=False)   # longer — PBKDF2 hashes are ~93 chars
    name          = Column(String(255), nullable=False)
    role          = Column(String(20),  nullable=False, default='user')   # admin | user
    is_active     = Column(Boolean, default=True)
    created_at    = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_login    = Column(DateTime)

    scans = relationship("Scan", back_populates="user", foreign_keys="Scan.user_id_fk")

    def set_password(self, password: str) -> None:
        """
        Hash password using PBKDF2-SHA256 (werkzeug default).
        Automatically salted. ~260,000 iterations as of Werkzeug 3.x.
        This replaces the old SHA-256 + manual salt which was brute-forceable.
        """
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        """
        Verify password in constant time (safe against timing attacks).
        Also handles the OLD sha256$salt format gracefully during migration —
        if the stored hash doesn't start with 'pbkdf2:' or 'scrypt:' we
        return False so the user just needs to reset their password.
        """
        if not self.password_hash:
            return False
        try:
            return check_password_hash(self.password_hash, password)
        except Exception:
            return False

    def __repr__(self):
        return f"<User(email={self.email}, role={self.role})>"


class Scan(Base):
    """Main scan record"""
    __tablename__ = 'scans'

    id          = Column(Integer, primary_key=True)
    scan_id     = Column(String(36), unique=True, nullable=False, index=True)
    user_id_fk  = Column(Integer, ForeignKey('users.id'), nullable=False)
    target      = Column(String(255), nullable=False)
    scan_type   = Column(String(50),  nullable=False)
    tool        = Column(String(50),  nullable=False)
    status      = Column(String(20),  nullable=False, default='pending')
    created_at  = Column(DateTime, default=datetime.utcnow, nullable=False)
    started_at  = Column(DateTime)
    completed_at= Column(DateTime)
    duration    = Column(Float)
    error_message = Column(Text)
    ai_summary  = Column(Text)
    risk_level  = Column(String(20))
    workflow_id = Column(String(36), index=True)
    workflow_position = Column(Integer)

    user           = relationship("User", back_populates="scans", foreign_keys=[user_id_fk])
    results        = relationship("ScanResult",    back_populates="scan", cascade="all, delete-orphan")
    vulnerabilities= relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Scan(id={self.scan_id}, target={self.target}, status={self.status})>"


class ScanResult(Base):
    """Individual scan result — open port / service"""
    __tablename__ = 'scan_results'

    id       = Column(Integer, primary_key=True)
    scan_id  = Column(Integer, ForeignKey('scans.id'), nullable=False)
    port     = Column(Integer)
    protocol = Column(String(10))
    state    = Column(String(20))
    service  = Column(String(100))
    version  = Column(String(255))
    banner   = Column(Text)
    os_detection = Column(String(255))

    scan = relationship("Scan", back_populates="results")

    def __repr__(self):
        return f"<ScanResult(port={self.port}, service={self.service}, state={self.state})>"


class Vulnerability(Base):
    """Discovered vulnerability"""
    __tablename__ = 'vulnerabilities'

    id          = Column(Integer, primary_key=True)
    scan_id     = Column(Integer, ForeignKey('scans.id'), nullable=False)
    title       = Column(String(255), nullable=False)
    description = Column(Text)
    severity    = Column(String(20), nullable=False)
    cvss_score  = Column(Float)
    cve_id      = Column(String(50))
    owasp_category = Column(String(50))
    owasp_name  = Column(String(255))
    affected_port    = Column(Integer)
    affected_service = Column(String(100))
    affected_version = Column(String(255))
    remediation = Column(Text)
    references  = Column(Text)
    ai_classified    = Column(Boolean, default=False)
    confidence_score = Column(Float)

    scan = relationship("Scan", back_populates="vulnerabilities")

    def __repr__(self):
        return f"<Vulnerability(title={self.title}, severity={self.severity}, cve={self.cve_id})>"


class Case(Base):
    """TheHive-style incident case for local case management."""
    __tablename__ = 'cases'

    id          = Column(Integer, primary_key=True)
    case_id     = Column(String(36), unique=True, nullable=False, index=True)
    user_id_fk  = Column(Integer, ForeignKey('users.id'), nullable=False)
    title       = Column(String(255), nullable=False)
    description = Column(Text)
    severity    = Column(String(20), nullable=False, default='medium')  # low|medium|high|critical
    status      = Column(String(30), nullable=False, default='open')    # open|investigating|resolved|closed
    tags        = Column(Text)     # JSON array stored as text
    scan_id     = Column(String(36), index=True)  # optional link to a scan
    created_at  = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at  = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User", foreign_keys=[user_id_fk])

    def __repr__(self):
        return f"<Case(id={self.case_id}, title={self.title}, severity={self.severity}, status={self.status})>"


class Statistics(Base):
    """Aggregated statistics for dashboard"""
    __tablename__ = 'statistics'

    id          = Column(Integer, primary_key=True)
    date        = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    total_scans = Column(Integer, default=0)
    scans_today = Column(Integer, default=0)
    scans_this_week = Column(Integer, default=0)
    active_scans    = Column(Integer, default=0)
    total_vulnerabilities = Column(Integer, default=0)
    critical_count  = Column(Integer, default=0)
    high_count      = Column(Integer, default=0)
    medium_count    = Column(Integer, default=0)
    low_count       = Column(Integer, default=0)
    info_count      = Column(Integer, default=0)
    avg_scan_duration     = Column(Float)
    total_targets_scanned = Column(Integer, default=0)

    def __repr__(self):
        return f"<Statistics(date={self.date}, total_scans={self.total_scans})>"
