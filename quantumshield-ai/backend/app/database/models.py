"""
Database ORM models for QuantumShield AI.
"""
import uuid
from datetime import datetime
from enum import Enum as PyEnum
from sqlalchemy import (
    Column, String, Integer, Float, Boolean, Text, DateTime,
    ForeignKey, Enum as SAEnum
)
from sqlalchemy.orm import relationship
from app.database.session import Base


def gen_uuid():
    return str(uuid.uuid4())


class ScanStatus(str, PyEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class Severity(str, PyEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class FindingStatus(str, PyEnum):
    OPEN = "OPEN"
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    FIXED = "FIXED"
    WONT_FIX = "WONT_FIX"


class FindingType(str, PyEnum):
    CLASSICAL = "CLASSICAL"
    QUANTUM = "QUANTUM"
    HYBRID = "HYBRID"


class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, default=gen_uuid)
    username = Column(String(64), unique=True, nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    projects = relationship("Project", back_populates="owner")


class Project(Base):
    __tablename__ = "projects"
    id = Column(String, primary_key=True, default=gen_uuid)
    name = Column(String(128), nullable=False)
    description = Column(Text, nullable=True)
    owner_id = Column(String, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    owner = relationship("User", back_populates="projects")
    targets = relationship("Target", back_populates="project")
    scans = relationship("Scan", back_populates="project")


class Target(Base):
    __tablename__ = "targets"
    id = Column(String, primary_key=True, default=gen_uuid)
    project_id = Column(String, ForeignKey("projects.id"), nullable=False)
    name = Column(String(128), nullable=False)
    url = Column(String(512), nullable=False)
    environment = Column(String(32), default="lab")
    allowed_hosts = Column(Text, nullable=True)    # JSON list
    allowed_ports = Column(Text, nullable=True)    # JSON list
    destructive_tests = Column(Boolean, default=False)
    max_requests_per_minute = Column(Integer, default=60)
    is_authorized = Column(Boolean, default=True)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    project = relationship("Project", back_populates="targets")
    scans = relationship("Scan", back_populates="target")


class Scan(Base):
    __tablename__ = "scans"
    id = Column(String, primary_key=True, default=gen_uuid)
    project_id = Column(String, ForeignKey("projects.id"), nullable=False)
    target_id = Column(String, ForeignKey("targets.id"), nullable=False)
    name = Column(String(128), nullable=False)
    scan_type = Column(String(32), default="full")
    status = Column(SAEnum(ScanStatus), default=ScanStatus.PENDING, nullable=False)
    current_state = Column(String(32), nullable=True)

    # Results
    security_score = Column(Float, nullable=True)
    quantum_score = Column(Float, nullable=True)
    pqc_readiness = Column(Float, nullable=True)
    endpoints_discovered = Column(Integer, default=0)
    quantum_assets_found = Column(Integer, default=0)
    total_tests = Column(Integer, default=0)
    completed_tests = Column(Integer, default=0)
    application_map = Column(Text, nullable=True)  # JSON
    error_message = Column(Text, nullable=True)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    project = relationship("Project", back_populates="scans")
    target = relationship("Target", back_populates="scans")
    findings = relationship("Finding", back_populates="scan")
    events = relationship("AgentEvent", back_populates="scan")
    endpoints = relationship("Endpoint", back_populates="scan")
    crypto_assets = relationship("CryptoAsset", back_populates="scan")


class Finding(Base):
    __tablename__ = "findings"
    id = Column(String, primary_key=True, default=gen_uuid)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False)
    title = Column(String(256), nullable=False)
    category = Column(String(64), nullable=False)
    finding_type = Column(SAEnum(FindingType), default=FindingType.CLASSICAL, nullable=False)
    severity = Column(SAEnum(Severity), nullable=False)
    confidence = Column(Float, default=0.5)
    endpoint = Column(String(512), nullable=True)
    description = Column(Text, nullable=True)
    impact = Column(Text, nullable=True)
    root_cause = Column(Text, nullable=True)
    risk_score = Column(Float, default=0.0)
    quantum_risk = Column(Float, nullable=True)
    status = Column(SAEnum(FindingStatus), default=FindingStatus.OPEN, nullable=False)
    first_detected = Column(DateTime, default=datetime.utcnow)
    last_verified = Column(DateTime, nullable=True)
    fixed_at = Column(DateTime, nullable=True)

    scan = relationship("Scan", back_populates="findings")
    evidence = relationship("Evidence", back_populates="finding")
    remediation = relationship("Remediation", back_populates="finding", uselist=False)
    regression_tests = relationship("RegressionTest", back_populates="finding")


class Evidence(Base):
    __tablename__ = "evidence"
    id = Column(String, primary_key=True, default=gen_uuid)
    finding_id = Column(String, ForeignKey("findings.id"), nullable=False)
    test_name = Column(String(128), nullable=True)
    endpoint = Column(String(512), nullable=True)
    observation = Column(Text, nullable=True)
    confidence = Column(Float, default=0.5)
    is_confirmed = Column(Boolean, default=False)
    raw_data = Column(Text, nullable=True)  # JSON
    collected_at = Column(DateTime, default=datetime.utcnow)

    finding = relationship("Finding", back_populates="evidence")


class Remediation(Base):
    __tablename__ = "remediations"
    id = Column(String, primary_key=True, default=gen_uuid)
    finding_id = Column(String, ForeignKey("findings.id"), nullable=False, unique=True)
    explanation = Column(Text, nullable=True)
    root_cause = Column(Text, nullable=True)
    recommended_fix = Column(Text, nullable=True)
    code_example = Column(Text, nullable=True)
    priority = Column(String(32), default="MEDIUM")
    regression_test_description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    finding = relationship("Finding", back_populates="remediation")


class RegressionTest(Base):
    __tablename__ = "regression_tests"
    id = Column(String, primary_key=True, default=gen_uuid)
    finding_id = Column(String, ForeignKey("findings.id"), nullable=False)
    status = Column(String(32), default="PENDING")  # PENDING | PASS | FAIL
    result_details = Column(Text, nullable=True)  # JSON
    run_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    finding = relationship("Finding", back_populates="regression_tests")


class AgentEvent(Base):
    __tablename__ = "agent_events"
    id = Column(String, primary_key=True, default=gen_uuid)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False)
    event_type = Column(String(64), nullable=False)
    agent = Column(String(64), nullable=True)
    message = Column(Text, nullable=False)
    reason = Column(Text, nullable=True)
    tool = Column(String(64), nullable=True)
    target = Column(String(512), nullable=True)
    result = Column(Text, nullable=True)
    decision = Column(String(32), nullable=True)
    state = Column(String(32), nullable=True)
    extra_metadata = Column(Text, nullable=True)  # JSON
    timestamp = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="events")


class Endpoint(Base):
    __tablename__ = "endpoints"
    id = Column(String, primary_key=True, default=gen_uuid)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False)
    path = Column(String(512), nullable=False)
    method = Column(String(10), default="GET")
    auth_required = Column(Boolean, default=False)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="endpoints")


class CryptoAsset(Base):
    __tablename__ = "crypto_assets"
    id = Column(String, primary_key=True, default=gen_uuid)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False)
    algorithm = Column(String(64), nullable=False)
    key_size = Column(Integer, nullable=True)
    protocol = Column(String(64), nullable=True)
    endpoint = Column(String(512), nullable=True)
    usage = Column(String(64), nullable=True)
    classical_security = Column(String(32), nullable=True)
    quantum_security = Column(String(32), nullable=True)
    quantum_attack = Column(String(32), nullable=True)
    pqc_status = Column(String(64), nullable=True)
    risk_score = Column(Float, default=0.0)
    details = Column(Text, nullable=True)  # JSON
    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="crypto_assets")
