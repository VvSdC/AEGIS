"""
AEGIS Database Models
SQLAlchemy ORM models for all entities.
"""

from datetime import datetime
from typing import Optional
from sqlalchemy import String, Text, Boolean, Integer, Float, DateTime, JSON, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .database import Base


class Policy(Base):
    """Policy template model — stores regulatory policy packs."""
    __tablename__ = "policies"
    
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    region: Mapped[str] = mapped_column(String(50), index=True)  # EU, US, APAC, Global
    category: Mapped[str] = mapped_column(String(50))  # privacy, fairness, transparency, etc.
    version: Mapped[str] = mapped_column(String(20), default="1.0.0")
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    rules: Mapped[dict] = mapped_column(JSON, default=dict)  # JSON array of rules
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self) -> str:
        return f"<Policy(name='{self.name}', region='{self.region}')>"


class AuditLog(Base):
    """Audit log model — hash-chained immutable audit entries."""
    __tablename__ = "audit_logs"
    
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    event_type: Mapped[str] = mapped_column(String(50), index=True)  # filter, risk_score, policy_check, etc.
    actor: Mapped[str] = mapped_column(String(100))  # user/system that triggered event
    system_name: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, index=True)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    hash: Mapped[str] = mapped_column(String(64), unique=True)  # SHA-256 hash
    prev_hash: Mapped[str] = mapped_column(String(64))  # Previous entry's hash
    
    def __repr__(self) -> str:
        return f"<AuditLog(id={self.id}, event_type='{self.event_type}', hash='{self.hash[:8]}...')>"


class RiskAssessment(Base):
    """Risk assessment model — stores risk scoring results."""
    __tablename__ = "risk_assessments"
    
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    system_name: Mapped[str] = mapped_column(String(100), index=True)
    score: Mapped[float] = mapped_column(Float)  # 0-100
    level: Mapped[str] = mapped_column(String(20))  # LOW, MEDIUM, HIGH, CRITICAL
    breakdown: Mapped[dict] = mapped_column(JSON, default=dict)  # Score per category
    recommendations: Mapped[list] = mapped_column(JSON, default=list)
    input_data: Mapped[dict] = mapped_column(JSON, default=dict)  # Original input for scoring
    assessed_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    assessed_by: Mapped[str] = mapped_column(String(100), default="system")
    
    def __repr__(self) -> str:
        return f"<RiskAssessment(system='{self.system_name}', score={self.score}, level='{self.level}')>"


class FilterLog(Base):
    """Filter log model — tracks guardrail filter activity."""
    __tablename__ = "filter_logs"
    
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    direction: Mapped[str] = mapped_column(String(20))  # prompt, response
    original_text: Mapped[str] = mapped_column(Text)
    filtered_text: Mapped[str] = mapped_column(Text)
    filters_triggered: Mapped[list] = mapped_column(JSON, default=list)  # List of filter names
    tier: Mapped[int] = mapped_column(Integer, default=1)  # 1 or 2
    latency_ms: Mapped[float] = mapped_column(Float)
    blocked: Mapped[bool] = mapped_column(Boolean, default=False)
    system_name: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, index=True)
    
    def __repr__(self) -> str:
        return f"<FilterLog(id={self.id}, direction='{self.direction}', blocked={self.blocked})>"


class Playbook(Base):
    """Playbook model — tracks governance workflow progress."""
    __tablename__ = "playbooks"
    
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    system_name: Mapped[str] = mapped_column(String(100), index=True)
    owner: Mapped[str] = mapped_column(String(100))
    region: Mapped[str] = mapped_column(String(50))
    current_stage: Mapped[str] = mapped_column(String(50), default="INTAKE")
    # INTAKE → RISK_ASSESSMENT → POLICY_CHECK → REVIEW → APPROVED → ATTESTED
    stages_completed: Mapped[dict] = mapped_column(JSON, default=dict)
    extra_data: Mapped[dict] = mapped_column(JSON, default=dict)  # Additional context
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self) -> str:
        return f"<Playbook(system='{self.system_name}', stage='{self.current_stage}')>"


class RedTeamResult(Base):
    """Red team test results model."""
    __tablename__ = "redteam_results"
    
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    system_name: Mapped[str] = mapped_column(String(100), index=True)
    target_model: Mapped[str] = mapped_column(String(100))
    category: Mapped[str] = mapped_column(String(50))  # jailbreak, pii, bias, hallucination, injection
    probe: Mapped[str] = mapped_column(Text)
    response: Mapped[str] = mapped_column(Text)
    passed: Mapped[bool] = mapped_column(Boolean)
    risk_level: Mapped[str] = mapped_column(String(20))  # LOW, MEDIUM, HIGH, CRITICAL
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    run_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    
    def __repr__(self) -> str:
        return f"<RedTeamResult(category='{self.category}', passed={self.passed})>"


class DPIAReport(Base):
    """Data Protection Impact Assessment report model."""
    __tablename__ = "dpia_reports"
    
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    system_name: Mapped[str] = mapped_column(String(100), index=True)
    description: Mapped[str] = mapped_column(Text)
    data_types: Mapped[list] = mapped_column(JSON, default=list)
    purpose: Mapped[str] = mapped_column(Text)
    report_content: Mapped[dict] = mapped_column(JSON, default=dict)  # Structured DPIA sections
    generated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    generated_by: Mapped[str] = mapped_column(String(100), default="gemini")
    status: Mapped[str] = mapped_column(String(20), default="draft")  # draft, reviewed, approved
    
    def __repr__(self) -> str:
        return f"<DPIAReport(system='{self.system_name}', status='{self.status}')>"
