"""
SQLAlchemy ORM models — maps to the DB schema in the implementation plan.
"""
import uuid
from datetime import datetime
from typing import Optional
from sqlalchemy import (
    String, Float, Boolean, Text, Integer, DateTime,
    ForeignKey, JSON, Enum as SAEnum
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from core.database import Base


def new_uuid() -> str:
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------
class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(
        SAEnum("admin", "analyst", "investigator", name="user_role"),
        default="analyst"
    )
    hashed_password: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    cases: Mapped[list["Case"]] = relationship("Case", back_populates="analyst")
    audit_logs: Mapped[list["AuditLog"]] = relationship("AuditLog", back_populates="analyst")


# ---------------------------------------------------------------------------
# Campaigns
# ---------------------------------------------------------------------------
class Campaign(Base):
    __tablename__ = "campaigns"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    graph_snapshot: Mapped[Optional[dict]] = mapped_column(JSON)

    cases: Mapped[list["Case"]] = relationship("Case", back_populates="campaign")


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------
class Case(Base):
    __tablename__ = "cases"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    analyst_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("users.id"))
    campaign_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("campaigns.id"))
    status: Mapped[str] = mapped_column(
        SAEnum("open", "closed", "escalated", name="case_status"),
        default="open"
    )

    analyst: Mapped[Optional["User"]] = relationship("User", back_populates="cases")
    campaign: Mapped[Optional["Campaign"]] = relationship("Campaign", back_populates="cases")
    emails: Mapped[list["Email"]] = relationship("Email", back_populates="case")


# ---------------------------------------------------------------------------
# Emails
# ---------------------------------------------------------------------------
class Email(Base):
    __tablename__ = "emails"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    case_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("cases.id"))
    sha256_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    raw_storage_path: Mapped[Optional[str]] = mapped_column(Text)

    from_address: Mapped[Optional[str]] = mapped_column(Text)
    from_display_name: Mapped[Optional[str]] = mapped_column(Text)
    reply_to: Mapped[Optional[str]] = mapped_column(Text)
    return_path: Mapped[Optional[str]] = mapped_column(Text)
    message_id: Mapped[Optional[str]] = mapped_column(Text)
    subject: Mapped[Optional[str]] = mapped_column(Text)
    date_sent: Mapped[Optional[datetime]] = mapped_column(DateTime)
    body_text: Mapped[Optional[str]] = mapped_column(Text)
    body_html: Mapped[Optional[str]] = mapped_column(Text)

    fraud_score: Mapped[Optional[float]] = mapped_column(Float)
    classification: Mapped[Optional[str]] = mapped_column(
        SAEnum("legitimate", "suspicious", "impersonation", "phishing", "bec_fraud", name="email_class"),
    )
    spf_result: Mapped[Optional[str]] = mapped_column(String(32))
    dkim_result: Mapped[Optional[str]] = mapped_column(String(32))
    dmarc_result: Mapped[Optional[str]] = mapped_column(String(32))
    analyzed_at: Mapped[Optional[datetime]] = mapped_column(DateTime)

    case: Mapped[Optional["Case"]] = relationship("Case", back_populates="emails")
    trace_hops: Mapped[list["TraceHop"]] = relationship("TraceHop", back_populates="email")
    iocs: Mapped[list["IOC"]] = relationship("IOC", back_populates="email")
    auth_results: Mapped[list["AuthenticationResult"]] = relationship("AuthenticationResult", back_populates="email")
    analysis_results: Mapped[list["AnalysisResult"]] = relationship("AnalysisResult", back_populates="email")


# ---------------------------------------------------------------------------
# Trace Hops (IP chain)
# ---------------------------------------------------------------------------
class TraceHop(Base):
    __tablename__ = "trace_hops"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    email_id: Mapped[str] = mapped_column(String(36), ForeignKey("emails.id"))
    hop_index: Mapped[int] = mapped_column(Integer, default=0)
    from_host: Mapped[Optional[str]] = mapped_column(Text)
    by_host: Mapped[Optional[str]] = mapped_column(Text)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45))
    timestamp: Mapped[Optional[datetime]] = mapped_column(DateTime)

    country: Mapped[Optional[str]] = mapped_column(String(64))
    country_code: Mapped[Optional[str]] = mapped_column(String(4))
    city: Mapped[Optional[str]] = mapped_column(String(128))
    region: Mapped[Optional[str]] = mapped_column(String(128))
    isp: Mapped[Optional[str]] = mapped_column(Text)
    asn: Mapped[Optional[str]] = mapped_column(Text)
    lat: Mapped[Optional[float]] = mapped_column(Float)
    lon: Mapped[Optional[float]] = mapped_column(Float)

    is_private: Mapped[bool] = mapped_column(Boolean, default=False)
    is_vpn_tor: Mapped[bool] = mapped_column(Boolean, default=False)
    is_hosting: Mapped[bool] = mapped_column(Boolean, default=False)
    threat_flags: Mapped[Optional[dict]] = mapped_column(JSON)

    email: Mapped["Email"] = relationship("Email", back_populates="trace_hops")


# ---------------------------------------------------------------------------
# Indicators of Compromise
# ---------------------------------------------------------------------------
class IOC(Base):
    __tablename__ = "iocs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    email_id: Mapped[str] = mapped_column(String(36), ForeignKey("emails.id"))
    ioc_type: Mapped[str] = mapped_column(
        SAEnum("url", "domain", "ip", "attachment", "email_addr", name="ioc_type")
    )
    value: Mapped[str] = mapped_column(Text, nullable=False)
    risk_level: Mapped[str] = mapped_column(
        SAEnum("low", "medium", "high", "critical", name="risk_level"),
        default="low"
    )
    context: Mapped[Optional[str]] = mapped_column(Text)
    metadata_: Mapped[Optional[dict]] = mapped_column("metadata", JSON)

    email: Mapped["Email"] = relationship("Email", back_populates="iocs")


# ---------------------------------------------------------------------------
# Domain Intelligence Cache
# ---------------------------------------------------------------------------
class DomainIntel(Base):
    __tablename__ = "domain_intel"

    domain: Mapped[str] = mapped_column(String(255), primary_key=True)
    registrar: Mapped[Optional[str]] = mapped_column(Text)
    creation_date: Mapped[Optional[str]] = mapped_column(String(32))
    expiry_date: Mapped[Optional[str]] = mapped_column(String(32))
    mx_records: Mapped[Optional[dict]] = mapped_column(JSON)
    nameservers: Mapped[Optional[dict]] = mapped_column(JSON)
    is_blacklisted: Mapped[bool] = mapped_column(Boolean, default=False)
    last_checked: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


# ---------------------------------------------------------------------------
# Immutable Audit Log
# ---------------------------------------------------------------------------
class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    analyst_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("users.id"))
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_type: Mapped[Optional[str]] = mapped_column(String(64))
    resource_id: Mapped[Optional[str]] = mapped_column(String(36))
    case_id: Mapped[Optional[str]] = mapped_column(String(36))
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45))
    detail: Mapped[Optional[str]] = mapped_column(Text)

    analyst: Mapped[Optional["User"]] = relationship("User", back_populates="audit_logs")


# ---------------------------------------------------------------------------
# Authentication Results
# ---------------------------------------------------------------------------
class AuthenticationResult(Base):
    __tablename__ = "authentication_results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    email_id: Mapped[str] = mapped_column(String(36), ForeignKey("emails.id"))
    protocol: Mapped[str] = mapped_column(String(32), nullable=False) # spf, dkim, dmarc
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    reason: Mapped[Optional[str]] = mapped_column(Text)
    raw_result: Mapped[Optional[str]] = mapped_column(Text)

    email: Mapped["Email"] = relationship("Email", back_populates="auth_results")


# ---------------------------------------------------------------------------
# Analysis Results
# ---------------------------------------------------------------------------
class AnalysisResult(Base):
    __tablename__ = "analysis_results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    email_id: Mapped[str] = mapped_column(String(36), ForeignKey("emails.id"))
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    classification: Mapped[str] = mapped_column(String(64), nullable=False)
    confidence: Mapped[str] = mapped_column(String(32), nullable=False)
    reasons: Mapped[Optional[dict]] = mapped_column(JSON) # Store list of reasons
    features: Mapped[Optional[dict]] = mapped_column(JSON) # Store dict/list of features
    analyzed_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    email: Mapped["Email"] = relationship("Email", back_populates="analysis_results")

