"""
Pydantic schemas for API request/response models.
"""
from pydantic import BaseModel, Field
from typing import Optional, Any
from datetime import datetime


# ─── Nested models ────────────────────────────────────────────────────────────

class AuthResult(BaseModel):
    result: str
    detail: Optional[str] = None
    record: Optional[str] = None
    domain: Optional[str] = None
    policy: Optional[str] = None


class AuthAnalysis(BaseModel):
    spf: AuthResult
    dkim: AuthResult
    dmarc: AuthResult


class HeaderAnomaly(BaseModel):
    type: str
    severity: str
    detail: str


class GeoHop(BaseModel):
    hop_index: int
    ip: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None
    city: Optional[str] = None
    country: Optional[str] = None
    country_code: Optional[str] = None
    isp: Optional[str] = None
    asn: Optional[str] = None
    is_private: bool = False
    is_vpn_tor: bool = False
    is_hosting: bool = False
    threat_flags: list[str] = []
    timestamp: Optional[str] = None


class IOCItem(BaseModel):
    ioc_type: str
    value: str
    risk_level: str
    context: Optional[str] = None
    metadata: Optional[dict] = None


class DomainIntelResult(BaseModel):
    domain: str
    mx_records: list[dict] = []
    nameservers: list[str] = []
    has_mx: bool = False
    has_spf: bool = False
    has_dmarc: bool = False
    is_suspicious_nameservers: bool = False


class ScoreBreakdown(BaseModel):
    urgency: float = 0
    credential_harvest: float = 0
    payment_diversion: float = 0
    executive_impersonation: float = 0
    url_risk: float = 0
    display_name_mismatch: float = 0
    auth_failure: float = 0
    geo_risk: float = 0
    header_anomalies: float = 0
    attachment_risk: float = 0


# ─── Main response ────────────────────────────────────────────────────────────

class EmailAnalysisResponse(BaseModel):
    email_id: str
    sha256_hash: str
    analyzed_at: str
    fraud_score: int = Field(..., ge=0, le=100)
    classification: str
    confidence: float
    flags: list[str] = []
    score_breakdown: ScoreBreakdown

    authentication: AuthAnalysis
    header_anomalies: list[HeaderAnomaly] = []
    from_domain: str = ""

    origin_trace: list[GeoHop] = []
    origin_ip: Optional[str] = None

    iocs: list[IOCItem] = []
    domain_intel: Optional[DomainIntelResult] = None

    forensic_summary: str = ""
    case_id: Optional[str] = None


# ─── Case schemas ─────────────────────────────────────────────────────────────

class CaseCreate(BaseModel):
    title: str
    analyst_id: Optional[str] = None


class CaseResponse(BaseModel):
    id: str
    title: str
    status: str
    created_at: str
    analyst_id: Optional[str] = None
    email_count: int = 0


class ErrorResponse(BaseModel):
    error: str
    detail: Optional[str] = None
