"""
ScamShield AI - Multi-Modal Request & Response Schemas
Provides strict validation, field constraints, and schemas for Message, URL, Screenshot, and Email scans.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
from pydantic import BaseModel, Field, field_validator

class ScanRequest(BaseModel):
    url: str = Field(
        ...,
        min_length=4,
        max_length=2048,
        description="The target URL to inspect statically without making network connections."
    )

    @field_validator("url")
    def validate_url_syntax(cls, v: str) -> str:
        clean = v.strip()
        if not clean:
            raise ValueError("URL cannot be empty or whitespace only.")
        lower = clean.lower()
        forbidden_schemes = ("javascript:", "data:", "file:", "blob:", "gopher:", "vbscript:")
        for scheme in forbidden_schemes:
            if lower.startswith(scheme):
                raise ValueError(f"Prohibited scheme '{scheme}'. Only HTTP and HTTPS static inspection is supported.")
        if not (lower.startswith("http://") or lower.startswith("https://")):
            raise ValueError("URL must explicitly start with 'http://' or 'https://'.")
        return clean

class MessageScanRequest(BaseModel):
    text: str = Field(
        ...,
        min_length=1,
        max_length=10000,
        description="Suspicious SMS, chat message, or text communication to analyze."
    )

    @field_validator("text")
    def validate_text(cls, v: str) -> str:
        clean = v.strip()
        if not clean:
            raise ValueError("Message text cannot be empty or whitespace only.")
        return clean

class EmailScanRequest(BaseModel):
    body: str = Field(..., min_length=1, max_length=20000, description="Email body or complete raw RFC message.")
    subject: Optional[str] = Field(None, max_length=500, description="Email subject line.")
    sender: Optional[str] = Field(None, max_length=500, description="Sender display name or email address.")

    @field_validator("body")
    def validate_body(cls, v: str) -> str:
        clean = v.strip()
        if not clean:
            raise ValueError("Email content cannot be empty.")
        return clean

class IndicatorItem(BaseModel):
    name: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    description: str
    evidence: Optional[str] = None

class ScanResponse(BaseModel):
    url: str
    risk_score: int
    risk_level: str
    ml_confidence: float
    phishing_probability: float
    indicators: List[IndicatorItem]
    features: Dict[str, Any]
    scanned_at: datetime
    disclaimer: str

class MessageScanResponse(BaseModel):
    scan_type: str = "message"
    risk_score: int
    risk_level: str
    intent_category: str
    indicators: List[IndicatorItem]
    extracted_urls: List[Dict[str, Any]]
    summary: str
    recommended_actions: List[str]
    scanned_at: datetime
    disclaimer: str

class ScreenshotScanResponse(BaseModel):
    scan_type: str = "screenshot"
    risk_score: int
    risk_level: str
    extracted_text: str
    ocr_metadata: Dict[str, Any]
    intent_category: str
    indicators: List[IndicatorItem]
    extracted_urls: List[Dict[str, Any]]
    summary: str
    recommended_actions: List[str]
    scanned_at: datetime
    disclaimer: str

class EmailScanResponse(BaseModel):
    scan_type: str = "email"
    risk_score: int
    risk_level: str
    sender: str
    subject: str
    indicators: List[IndicatorItem]
    extracted_urls: List[Dict[str, Any]]
    summary: str
    recommended_actions: List[str]
    disclaimer: str
    scanned_at: datetime

class HistoryItemResponse(BaseModel):
    id: int
    scan_type: str = "url"
    url: str
    risk_score: int
    risk_level: str
    ml_confidence: Optional[float] = None
    phishing_probability: Optional[float] = None
    summary: Optional[str] = None
    indicators: List[IndicatorItem]
    features: Dict[str, Any]
    scanned_at: datetime

class AnalyticsResponse(BaseModel):
    total_scans: int
    high_risk_scans: int
    suspicious_scans: int
    safe_scans: int
    avg_risk_score: float
    top_indicators: List[Dict[str, Any]]
    db_type: str

class ModelInfoResponse(BaseModel):
    model_name: str
    architecture: str
    dataset_name: str
    dataset_provenance: Dict[str, str]
    dataset_license: str
    total_samples: int
    train_samples: int
    test_samples: int
    metrics: Dict[str, Any]
    feature_importances: List[Dict[str, Any]]

class HealthResponse(BaseModel):
    status: str
    version: str
    model_loaded: bool
    db_connected: bool
    environment: str
    supported_modalities: List[str] = ["url", "message", "screenshot", "email"]
