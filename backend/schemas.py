"""
ScamShield AI - Pydantic Request & Response Schemas
Provides strict schema validation, field constraints, and serialized outputs.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
from pydantic import BaseModel, Field, HttpUrl, field_validator

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
        # Reject non-routable or dangerous pseudo-schemes
        lower = clean.lower()
        forbidden_schemes = ("javascript:", "data:", "file:", "blob:", "gopher:", "vbscript:")
        for scheme in forbidden_schemes:
            if lower.startswith(scheme):
                raise ValueError(f"Prohibited scheme '{scheme}'. Only HTTP and HTTPS static inspection is supported.")
        if not (lower.startswith("http://") or lower.startswith("https://")):
            raise ValueError("URL must explicitly start with 'http://' or 'https://'.")
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

class HistoryItemResponse(BaseModel):
    id: int
    url: str
    risk_score: int
    risk_level: str
    ml_confidence: Optional[float] = None
    phishing_probability: Optional[float] = None
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
