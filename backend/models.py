"""
ScamShield AI - Multi-Modal Database Models
Supports persistent audit trails for Message, URL, Screenshot, and Email scans.
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, Text
from backend.database import Base

class ScanRecord(Base):
    __tablename__ = "scan_records"

    id = Column(Integer, primary_key=True, index=True)
    scan_type = Column(String(32), default="url", index=True, nullable=False) # url, message, screenshot, email
    url = Column(String(2048), nullable=False)                                # primary target string / identifier
    url_hash = Column(String(64), index=True, nullable=False)                 # SHA-256 for privacy audit indexing
    risk_score = Column(Integer, nullable=False)                              # 0 - 100
    risk_level = Column(String(32), nullable=False)                           # SAFE, SUSPICIOUS, HIGH
    ml_confidence = Column(Float, nullable=True)
    phishing_probability = Column(Float, nullable=True)
    summary = Column(String(512), nullable=True)                              # Executive summary
    indicators = Column(Text, nullable=False, default="[]")                   # JSON serialized list
    features = Column(Text, nullable=False, default="{}")                     # JSON serialized dictionary
    scanned_at = Column(DateTime, default=datetime.utcnow, nullable=False)
