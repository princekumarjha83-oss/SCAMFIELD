"""
ScamShield AI - Safe Sanitizer & Privacy-Preserving Logger
Enforces static inspection security rules:
- Strictly prohibits outbound requests (no socket, no requests, no urllib.request.urlopen)
- Masks sensitive credentials or tokens in logs
- Generates cryptographic SHA-256 digests for audit trails
"""

import hashlib
import logging
from urllib.parse import urlparse

logger = logging.getLogger("scamshield.security")
logger.setLevel(logging.INFO)

# Formatter that avoids leaking credentials
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "[%(asctime)s] [SOC-AUDIT] [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)

def hash_url(url: str) -> str:
    """Computes a SHA-256 digest of the URL for privacy-preserving index and search."""
    return hashlib.sha256(url.strip().encode("utf-8")).hexdigest()

def sanitize_and_log_scan(url: str, risk_score: int, risk_level: str) -> str:
    """
    Safely logs a scan event without leaking sensitive query parameters,
    tokens, or passwords that might have been part of the URL.
    Returns the SHA-256 digest.
    """
    digest = hash_url(url)
    try:
        parsed = urlparse(url)
        safe_host = parsed.hostname or "unknown-host"
        safe_path = parsed.path or "/"
        has_query = bool(parsed.query)

        # Log safe metadata without query payload
        logger.info(
            f"Static Inspection Event | Host: {safe_host} | Path: {safe_path} | "
            f"QueryPresent: {has_query} | Digest: {digest[:12]}... | "
            f"Risk: {risk_score}/100 ({risk_level})"
        )
    except Exception:
        logger.info(f"Static Inspection Event | Digest: {digest[:12]}... | Risk: {risk_score}/100")

    return digest
