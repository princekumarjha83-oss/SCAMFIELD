"""
ScamShield AI - Application Configuration
Uses pydantic-settings to manage environment variables and security constraints.
"""

from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    APP_NAME: str = "ScamShield AI"
    VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False

    # Security: Database URL supports SQLite local default and PostgreSQL
    DATABASE_URL: str = "sqlite:///./scamshield.db"

    # Security: Restrict CORS to configured frontend origins
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

    # Security: Rate Limiting
    RATE_LIMIT_PER_MINUTE: str = "60/minute"
    SCAN_RATE_LIMIT_PER_MINUTE: str = "30/minute"

    # ML Artifacts Paths
    MODEL_PATH: str = "ml/artifacts/phishing_model.joblib"
    METRICS_PATH: str = "ml/artifacts/metrics.json"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()
