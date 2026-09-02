"""
Application configuration — loads settings from environment variables
with sensible defaults for local development.
"""

from pydantic_settings import BaseSettings
from pathlib import Path


class Settings(BaseSettings):
    # ── App ──
    APP_NAME: str = "ProofStrike"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = True

    # ── Database ──
    DATABASE_URL: str = "sqlite+aiosqlite:///./proofstrike.db"

    # ── CORS (frontend origin) ──
    CORS_ORIGINS: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    # ── Evidence / Report storage ──
    EVIDENCE_DIR: str = str(Path(__file__).resolve().parent.parent / "evidence")
    REPORT_DIR: str = str(Path(__file__).resolve().parent.parent / "reports")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
