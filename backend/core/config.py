"""
Application configuration — reads from environment variables or .env file.
"""
from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    app_name: str = "ForensicAI"
    app_version: str = "3.0.0"
    debug: bool = True

    # Logging
    log_level: str = "INFO"

    # Database
    database_url: str = "sqlite+aiosqlite:///./forensics.db"

    # Security
    secret_key: str = "CHANGE_ME_IN_PRODUCTION_USE_STRONG_RANDOM_KEY"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 480

    # IP Geolocation and Threat Intel
    ipinfo_token: Optional[str] = None
    maxmind_db_path: Optional[str] = None
    abuseipdb_api_key: Optional[str] = None

    # File storage
    upload_dir: str = "./uploads"
    max_file_size_mb: int = 25

    # PII masking
    mask_pii: bool = False

    class Config:
        env_file = ".env"
        case_sensitive = False


settings = Settings()
