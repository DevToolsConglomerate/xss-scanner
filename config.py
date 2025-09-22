"""
Configuration management for XSS Scanner API
"""
import os
from typing import Optional
import secrets

class Config:
    """Application configuration class"""

    # Database
    MONGODB_URI: Optional[str] = os.getenv("MONGODB_URI")
    DATABASE_NAME: str = os.getenv("DATABASE_NAME", "devtools_conglomerate")

    # Stripe
    STRIPE_API_KEY: Optional[str] = os.getenv("STRIPE_API_KEY")
    STRIPE_WEBHOOK_SECRET: Optional[str] = os.getenv("STRIPE_WEBHOOK_SECRET")

    # API
    API_HOST: str = os.getenv("API_HOST", "0.0.0.0")
    API_PORT: int = int(os.getenv("API_PORT", "8000"))

    # Security - Generate secure random key if not provided
    SECRET_KEY: str = os.getenv("SECRET_KEY") or secrets.token_hex(32)

    # CORS
    ALLOWED_ORIGINS: list = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:8000").split(",")

    # Rate limiting
    RATE_LIMIT_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))

    # Scanner settings
    MAX_CODE_LENGTH: int = int(os.getenv("MAX_CODE_LENGTH", "100000"))
    MAX_VULNERABILITIES: int = int(os.getenv("MAX_VULNERABILITIES", "50"))

    @property
    def is_database_enabled(self) -> bool:
        """Check if database is configured"""
        return self.MONGODB_URI is not None

    @property
    def is_stripe_enabled(self) -> bool:
        """Check if Stripe is configured"""
        return self.STRIPE_API_KEY is not None

# Global config instance
config = Config()
