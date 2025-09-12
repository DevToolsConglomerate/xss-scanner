"""
Configuration management for XSS Scanner API
"""
import os
from typing import Optional

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

    # Security
    SECRET_KEY: str = os.getenv("SECRET_KEY", "your-secret-key-here")

    # CORS
    ALLOWED_ORIGINS: list = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:8000").split(",")

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
