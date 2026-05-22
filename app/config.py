"""
AEGIS Configuration Module
Loads settings from environment variables with sensible defaults.
"""

from functools import lru_cache
from typing import List
from pydantic_settings import BaseSettings
from pydantic import Field
import json


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # Application
    app_name: str = Field(default="AEGIS", description="Application name")
    app_version: str = Field(default="1.0.0", description="Application version")
    debug: bool = Field(default=True, description="Debug mode")
    secret_key: str = Field(default="dev-secret-key-change-in-prod", description="Secret key for JWT")

    # Server
    backend_host: str = Field(default="127.0.0.1", description="Backend host")
    backend_port: int = Field(default=8001, description="Backend port")
    
    # Database
    database_url: str = Field(
        default="sqlite+aiosqlite:///./aegis.db",
        description="Database connection URL"
    )
    
    # Cache
    cache_type: str = Field(default="memory", description="Cache type: memory or redis")
    redis_url: str = Field(default="redis://localhost:6379/0", description="Redis URL if using redis cache")
    
    # API
    api_v1_prefix: str = Field(default="/api/v1", description="API version prefix")
    cors_origins: str = Field(
        default='["http://localhost:3000","http://localhost:5173"]',
        description="CORS allowed origins as JSON array"
    )
    
    # Google Gemini / Vertex AI
    gemini_api_key: str = Field(default="", description="Google AI Studio API key (optional if using Vertex AI)")
    gemini_model: str = Field(default="gemini-2.5-flash", description="Gemini model to use")
    use_vertex_ai: bool = Field(default=True, description="Use Vertex AI instead of API key")
    google_cloud_project: str = Field(default="", description="GCP project ID")
    google_cloud_location: str = Field(default="us-central1", description="GCP location")
    
    # Guardrails
    tier1_max_latency_ms: int = Field(default=30, description="Tier 1 filter max latency in ms")
    tier2_timeout_seconds: int = Field(default=5, description="Tier 2 async timeout")
    tier2_enabled: bool = Field(default=True, description="Enable Tier 2 LLM filtering")
    
    # Audit
    audit_hash_algorithm: str = Field(default="sha256", description="Hash algorithm for audit chain")
    audit_genesis_seed: str = Field(default="AEGIS-GENESIS-2024", description="Genesis block seed")
    
    # Rate Limiting
    rate_limit_enabled: bool = Field(default=False, description="Enable rate limiting")
    rate_limit_requests_per_minute: int = Field(default=60, description="Requests per minute limit")
    
    @property
    def cors_origins_list(self) -> List[str]:
        """Parse CORS origins from JSON string to list."""
        try:
            return json.loads(self.cors_origins)
        except json.JSONDecodeError:
            return ["http://localhost:3000", "http://localhost:5173"]
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    """
    Get cached settings instance.
    Using lru_cache ensures settings are only loaded once.
    """
    return Settings()


# Convenience access
settings = get_settings()
