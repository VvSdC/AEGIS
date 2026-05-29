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
    admin_email: str = Field(default="admin@aegis.local", description="Default admin email")
    admin_password: str = Field(default="admin123", description="Default admin password")
    auth_token_expire_minutes: int = Field(default=480, description="JWT expiration in minutes")

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
    
    # Inference providers
    gemini_api_key: str = Field(default="", description="Google Gemini API key (AI Studio)")
    huggingface_api_key: str = Field(default="", description="Hugging Face Inference API key")
    openrouter_api_key: str = Field(default="", description="OpenRouter API key")
    mistral_api_key: str = Field(default="", description="Mistral API key (La Plateforme Experiment plan)")
    
    # Guardrails
    tier1_max_latency_ms: int = Field(default=30, description="Tier 1 filter max latency in ms")
    tier1_jailbreak_injection_patterns: bool = Field(
        default=False,
        description="Use English regex jailbreak/injection patterns in Tier 1 (off when using Llama Guard)",
    )
    tier2_timeout_seconds: int = Field(default=30, description="Tier 2 timeout (Llama Guard on Hugging Face)")
    tier2_enabled: bool = Field(default=True, description="Enable Tier 2 semantic safety (Llama Guard)")
    llama_guard_model: str = Field(
        default="meta-llama/Llama-Guard-3-1B",
        description="Hugging Face model id for Llama Guard 3 (gated; accept license on HF)",
    )
    llama_guard_max_tokens: int = Field(default=128, description="Max tokens for Llama Guard classification output")
    llama_guard_max_input_chars: int = Field(
        default=12000,
        description="Truncate prompts sent to Llama Guard",
    )
    
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
