import logging
from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings

logger = logging.getLogger(__name__)

# Resolve paths relative to the backend/ directory, not the working directory
BACKEND_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BACKEND_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)


class Settings(BaseSettings):
    database_url: str = f"sqlite:///{DATA_DIR / 'honeypot.db'}"
    cowrie_log_path: str = "/var/log/cowrie/cowrie.json"
    geoip_db_path: str = str(DATA_DIR / "GeoLite2-City.mmdb")

    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""

    admin_api_key: str = ""

    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    # Rate limiting
    rate_limit_default: str = "60/minute"
    rate_limit_stream: str = "10/minute"

    model_config = {"env_file": ".env"}

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, v):
        """Accept comma-separated string from env var: CORS_ORIGINS=https://a.com,https://b.com"""
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v

    @field_validator("database_url", mode="after")
    @classmethod
    def ensure_absolute_db_path(cls, v):
        """Resolve relative SQLite paths to be under DATA_DIR."""
        if v.startswith("sqlite:///") and not v.startswith("sqlite:////"):
            relative = v[len("sqlite:///"):]
            absolute = str(DATA_DIR / relative)
            return f"sqlite:///{absolute}"
        return v

    def validate_startup(self):
        """Log warnings for missing or problematic configuration."""
        if not self.admin_api_key:
            logger.warning(
                "ADMIN_API_KEY not set — admin endpoints and SSE stream are unprotected"
            )

        geoip_path = Path(self.geoip_db_path)
        if not geoip_path.exists():
            logger.warning(
                "GeoIP database not found at %s — geolocation will be unavailable",
                geoip_path,
            )

        cowrie_path = Path(self.cowrie_log_path)
        if not cowrie_path.exists():
            logger.warning(
                "Cowrie log not found at %s — ingestion will wait for file creation",
                cowrie_path,
            )

        if not self.virustotal_api_key:
            logger.info("VIRUSTOTAL_API_KEY not set — malware enrichment disabled")

        if not self.abuseipdb_api_key:
            logger.info("ABUSEIPDB_API_KEY not set — IP reputation lookups disabled")


settings = Settings()
