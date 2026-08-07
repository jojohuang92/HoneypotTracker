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
    # Where Cowrie stores captured files (named by sha256). Needed because
    # Cowrie logs 'outfile' relative to its own working directory.
    cowrie_downloads_dir: str = ""
    geoip_db_path: str = str(DATA_DIR / "GeoLite2-City.mmdb")

    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""

    admin_api_key: str = ""

    # Splunk HEC forwarding — set both URL and token to enable
    splunk_hec_url: str = ""
    splunk_hec_token: str = ""
    splunk_hec_verify_ssl: bool = True

    # Push alerts — set either (or both) to enable
    ntfy_url: str = ""              # full topic URL, e.g. https://ntfy.sh/my-honeypot
    discord_webhook_url: str = ""
    alert_cooldown_minutes: int = 30   # min gap between repeat alerts for the same key
    alert_vt_min_positives: int = 3    # VT engines needed to trigger a malware alert

    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    honeypot_label: str = "Honeypot"
    local_timezone: str = "America/Los_Angeles"
    enable_background_tasks: bool = True

    # Days of raw data (attempts, sessions, page views) to keep. 0 = keep
    # forever. Daily aggregates are always written and never pruned.
    retention_days: int = 0

    # Rate limiting
    rate_limit_default: str = "60/minute"
    rate_limit_stream: str = "10/minute"

    model_config = {"env_file": ".env", "extra": "ignore"}

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
                "ADMIN_API_KEY not set — admin endpoints are disabled and /api/stream/events is open"
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
