from pydantic_settings import BaseSettings
from pathlib import Path

# Resolve paths relative to the backend/ directory, not the working directory
BACKEND_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BACKEND_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)


class Settings(BaseSettings):
    database_url: str = f"sqlite:///{DATA_DIR / 'honeypot.db'}"
    cowrie_log_path: str = "/home/cowrie/cowrie-git/var/log/cowrie/cowrie.json"
    geoip_db_path: str = str(DATA_DIR / "GeoLite2-City.mmdb")

    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""

    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    model_config = {"env_file": ".env"}


settings = Settings()
