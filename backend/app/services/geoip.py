"""MaxMind GeoLite2 lookup wrapper with graceful fallback."""

import logging
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

try:
    import maxminddb
    HAS_MAXMIND = True
except ImportError:
    HAS_MAXMIND = False
    logger.warning("maxminddb not installed — GeoIP lookups disabled. pip install maxminddb")


@dataclass
class GeoResult:
    country_code: str = ""
    country_name: str = ""
    city: str = ""
    latitude: float = 0.0
    longitude: float = 0.0
    asn: int | None = None
    as_org: str = ""


class GeoIPLookup:
    """Wraps MaxMind .mmdb file. Returns empty GeoResult if DB is missing."""

    def __init__(self, db_path: str):
        self._reader = None
        if not HAS_MAXMIND:
            return
        path = Path(db_path)
        if path.exists():
            try:
                self._reader = maxminddb.open_database(str(path))
                logger.info(f"GeoIP database loaded: {path}")
            except Exception as e:
                logger.warning(f"Failed to open GeoIP database: {e}")
        else:
            logger.warning(f"GeoIP database not found at {path} — lookups will return empty results")

    def lookup(self, ip: str) -> GeoResult:
        """Look up an IP address. Returns empty GeoResult on any failure."""
        if not self._reader:
            return GeoResult()

        # Skip private/reserved IPs
        if ip.startswith(("10.", "172.16.", "192.168.", "127.", "0.")):
            return GeoResult()

        try:
            record = self._reader.get(ip)
            if not record:
                return GeoResult()

            country = record.get("country", {})
            city_data = record.get("city", {})
            location = record.get("location", {})
            traits = record.get("traits", {})

            return GeoResult(
                country_code=country.get("iso_code", ""),
                country_name=country.get("names", {}).get("en", ""),
                city=city_data.get("names", {}).get("en", ""),
                latitude=location.get("latitude", 0.0),
                longitude=location.get("longitude", 0.0),
                asn=traits.get("autonomous_system_number"),
                as_org=traits.get("autonomous_system_organization", ""),
            )
        except Exception:
            return GeoResult()

    def close(self):
        if self._reader:
            self._reader.close()
