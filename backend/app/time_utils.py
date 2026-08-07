"""Timezone helpers for local dashboard reporting windows."""

from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from app.config import settings


def _local_zone() -> ZoneInfo:
    try:
        return ZoneInfo(settings.local_timezone)
    except ZoneInfoNotFoundError:
        return ZoneInfo("UTC")


def local_midnight_utc_naive(now: datetime | None = None) -> datetime:
    """Return local midnight converted to the naive UTC format stored in SQLite."""
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    local_start = current.astimezone(_local_zone()).replace(
        hour=0,
        minute=0,
        second=0,
        microsecond=0,
    )
    return local_start.astimezone(timezone.utc).replace(tzinfo=None)
