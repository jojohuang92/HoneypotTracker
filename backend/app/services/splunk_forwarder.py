"""Forward enriched honeypot events to Splunk via the HTTP Event Collector (HEC).

Fire-and-forget: never blocks or raises to the caller, so a Splunk outage
cannot stall Cowrie log ingestion.
"""

import logging
import time

import httpx

from app.config import settings

logger = logging.getLogger(__name__)


def _enabled() -> bool:
    return bool(settings.splunk_hec_url and settings.splunk_hec_token)


async def send(event: dict) -> None:
    if not _enabled():
        return

    url = f"{settings.splunk_hec_url.rstrip('/')}/services/collector/event"
    headers = {"Authorization": f"Splunk {settings.splunk_hec_token}"}
    body = {
        "event": event,
        "sourcetype": "cowrie:honeypot",
        "source": "honeypot-tracker",
        "time": time.time(),
    }

    try:
        async with httpx.AsyncClient(
            timeout=5, verify=settings.splunk_hec_verify_ssl
        ) as client:
            resp = await client.post(url, headers=headers, json=body)
        if resp.status_code >= 400:
            logger.warning(
                f"Splunk HEC returned {resp.status_code}: {resp.text[:200]}"
            )
    except Exception as e:
        logger.warning(f"Splunk HEC send failed: {e}")
