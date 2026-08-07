"""Push alerts for high-signal honeypot events via ntfy and/or Discord.

Fire-and-forget like the Splunk forwarder: failures are logged, never raised,
so an alerting outage can never stall log ingestion. Repeat alerts for the
same key (same IP, same file, ...) are suppressed by an in-memory cooldown.

Alert triggers:
- successful login (an attacker got a shell)
- captured file upload/download (malware dropped)
- VirusTotal verdict at or above ``alert_vt_min_positives`` engines
- first session ever seen from a country
"""

import asyncio
import logging
import time

import httpx

from app.config import settings

logger = logging.getLogger(__name__)

# alert key → time.monotonic() of the last alert sent for it
_last_sent: dict[str, float] = {}

# Countries already seen, lazily seeded from the sessions table on first use.
# None means "not seeded yet".
_known_countries: set[str] | None = None


def _enabled() -> bool:
    return bool(settings.ntfy_url or settings.discord_webhook_url)


def _should_send(key: str) -> bool:
    """True if no alert for this key was sent within the cooldown window."""
    now = time.monotonic()
    cooldown = settings.alert_cooldown_minutes * 60
    last = _last_sent.get(key)
    if last is not None and (now - last) < cooldown:
        return False
    _last_sent[key] = now
    # Bound memory over long uptimes
    if len(_last_sent) > 10_000:
        expired = [k for k, v in _last_sent.items() if (now - v) >= cooldown]
        for k in expired:
            del _last_sent[k]
    return True


async def send_alert(title: str, message: str, priority: str = "default") -> None:
    """Deliver an alert to every configured channel. Never raises."""
    if settings.ntfy_url:
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.post(
                    settings.ntfy_url,
                    content=message.encode("utf-8"),
                    headers={"Title": title, "Priority": priority, "Tags": "honeypot"},
                )
            if resp.status_code >= 400:
                logger.warning(f"ntfy alert returned {resp.status_code}: {resp.text[:200]}")
        except Exception as e:
            logger.warning(f"ntfy alert failed: {e}")

    if settings.discord_webhook_url:
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.post(
                    settings.discord_webhook_url,
                    json={"content": f"**{title}**\n{message}"},
                )
            if resp.status_code >= 400:
                logger.warning(f"Discord alert returned {resp.status_code}: {resp.text[:200]}")
        except Exception as e:
            logger.warning(f"Discord alert failed: {e}")


def _load_known_countries() -> set[str]:
    from app.database import SessionLocal
    from app.models import Session

    db = SessionLocal()
    try:
        rows = (
            db.query(Session.country_name)
            .filter(Session.country_name.isnot(None), Session.country_name != "")
            .distinct()
            .all()
        )
        return {r[0] for r in rows}
    finally:
        db.close()


async def alert_for_event(event: dict) -> None:
    """Inspect an ingestion SSE payload and alert if it is high-signal."""
    if not _enabled():
        return

    etype = event.get("type")
    ip = event.get("src_ip", "unknown")
    country = event.get("country") or ""

    if etype == "login_attempt" and event.get("success"):
        if _should_send(f"login-success:{ip}"):
            await send_alert(
                "Honeypot: successful login",
                f"{ip} ({country or 'unknown country'}) logged in as "
                f"'{event.get('username', '?')}'",
                priority="high",
            )

    elif etype == "file_download":
        ident = event.get("sha256") or event.get("url") or ip
        if _should_send(f"malware:{ident}"):
            await send_alert(
                "Honeypot: file captured",
                f"{ip} dropped a file\n"
                f"url: {event.get('url') or 'n/a'}\n"
                f"sha256: {event.get('sha256') or 'n/a'}",
                priority="high",
            )

    elif etype == "session_start" and country:
        global _known_countries
        if _known_countries is None:
            _known_countries = await asyncio.to_thread(_load_known_countries)
        if country not in _known_countries:
            _known_countries.add(country)
            if _should_send(f"new-country:{country}"):
                await send_alert(
                    "Honeypot: first attack from new country",
                    f"First session from {country} ({ip})",
                )


async def alert_vt_result(
    sha256: str, positives: int, total: int, filename: str | None = None
) -> None:
    """Alert when VirusTotal flags a captured file as malicious."""
    if not _enabled():
        return
    if positives < settings.alert_vt_min_positives:
        return
    if _should_send(f"vt:{sha256}"):
        await send_alert(
            "Honeypot: VirusTotal flagged captured file",
            f"{filename or sha256[:16]}: {positives}/{total} engines\n"
            f"https://www.virustotal.com/gui/file/{sha256}",
            priority="high",
        )
