"""Tag attacking IPs with infrastructure context from free, keyless sources.

Two sources, both chosen because they cost nothing and need no account, so
they run on every deployment rather than only where a key was configured:

- **Shodan InternetDB** (``https://internetdb.shodan.io/<ip>``): what the
  attacker's own host exposes — open ports, product CPEs, hostnames, known
  CVEs — plus Shodan's tags (``vpn``, ``proxy``, ``tor``, ``cloud``,
  ``scanner``, ``compromised``, ``honeypot``, ...). A brute-forcer whose host
  runs an EOL OpenSSH with public CVEs is very likely a compromised box, which
  is a different thing from a scanning service, and the tag says which.
- **Tor bulk exit list** (``check.torproject.org``): authoritative for exit
  nodes. Blocking one blocks every Tor user, so a blocklist consumer wants to
  know, and the true origin is unknowable, so the IP is a weaker indicator.

Lookups run in a background worker like the AbuseIPDB scorer, one request a
second, with the result cached for ``CACHE_TTL``. An IP that InternetDB has
never seen answers 404; that is recorded too (``found`` False) so the worker
does not ask again until the TTL lapses.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session as DBSession

from app.config import settings
from app.database import SessionLocal
from app.models import Attempt, IPIntel

logger = logging.getLogger(__name__)

INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"
TOR_EXIT_LIST_URL = "https://check.torproject.org/torbulkexitlist"

CACHE_TTL = timedelta(days=7)
TOR_REFRESH = timedelta(hours=1)

SCAN_INTERVAL = 60        # seconds between passes over the attempts table
API_DELAY = 1.0           # InternetDB asks for roughly one request a second
BATCH_LIMIT = 300         # IPs per pass, so a backlog cannot starve the loop
FAILURE_BACKOFF = 3600    # seconds before retrying an IP whose lookup errored
ERROR_COOLOFF = 300       # pause after a 429 or a connection failure

# Tags worth surfacing in a feed comment or a table chip: they change how a
# consumer should read the indicator. Everything else InternetDB emits is kept
# in the row but not promoted.
NOTABLE_TAGS = (
    "tor", "vpn", "proxy", "cloud", "cdn", "scanner", "honeypot",
    "compromised", "malware", "c2", "iot", "eol-os", "eol-product",
)

# ip → time.monotonic() of the last failed lookup
_failed_ips: dict[str, float] = {}

# Latest Tor exit list, and when it was fetched. Empty until the first
# successful fetch; ``None`` for the timestamp means never fetched.
_tor_exits: set[str] = set()
_tor_fetched_at: datetime | None = None


@dataclass
class IntelSummary:
    """What the API exposes per IP: promoted tags and the raw detail."""

    ip: str
    tags: list[str] = field(default_factory=list)
    open_ports: list[int] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)
    cpes: list[str] = field(default_factory=list)
    vulns: list[str] = field(default_factory=list)
    is_tor: bool = False
    fetched_at: datetime | None = None


# ---------------------------------------------------------------------------
# Failure backoff (mirrors ip_lookup)
# ---------------------------------------------------------------------------

def _recently_failed(ip: str) -> bool:
    failed_at = _failed_ips.get(ip)
    return failed_at is not None and (time.monotonic() - failed_at) < FAILURE_BACKOFF


def _mark_failed(ip: str) -> None:
    _failed_ips[ip] = time.monotonic()
    if len(_failed_ips) > 10_000:
        now = time.monotonic()
        for stale in [k for k, v in _failed_ips.items() if (now - v) >= FAILURE_BACKOFF]:
            del _failed_ips[stale]


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _loads(raw: str | None) -> list:
    if not raw:
        return []
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return []
    return value if isinstance(value, list) else []


def parse_tor_list(body: str) -> set[str]:
    """One address per line; anything that is not an IP address is ignored."""
    exits: set[str] = set()
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            ipaddress.ip_address(line)
        except ValueError:
            continue
        exits.add(line)
    return exits


def parse_internetdb(data: dict) -> dict:
    """Normalise an InternetDB document to the columns stored.

    Defensive about types: the fields are documented as arrays, but a feed
    this code does not control gets validated, not trusted.
    """
    def strs(key: str) -> list[str]:
        value = data.get(key)
        if not isinstance(value, list):
            return []
        return [str(v)[:200] for v in value if isinstance(v, (str, int))][:100]

    ports_raw = data.get("ports")
    ports: list[int] = []
    if isinstance(ports_raw, list):
        for p in ports_raw:
            if isinstance(p, int) and 0 < p < 65536:
                ports.append(p)
    return {
        "tags": sorted({t.lower() for t in strs("tags")}),
        "ports": sorted(set(ports))[:200],
        "hostnames": strs("hostnames"),
        "cpes": strs("cpes"),
        "vulns": sorted(set(strs("vulns"))),
    }


def promoted_tags(tags: list[str], is_tor: bool) -> list[str]:
    """The tags a consumer should see, in a stable order; Tor from the exit
    list wins over Shodan's own ``tor`` tag so the two never disagree."""
    out = [t for t in NOTABLE_TAGS if t in tags and t != "tor"]
    if is_tor or "tor" in tags:
        out.insert(0, "tor")
    return out


def summarize(row: IPIntel | None, ip: str) -> IntelSummary:
    if row is None:
        return IntelSummary(ip=ip)
    tags = _loads(row.tags)
    return IntelSummary(
        ip=ip,
        tags=promoted_tags(tags, bool(row.is_tor)),
        open_ports=[p for p in _loads(row.ports) if isinstance(p, int)],
        hostnames=[str(h) for h in _loads(row.hostnames)],
        cpes=[str(c) for c in _loads(row.cpes)],
        vulns=[str(v) for v in _loads(row.vulns)],
        is_tor=bool(row.is_tor),
        fetched_at=row.fetched_at,
    )


def intel_for_ips(db: DBSession, ips: list[str]) -> dict[str, IntelSummary]:
    """Batch-load summaries; IPs with no row are simply absent."""
    if not ips:
        return {}
    out: dict[str, IntelSummary] = {}
    # SQLite caps bound parameters; chunk to stay well under it.
    for i in range(0, len(ips), 500):
        chunk = ips[i:i + 500]
        for row in db.query(IPIntel).filter(IPIntel.ip.in_(chunk)).all():
            out[row.ip] = summarize(row, row.ip)
    return out


# ---------------------------------------------------------------------------
# Fetching
# ---------------------------------------------------------------------------

class LookupThrottled(Exception):
    """InternetDB answered 429 or was unreachable — pause the whole pass."""


def fetch_internetdb(ip: str) -> dict | None:
    """One InternetDB lookup. ``None`` means InternetDB has no record.

    Raises LookupThrottled for conditions that are about the service rather
    than this IP, so the caller backs off instead of burning the whole batch.
    """
    try:
        resp = httpx.get(INTERNETDB_URL.format(ip=ip), timeout=10,
                         headers={"Accept": "application/json"})
    except httpx.HTTPError as exc:
        raise LookupThrottled(str(exc)) from exc
    if resp.status_code == 404:
        return None
    if resp.status_code == 429:
        raise LookupThrottled("429")
    resp.raise_for_status()
    data = resp.json()
    if not isinstance(data, dict):
        raise ValueError("unexpected InternetDB payload")
    return parse_internetdb(data)


def store_intel(db: DBSession, ip: str, parsed: dict | None,
                now: datetime | None = None) -> IPIntel:
    now = now or datetime.utcnow()
    row = IPIntel(
        ip=ip,
        found=parsed is not None,
        tags=json.dumps(parsed["tags"]) if parsed else None,
        ports=json.dumps(parsed["ports"]) if parsed else None,
        hostnames=json.dumps(parsed["hostnames"]) if parsed else None,
        cpes=json.dumps(parsed["cpes"]) if parsed else None,
        vulns=json.dumps(parsed["vulns"]) if parsed else None,
        is_tor=ip in _tor_exits,
        fetched_at=now,
    )
    db.merge(row)
    db.commit()
    return row


def _lookup_and_store(ip: str) -> IPIntel | None:
    db = SessionLocal()
    try:
        return store_intel(db, ip, fetch_internetdb(ip))
    finally:
        db.close()


def fetch_tor_exits() -> set[str]:
    resp = httpx.get(TOR_EXIT_LIST_URL, timeout=20)
    resp.raise_for_status()
    exits = parse_tor_list(resp.text)
    if not exits:
        raise ValueError("Tor exit list was empty")
    return exits


def apply_tor_flags(db: DBSession, exits: set[str]) -> int:
    """Reconcile stored rows with a fresh exit list. Returns rows changed."""
    changed = 0
    flagged = db.query(IPIntel).filter(IPIntel.is_tor.is_(True)).all()
    for row in flagged:
        if row.ip not in exits:
            row.is_tor = False
            changed += 1
    known = db.query(IPIntel.ip).all()
    to_flag = [ip for (ip,) in known if ip in exits]
    if to_flag:
        for i in range(0, len(to_flag), 500):
            rows = db.query(IPIntel).filter(IPIntel.ip.in_(to_flag[i:i + 500])).all()
            for row in rows:
                if not row.is_tor:
                    row.is_tor = True
                    changed += 1
    db.commit()
    return changed


def _refresh_tor() -> int:
    global _tor_exits, _tor_fetched_at
    exits = fetch_tor_exits()
    _tor_exits = exits
    _tor_fetched_at = datetime.utcnow()
    db = SessionLocal()
    try:
        return apply_tor_flags(db, exits)
    finally:
        db.close()


def is_tor_exit(ip: str) -> bool:
    return ip in _tor_exits


# ---------------------------------------------------------------------------
# Worker
# ---------------------------------------------------------------------------

def _pending_ips(db: DBSession, limit: int) -> list[str]:
    """IPs with no fresh row, newest attackers first.

    Two indexed queries rather than one ordered aggregate: grouping the whole
    attempts table by IP to sort on last-seen costs about a second per pass
    on a million rows, while a distinct over the last day plus an unordered
    distinct over the rest both answer from the src_ip index instantly.
    """
    fresh_cutoff = datetime.utcnow() - CACHE_TTL
    fresh = select(IPIntel.ip).where(IPIntel.fetched_at >= fresh_cutoff)

    recent = (
        db.query(Attempt.src_ip)
        .filter(Attempt.timestamp >= datetime.utcnow() - timedelta(days=1))
        .filter(~Attempt.src_ip.in_(fresh))
        .distinct()
        .limit(limit)
        .all()
    )
    pending = [r[0] for r in recent]
    if len(pending) < limit:
        seen = set(pending)
        older = (
            db.query(Attempt.src_ip)
            .filter(~Attempt.src_ip.in_(fresh))
            .distinct()
            .limit(limit)
            .all()
        )
        for (ip,) in older:
            if ip not in seen and len(pending) < limit:
                pending.append(ip)
                seen.add(ip)
    return pending


async def ip_intel_worker():
    """Keep ip_intel current: Tor list hourly, InternetDB for every new IP."""
    if not settings.ip_intel_enabled:
        logger.info("IP intel enrichment disabled by configuration")
        return

    logger.info("Starting IP intel worker (InternetDB + Tor exit list)")

    while True:
        try:
            if (_tor_fetched_at is None
                    or datetime.utcnow() - _tor_fetched_at >= TOR_REFRESH):
                try:
                    changed = await asyncio.to_thread(_refresh_tor)
                    logger.info("Tor exit list refreshed: %d exits, %d rows updated",
                                len(_tor_exits), changed)
                except Exception as exc:
                    logger.warning("Tor exit list refresh failed: %s", exc)

            db = SessionLocal()
            try:
                pending = await asyncio.to_thread(_pending_ips, db, BATCH_LIMIT)
            finally:
                db.close()

            if pending:
                logger.info("IP intel: %d IPs to look up", len(pending))

            for ip in pending:
                if _recently_failed(ip):
                    continue
                try:
                    row = await asyncio.to_thread(_lookup_and_store, ip)
                except LookupThrottled as exc:
                    logger.warning("InternetDB unavailable (%s) — pausing %ds",
                                   exc, ERROR_COOLOFF)
                    await asyncio.sleep(ERROR_COOLOFF)
                    break
                except Exception as exc:
                    logger.warning("IP intel lookup failed for %s: %s", ip, exc)
                    _mark_failed(ip)
                else:
                    if row is not None and row.found:
                        logger.debug("IP intel for %s: tags=%s ports=%s",
                                     ip, row.tags, row.ports)
                await asyncio.sleep(API_DELAY)

        except Exception as exc:
            logger.error("IP intel worker error: %s", exc, exc_info=True)

        await asyncio.sleep(SCAN_INTERVAL)
