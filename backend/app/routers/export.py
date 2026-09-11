"""Public IOC feeds: plaintext blocklist, top attackers, CSV, STIX 2.1.

These endpoints are deliberately unauthenticated — they exist so firewalls,
Pi-holes and threat-intel platforms can subscribe — and they are the
heaviest queries the API serves. Each body is built at most once per
``settings.export_cache_seconds`` and served with ``Cache-Control`` and an
``ETag``, so an edge cache in front of the API (Cloudflare) and the
subscribers' own conditional requests both stop the query from running.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session as DBSession

from app.config import settings
from app.database import get_db
from app.rate_limit import limiter
from app.services.export_cache import CachedBody, export_cache
from app.services.ioc_export import (
    build_blocklist,
    build_csv,
    build_stix_bundle,
    build_top_attackers,
    collect_iocs,
)

router = APIRouter()

DaysQuery = Query(30, ge=1, le=365)


def _iocs(db: DBSession, days: int):
    return collect_iocs(db, cutoff=datetime.utcnow() - timedelta(days=days))


def _http_date(dt: datetime) -> str:
    return dt.strftime("%a, %d %b %Y %H:%M:%S GMT")


def _serve(request: Request, key: tuple, build, media_type: str,
           filename: str | None = None) -> Response:
    """Build (or reuse) a feed body and answer with cache headers.

    A matching ``If-None-Match`` gets a 304 with no body. ``max-age`` equals
    the server-side TTL so an edge cache and this cache expire together.
    """
    ttl = max(0, settings.export_cache_seconds)
    entry: CachedBody = export_cache.get_or_build(key, ttl, build)

    headers = {
        "ETag": entry.etag,
        "Last-Modified": _http_date(entry.built_at),
        "Cache-Control": f"public, max-age={ttl}" if ttl else "no-cache",
        # Feeds are data, not pages: keep them out of search results.
        "X-Robots-Tag": "noindex",
    }
    if filename:
        headers["Content-Disposition"] = f'attachment; filename="{filename}"'

    inm = request.headers.get("if-none-match")
    if inm and entry.etag in [tag.strip() for tag in inm.split(",")]:
        return Response(status_code=304, headers=headers)
    return Response(content=entry.body, media_type=media_type, headers=headers)


@router.get("/blocklist.txt", response_class=PlainTextResponse)
@limiter.limit(settings.rate_limit_default)
def blocklist(
    request: Request,
    days: int = DaysQuery,
    exclude_tor: bool = Query(
        False, description="Drop known Tor exit nodes (see the '# tor_exits' header)"),
    db: DBSession = Depends(get_db),
):
    """Attacker IPs seen in the window, one per line. '#' lines are comments.

    Drop-in for pfSense/OPNsense URL aliases, Pi-hole adlists and fail2ban.
    """
    return _serve(
        request, ("blocklist", days, exclude_tor),
        lambda: build_blocklist(_iocs(db, days), days=days,
                                generated_at=datetime.utcnow(),
                                exclude_tor=exclude_tor).encode(),
        "text/plain; charset=utf-8",
    )


@router.get("/top-attackers.json")
@limiter.limit(settings.rate_limit_default)
def top_attackers(
    request: Request,
    days: int = DaysQuery,
    limit: int = Query(100, ge=1, le=1000),
    db: DBSession = Depends(get_db),
):
    """Most active source IPs in the window, with intent, country and tags."""
    import json

    return _serve(
        request, ("top-attackers", days, limit),
        lambda: json.dumps(build_top_attackers(
            _iocs(db, days), days=days, generated_at=datetime.utcnow(),
            limit=limit)).encode(),
        "application/json",
    )


@router.get("/iocs.csv")
@limiter.limit(settings.rate_limit_default)
def iocs_csv(
    request: Request,
    days: int = DaysQuery,
    db: DBSession = Depends(get_db),
):
    """All IOC types (ip / sha256 / url) as a flat CSV."""
    return _serve(
        request, ("csv", days),
        lambda: build_csv(_iocs(db, days)).encode(),
        "text/csv; charset=utf-8",
        filename="iocs.csv",
    )


@router.get("/stix.json")
@limiter.limit(settings.rate_limit_default)
def stix_bundle(
    request: Request,
    days: int = DaysQuery,
    db: DBSession = Depends(get_db),
):
    """STIX 2.1 bundle of indicators with deterministic ids."""
    import json

    return _serve(
        request, ("stix", days),
        lambda: json.dumps(build_stix_bundle(
            _iocs(db, days), generated_at=datetime.utcnow())).encode(),
        "application/stix+json",
        filename="stix.json",
    )
