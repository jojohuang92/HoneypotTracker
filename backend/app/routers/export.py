"""Public IOC export endpoints: plaintext blocklist, CSV, and STIX 2.1 bundle."""

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from sqlalchemy.orm import Session as DBSession

from app.config import settings
from app.database import get_db
from app.rate_limit import limiter
from app.services.ioc_export import (
    build_blocklist,
    build_csv,
    build_stix_bundle,
    collect_iocs,
)

router = APIRouter()


def _iocs(db: DBSession, days: int):
    return collect_iocs(db, cutoff=datetime.utcnow() - timedelta(days=days))


@router.get("/blocklist.txt", response_class=PlainTextResponse)
@limiter.limit(settings.rate_limit_default)
def blocklist(
    request: Request,
    days: int = Query(30, ge=1, le=365),
    db: DBSession = Depends(get_db),
):
    """Attacker IPs seen in the window, one per line. '#' lines are comments."""
    body = build_blocklist(_iocs(db, days), days=days, generated_at=datetime.utcnow())
    return PlainTextResponse(body)


@router.get("/iocs.csv")
@limiter.limit(settings.rate_limit_default)
def iocs_csv(
    request: Request,
    days: int = Query(30, ge=1, le=365),
    db: DBSession = Depends(get_db),
):
    """All IOC types (ip / sha256 / url) as a flat CSV."""
    body = build_csv(_iocs(db, days))
    return Response(
        content=body,
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="iocs.csv"'},
    )


@router.get("/stix.json")
@limiter.limit(settings.rate_limit_default)
def stix_bundle(
    request: Request,
    days: int = Query(30, ge=1, le=365),
    db: DBSession = Depends(get_db),
):
    """STIX 2.1 bundle of indicators with deterministic ids."""
    bundle = build_stix_bundle(_iocs(db, days), generated_at=datetime.utcnow())
    return JSONResponse(
        content=bundle,
        media_type="application/stix+json",
        headers={"Content-Disposition": 'attachment; filename="stix.json"'},
    )
