"""Metadata about the honeypot deployment (label)."""

from fastapi import APIRouter, Request

from app.config import settings
from app.rate_limit import limiter
from app.schemas import HoneypotMeta

router = APIRouter()


@router.get("/honeypot", response_model=HoneypotMeta)
@limiter.limit("60/minute")
def honeypot_meta(request: Request):
    return HoneypotMeta(label=settings.honeypot_label)
