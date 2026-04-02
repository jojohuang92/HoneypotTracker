"""Session replay endpoint — returns chronological events for a session."""

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session as DBSession
from sqlalchemy import asc

from app.database import get_db
from app.models import Attempt, Session
from app.rate_limit import limiter
from app.schemas import AttemptOut

router = APIRouter()


@router.get("/{session_id}", response_model=list[AttemptOut])
@limiter.limit("30/minute")
def get_session_replay(
    request: Request,
    session_id: str,
    db: DBSession = Depends(get_db),
):
    """Return all events for a session in chronological order for replay."""
    session = db.query(Session).filter(Session.session_id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    events = (
        db.query(Attempt)
        .filter(Attempt.session_id == session_id)
        .order_by(asc(Attempt.timestamp))
        .all()
    )

    return events
