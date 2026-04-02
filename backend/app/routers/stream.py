import asyncio
import json
import secrets

from fastapi import APIRouter, Query, HTTPException
from sse_starlette.sse import EventSourceResponse

from app.config import settings

router = APIRouter()

# Simple in-memory event bus for SSE
subscribers: list[asyncio.Queue] = []


def publish_event(event_type: str, data: dict):
    """Publish an event to all connected SSE clients."""
    message = json.dumps(data)
    for queue in subscribers:
        queue.put_nowait({"event": event_type, "data": message})


@router.get("/events")
async def event_stream(token: str = Query(None)):
    """SSE endpoint. Requires ?token=<admin_api_key> when ADMIN_API_KEY is set.
    Open access in dev mode (no key configured)."""
    if settings.admin_api_key:
        if not token or not secrets.compare_digest(token, settings.admin_api_key):
            raise HTTPException(status_code=403, detail="Invalid or missing stream token")

    queue: asyncio.Queue = asyncio.Queue()
    subscribers.append(queue)

    async def generate():
        try:
            while True:
                event = await queue.get()
                yield event
        except asyncio.CancelledError:
            subscribers.remove(queue)
            raise

    return EventSourceResponse(generate())
