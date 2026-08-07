import asyncio
import json
import secrets

from fastapi import APIRouter, Header, HTTPException, Request
from sse_starlette.sse import EventSourceResponse

from app.config import settings
from app.rate_limit import limiter

router = APIRouter()

# Simple in-memory event bus for SSE
subscribers: list[asyncio.Queue] = []
MAX_QUEUE_SIZE = 1000


def publish_event(event_type: str, data: dict):
    """Publish an event to all connected SSE clients."""
    message = json.dumps(data)
    for queue in list(subscribers):
        if queue.full():
            try:
                queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
        queue.put_nowait({"event": event_type, "data": message})


@router.get("/events")
@limiter.limit(settings.rate_limit_stream)
async def event_stream(request: Request, x_admin_key: str = Header(None)):
    """SSE endpoint. Requires the X-Admin-Key header when ADMIN_API_KEY is set.
    Open access in dev mode (no key configured).

    The key is passed in a header (not a URL query parameter) so it does not
    leak into proxy/access logs, browser history, or Referer headers."""
    if settings.admin_api_key:
        if not x_admin_key or not secrets.compare_digest(
            x_admin_key, settings.admin_api_key
        ):
            raise HTTPException(status_code=403, detail="Invalid or missing admin key")

    queue: asyncio.Queue = asyncio.Queue(maxsize=MAX_QUEUE_SIZE)
    subscribers.append(queue)

    async def generate():
        try:
            while True:
                event = await queue.get()
                yield event
        finally:
            if queue in subscribers:
                subscribers.remove(queue)

    return EventSourceResponse(generate())


@router.get("/live")
@limiter.limit(settings.rate_limit_stream)
async def public_live_stream(request: Request):
    """Public read-only SSE stream — only forwards new_attack events."""
    queue: asyncio.Queue = asyncio.Queue(maxsize=MAX_QUEUE_SIZE)
    subscribers.append(queue)

    async def generate():
        try:
            while True:
                event = await queue.get()
                if event.get("event") == "new_attack":
                    yield event
        finally:
            if queue in subscribers:
                subscribers.remove(queue)

    return EventSourceResponse(generate())
