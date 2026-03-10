import asyncio
import json
from fastapi import APIRouter
from sse_starlette.sse import EventSourceResponse

router = APIRouter()

# Simple in-memory event bus for SSE
subscribers: list[asyncio.Queue] = []


def publish_event(event_type: str, data: dict):
    """Publish an event to all connected SSE clients."""
    message = json.dumps(data)
    for queue in subscribers:
        queue.put_nowait({"event": event_type, "data": message})


@router.get("/events")
async def event_stream():
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
