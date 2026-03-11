import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import engine, Base
from app.routers import attempts, stats, geo, malware, stream, admin, viewers
from app.services.log_ingestion import tail_cowrie_log

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)

    # Start Cowrie log ingestion as a background task
    ingestion_task = asyncio.create_task(tail_cowrie_log(settings.cowrie_log_path))
    logger.info("Cowrie log ingestion task started")

    yield

    # Shutdown: cancel the ingestion task
    ingestion_task.cancel()
    try:
        await ingestion_task
    except asyncio.CancelledError:
        pass


app = FastAPI(
    title="Honeypot Tracker API",
    description="Real-time honeypot attack monitoring and analysis",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(attempts.router, prefix="/api/attempts", tags=["Attempts"])
app.include_router(stats.router, prefix="/api/stats", tags=["Statistics"])
app.include_router(geo.router, prefix="/api/geo", tags=["Geolocation"])
app.include_router(malware.router, prefix="/api/malware", tags=["Malware"])
app.include_router(stream.router, prefix="/api/stream", tags=["Real-time"])
app.include_router(admin.router, prefix="/api/admin", tags=["Admin"])
app.include_router(viewers.router, prefix="/api/stats", tags=["Statistics"])


@app.get("/api/health")
def health_check():
    return {"status": "ok", "service": "honeypot-tracker"}
