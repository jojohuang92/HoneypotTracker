import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.config import settings
from app.database import engine, Base
from app.rate_limit import limiter
from app.routers import attempts, stats, geo, malware, stream, admin, viewers, ips, profile, search, replay
from app.services.log_ingestion import tail_cowrie_log
from app.services.ip_lookup import auto_lookup_ips
from app.services.abuse_reporter import auto_report_ips
from app.services.vt_reporter import auto_report_files

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings.validate_startup()
    Base.metadata.create_all(bind=engine)

    # Start Cowrie log ingestion as a background task
    ingestion_task = asyncio.create_task(tail_cowrie_log(settings.cowrie_log_path))
    logger.info("Cowrie log ingestion task started")

    # Start automatic IP lookup service
    ip_lookup_task = asyncio.create_task(auto_lookup_ips())
    logger.info("Automatic IP lookup task started")

    # Start auto-reporting services
    abuse_report_task = asyncio.create_task(auto_report_ips())
    logger.info("AbuseIPDB auto-reporter started")

    vt_report_task = asyncio.create_task(auto_report_files())
    logger.info("VirusTotal auto-reporter started")

    yield

    # Shutdown: cancel background tasks
    for task in (ingestion_task, ip_lookup_task, abuse_report_task, vt_report_task):
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


app = FastAPI(
    title="Honeypot Tracker API",
    description="Real-time honeypot attack monitoring and analysis",
    version="1.0.0",
    lifespan=lifespan,
)

# Rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type", "X-Admin-Key"],
)

app.include_router(attempts.router, prefix="/api/attempts", tags=["Attempts"])
app.include_router(stats.router, prefix="/api/stats", tags=["Statistics"])
app.include_router(geo.router, prefix="/api/geo", tags=["Geolocation"])
app.include_router(malware.router, prefix="/api/malware", tags=["Malware"])
app.include_router(stream.router, prefix="/api/stream", tags=["Real-time"])
app.include_router(ips.router, prefix="/api/ips", tags=["IPs"])
app.include_router(admin.router, prefix="/api/admin", tags=["Admin"])
app.include_router(viewers.router, prefix="/api/stats", tags=["Statistics"])
app.include_router(profile.router, prefix="/api/profile", tags=["Attacker Profile"])
app.include_router(search.router, prefix="/api/search", tags=["Search"])
app.include_router(replay.router, prefix="/api/replay", tags=["Session Replay"])


@app.get("/api/health")
def health_check():
    return {"status": "ok", "service": "honeypot-tracker"}
