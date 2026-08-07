import asyncio
import fcntl
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.config import DATA_DIR, settings
from app.database import engine, Base
from app.rate_limit import limiter
from app.routers import attempts, stats, geo, malware, stream, admin, viewers, ips, profile, search, replay, meta, export
from app.services.log_ingestion import tail_cowrie_log
from app.services.ip_lookup import auto_lookup_ips
from app.services.abuse_reporter import auto_report_ips
from app.services.retention import retention_worker
from app.services.vt_reporter import auto_report_files

logger = logging.getLogger(__name__)


def _acquire_background_lock():
    if not settings.enable_background_tasks:
        logger.info("Background tasks disabled by configuration")
        return None

    lock_path = Path(DATA_DIR) / "background.lock"
    lock_file = lock_path.open("w")
    try:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        lock_file.write(str(lock_path))
        lock_file.flush()
        return lock_file
    except BlockingIOError:
        lock_file.close()
        logger.warning("Background task lock is held by another process; skipping workers")
        return None


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings.validate_startup()
    Base.metadata.create_all(bind=engine)
    background_lock = _acquire_background_lock()
    background_tasks: list[asyncio.Task] = []

    if background_lock:
        # Start Cowrie log ingestion as a background task
        ingestion_task = asyncio.create_task(tail_cowrie_log(settings.cowrie_log_path))
        background_tasks.append(ingestion_task)
        logger.info("Cowrie log ingestion task started")

        # Start automatic IP lookup service
        ip_lookup_task = asyncio.create_task(auto_lookup_ips())
        background_tasks.append(ip_lookup_task)
        logger.info("Automatic IP lookup task started")

        # Start auto-reporting services
        abuse_report_task = asyncio.create_task(auto_report_ips())
        background_tasks.append(abuse_report_task)
        logger.info("AbuseIPDB auto-reporter started")

        vt_report_task = asyncio.create_task(auto_report_files())
        background_tasks.append(vt_report_task)
        logger.info("VirusTotal auto-reporter started")

        retention_task = asyncio.create_task(retention_worker())
        background_tasks.append(retention_task)
        logger.info("Retention worker started")

    yield

    # Shutdown: cancel background tasks
    for task in background_tasks:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
    if background_lock:
        fcntl.flock(background_lock.fileno(), fcntl.LOCK_UN)
        background_lock.close()


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
app.include_router(meta.router, prefix="/api/meta", tags=["Metadata"])
app.include_router(export.router, prefix="/api/export", tags=["IOC Export"])


@app.get("/api/health")
def health_check():
    """Liveness plus basic operational signals (DB size, ingestion lag)."""
    from sqlalchemy import func

    from app.database import SessionLocal
    from app.models import Attempt

    info: dict = {"status": "ok", "service": "honeypot-tracker"}
    try:
        db = SessionLocal()
        try:
            info["total_attempts"] = db.query(func.count(Attempt.id)).scalar() or 0
            last = db.query(func.max(Attempt.timestamp)).scalar()
            info["last_event_at"] = f"{last.isoformat()}Z" if last else None
        finally:
            db.close()

        db_url = settings.database_url
        if db_url.startswith("sqlite:///"):
            db_file = Path(db_url[len("sqlite:///"):])
            if db_file.exists():
                info["db_size_bytes"] = db_file.stat().st_size
    except Exception:
        logger.exception("Health check DB probe failed")
        info["status"] = "degraded"
    return info
