"""Shared test fixtures: in-memory SQLite database and FastAPI TestClient."""

from datetime import datetime, timedelta

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, Session as SASession

from app.database import Base, get_db
from app.models import Attempt, CapturedFile, Session, IPScore, PageView


# ---------------------------------------------------------------------------
# Database fixtures
#
# In-memory SQLite uses a per-connection database.  We use a *single*
# connection shared by both the seed helpers (db_session) and the
# TestClient (via the dependency override).  This ensures they see
# the same data.
# ---------------------------------------------------------------------------

@pytest.fixture()
def db_engine():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(engine, "connect")
    def _set_pragmas(dbapi_conn, _rec):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture()
def _shared_connection(db_engine):
    """A single raw DBAPI connection reused for the whole test."""
    connection = db_engine.connect()
    yield connection
    connection.close()


@pytest.fixture()
def db_session(_shared_connection):
    """Session for seeding data in tests — uses the shared connection."""
    Session = sessionmaker(bind=_shared_connection)
    session = Session()
    yield session
    session.close()


# ---------------------------------------------------------------------------
# FastAPI TestClient (no background tasks)
# ---------------------------------------------------------------------------

@pytest.fixture()
def client(_shared_connection):
    """Create a TestClient that shares the same DB connection as db_session."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from app.routers import attempts, stats, geo, malware, admin, viewers, ips, profile, search, replay

    TestSession = sessionmaker(bind=_shared_connection)

    def _override_get_db():
        db = TestSession()
        try:
            yield db
        finally:
            db.close()

    from app.rate_limit import limiter

    app = FastAPI()
    app.state.limiter = limiter
    app.dependency_overrides[get_db] = _override_get_db

    app.include_router(attempts.router, prefix="/api/attempts")
    app.include_router(stats.router, prefix="/api/stats")
    app.include_router(geo.router, prefix="/api/geo")
    app.include_router(malware.router, prefix="/api/malware")
    app.include_router(ips.router, prefix="/api/ips")
    app.include_router(admin.router, prefix="/api/admin")
    app.include_router(viewers.router, prefix="/api/stats")
    app.include_router(profile.router, prefix="/api/profile")
    app.include_router(search.router, prefix="/api/search")
    app.include_router(replay.router, prefix="/api/replay")

    return TestClient(app)


# ---------------------------------------------------------------------------
# Seed helpers
# ---------------------------------------------------------------------------

NOW = datetime(2025, 6, 15, 12, 0, 0)


def make_attempt(db_session, **overrides) -> Attempt:
    """Insert an Attempt with sensible defaults. Override any field via kwargs."""
    defaults = dict(
        session_id="sess-001",
        event_id="cowrie.login.failed",
        timestamp=NOW,
        src_ip="1.2.3.4",
        src_port=54321,
        dst_port=22,
        protocol="ssh",
        country_code="US",
        country_name="United States",
        city="Los Angeles",
        latitude=34.05,
        longitude=-118.24,
        username="root",
        password="123456",
        intent="brute_force",
        mitre_id="T1110",
    )
    defaults.update(overrides)
    attempt = Attempt(**defaults)
    db_session.add(attempt)
    db_session.commit()
    db_session.refresh(attempt)
    return attempt


def make_session(db_session, **overrides) -> Session:
    defaults = dict(
        session_id="sess-001",
        src_ip="1.2.3.4",
        start_time=NOW,
        protocol="ssh",
        country_code="US",
        country_name="United States",
    )
    defaults.update(overrides)
    sess = Session(**defaults)
    db_session.add(sess)
    db_session.commit()
    db_session.refresh(sess)
    return sess


def make_captured_file(db_session, **overrides) -> CapturedFile:
    defaults = dict(
        session_id="sess-001",
        timestamp=NOW,
        filename="malware.sh",
        sha256="a" * 64,
        url="http://evil.com/malware.sh",
    )
    defaults.update(overrides)
    cf = CapturedFile(**defaults)
    db_session.add(cf)
    db_session.commit()
    db_session.refresh(cf)
    return cf


def make_ip_score(db_session, **overrides) -> IPScore:
    defaults = dict(
        ip="1.2.3.4",
        abuse_score=85,
        isp="Evil ISP",
        usage_type="Data Center",
        total_reports=42,
        fetched_at=NOW,
    )
    defaults.update(overrides)
    score = IPScore(**defaults)
    db_session.add(score)
    db_session.commit()
    db_session.refresh(score)
    return score


def seed_attempts(db_session, count=5, **overrides) -> list[Attempt]:
    """Insert multiple attempts with unique timestamps."""
    attempts = []
    for i in range(count):
        a = make_attempt(
            db_session,
            session_id=f"sess-{i:03d}",
            timestamp=NOW - timedelta(hours=i),
            src_ip=f"1.2.3.{i + 1}",
            **overrides,
        )
        attempts.append(a)
    return attempts
