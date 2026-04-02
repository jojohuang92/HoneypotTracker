"""Tests for the AbuseIPDB service."""

from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

import pytest
from sqlalchemy import create_engine, event as sa_event
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import IPScore
from app.services.abuseipdb import get_cached_score, fetch_and_cache_score, CACHE_TTL


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})

    @sa_event.listens_for(engine, "connect")
    def _pragma(conn, _):
        cur = conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    Base.metadata.create_all(bind=engine)
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    yield session
    session.close()
    engine.dispose()


class TestGetCachedScore:
    def test_returns_fresh_cache(self, db):
        score = IPScore(ip="1.2.3.4", abuse_score=80, fetched_at=datetime.utcnow())
        db.add(score)
        db.commit()

        result = get_cached_score(db, "1.2.3.4")
        assert result is not None
        assert result.abuse_score == 80

    def test_returns_none_for_stale(self, db):
        score = IPScore(
            ip="1.2.3.4", abuse_score=80,
            fetched_at=datetime.utcnow() - timedelta(days=8),
        )
        db.add(score)
        db.commit()

        result = get_cached_score(db, "1.2.3.4")
        assert result is None

    def test_returns_none_when_missing(self, db):
        assert get_cached_score(db, "1.2.3.4") is None


class TestFetchAndCacheScore:
    @patch("app.services.abuseipdb.settings")
    def test_no_api_key_returns_none(self, mock_settings, db):
        mock_settings.abuseipdb_api_key = ""
        result = fetch_and_cache_score(db, "1.2.3.4")
        assert result is None

    @patch("app.services.abuseipdb.httpx")
    @patch("app.services.abuseipdb.settings")
    def test_successful_fetch(self, mock_settings, mock_httpx, db):
        mock_settings.abuseipdb_api_key = "test-key"
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "data": {
                "abuseConfidenceScore": 95,
                "isp": "Shady ISP",
                "usageType": "Data Center/Web Hosting/Transit",
                "totalReports": 100,
            }
        }
        mock_resp.raise_for_status = MagicMock()
        mock_httpx.get.return_value = mock_resp

        result = fetch_and_cache_score(db, "1.2.3.4")
        assert result is not None
        assert result.abuse_score == 95
        assert result.isp == "Shady ISP"
        assert result.total_reports == 100

        # Verify it's persisted
        cached = db.query(IPScore).filter_by(ip="1.2.3.4").first()
        assert cached.abuse_score == 95

    @patch("app.services.abuseipdb.httpx")
    @patch("app.services.abuseipdb.settings")
    def test_api_error_returns_none(self, mock_settings, mock_httpx, db):
        mock_settings.abuseipdb_api_key = "test-key"
        mock_httpx.get.side_effect = Exception("Connection timeout")

        result = fetch_and_cache_score(db, "1.2.3.4")
        assert result is None
        assert db.query(IPScore).count() == 0
