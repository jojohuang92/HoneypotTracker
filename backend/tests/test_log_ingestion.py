"""Tests for the Cowrie log ingestion pipeline."""

from datetime import datetime
from unittest.mock import patch, MagicMock

import pytest
from sqlalchemy import create_engine, event as sa_event
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import Attempt, CapturedFile, Session
from app.services.log_ingestion import (
    _is_private_ip,
    _parse_timestamp,
    _process_event,
    _increment_session_field,
)
from app.services.geoip import GeoResult


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

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


FAKE_GEO = GeoResult(
    country_code="US",
    country_name="United States",
    city="Los Angeles",
    latitude=34.05,
    longitude=-118.24,
)


def _patch_geoip():
    """Return a mock GeoIPLookup that always returns FAKE_GEO."""
    mock = MagicMock()
    mock.lookup.return_value = FAKE_GEO
    return patch("app.services.log_ingestion.get_geoip", return_value=mock)


# ---------------------------------------------------------------------------
# _is_private_ip
# ---------------------------------------------------------------------------

class TestIsPrivateIP:
    @pytest.mark.parametrize("ip", [
        "10.0.0.1", "10.255.255.255",
        "172.16.0.1", "172.31.255.255",
        "192.168.0.1", "192.168.255.255",
        "127.0.0.1",
    ])
    def test_private(self, ip):
        assert _is_private_ip(ip) is True

    @pytest.mark.parametrize("ip", [
        "8.8.8.8", "1.2.3.4", "45.33.32.156",
    ])
    def test_public(self, ip):
        assert _is_private_ip(ip) is False

    def test_invalid_ip(self):
        assert _is_private_ip("not-an-ip") is False

    def test_empty(self):
        assert _is_private_ip("") is False


# ---------------------------------------------------------------------------
# _parse_timestamp
# ---------------------------------------------------------------------------

class TestParseTimestamp:
    def test_iso_with_z(self):
        dt = _parse_timestamp("2025-01-15T08:23:45.123456Z")
        assert dt == datetime(2025, 1, 15, 8, 23, 45, 123456)
        assert dt.tzinfo is None

    def test_iso_with_offset(self):
        dt = _parse_timestamp("2025-01-15T08:23:45.123456+0000")
        assert dt.year == 2025
        assert dt.tzinfo is None

    def test_malformed_returns_now(self):
        dt = _parse_timestamp("not-a-date")
        # Should return something close to now (within 5 seconds)
        assert (datetime.utcnow() - dt).total_seconds() < 5


# ---------------------------------------------------------------------------
# _process_event — session.connect
# ---------------------------------------------------------------------------

class TestProcessSessionConnect:
    def test_creates_session(self, db):
        event = {
            "eventid": "cowrie.session.connect",
            "session": "abc123",
            "src_ip": "1.2.3.4",
            "timestamp": "2025-06-15T10:00:00Z",
            "protocol": "ssh",
        }
        with _patch_geoip():
            payload, cap_id = _process_event(event, db)

        assert payload is not None
        assert payload["type"] == "session_start"
        assert payload["src_ip"] == "1.2.3.4"
        assert cap_id is None

        sess = db.query(Session).filter_by(session_id="abc123").first()
        assert sess is not None
        assert sess.country_code == "US"

    def test_skips_private_ip(self, db):
        event = {
            "eventid": "cowrie.session.connect",
            "session": "priv",
            "src_ip": "192.168.1.100",
            "timestamp": "2025-06-15T10:00:00Z",
        }
        with _patch_geoip():
            payload, _ = _process_event(event, db)
        assert payload is None
        assert db.query(Session).count() == 0


# ---------------------------------------------------------------------------
# _process_event — login
# ---------------------------------------------------------------------------

class TestProcessLogin:
    def test_failed_login(self, db):
        # Need a session first
        db.add(Session(session_id="s1", src_ip="1.2.3.4",
                       start_time=datetime(2025, 6, 15), protocol="ssh"))
        db.commit()

        event = {
            "eventid": "cowrie.login.failed",
            "session": "s1",
            "src_ip": "1.2.3.4",
            "timestamp": "2025-06-15T10:00:00Z",
            "username": "root",
            "password": "toor",
        }
        with _patch_geoip():
            payload, _ = _process_event(event, db)

        assert payload["type"] == "login_attempt"
        assert payload["success"] is False
        assert payload["username"] == "root"

        attempt = db.query(Attempt).first()
        assert attempt.intent == "brute_force"
        assert attempt.username == "root"

        sess = db.query(Session).filter_by(session_id="s1").first()
        assert sess.login_attempts == 1

    def test_successful_login(self, db):
        db.add(Session(session_id="s1", src_ip="1.2.3.4",
                       start_time=datetime(2025, 6, 15), protocol="ssh"))
        db.commit()

        event = {
            "eventid": "cowrie.login.success",
            "session": "s1",
            "src_ip": "1.2.3.4",
            "timestamp": "2025-06-15T10:00:00Z",
            "username": "root",
            "password": "root",
        }
        with _patch_geoip():
            payload, _ = _process_event(event, db)

        assert payload["success"] is True
        attempt = db.query(Attempt).first()
        assert attempt.success is True


# ---------------------------------------------------------------------------
# _process_event — command.input
# ---------------------------------------------------------------------------

class TestProcessCommand:
    def test_classifies_command(self, db):
        db.add(Session(session_id="s1", src_ip="1.2.3.4",
                       start_time=datetime(2025, 6, 15), protocol="ssh"))
        db.commit()

        event = {
            "eventid": "cowrie.command.input",
            "session": "s1",
            "src_ip": "1.2.3.4",
            "timestamp": "2025-06-15T10:00:00Z",
            "input": "uname -a",
        }
        with _patch_geoip():
            payload, _ = _process_event(event, db)

        assert payload["type"] == "command"
        assert payload["intent"] == "reconnaissance"
        assert payload["command"] == "uname -a"

        sess = db.query(Session).filter_by(session_id="s1").first()
        assert sess.commands_run == 1


# ---------------------------------------------------------------------------
# _process_event — file download
# ---------------------------------------------------------------------------

class TestProcessFileDownload:
    def test_creates_attempt_and_captured_file(self, db):
        db.add(Session(session_id="s1", src_ip="1.2.3.4",
                       start_time=datetime(2025, 6, 15), protocol="ssh"))
        db.commit()

        event = {
            "eventid": "cowrie.session.file_download",
            "session": "s1",
            "src_ip": "1.2.3.4",
            "timestamp": "2025-06-15T10:00:00Z",
            "url": "http://evil.com/malware.sh",
            "shasum": "a" * 64,
            "outfile": "/tmp/malware.sh",
        }
        with _patch_geoip():
            payload, captured_id = _process_event(event, db)

        assert payload["type"] == "file_download"
        assert payload["sha256"] == "a" * 64
        assert captured_id is not None

        cf = db.query(CapturedFile).filter_by(id=captured_id).first()
        assert cf.sha256 == "a" * 64
        assert cf.url == "http://evil.com/malware.sh"

        attempt = db.query(Attempt).first()
        assert attempt.intent == "malware_deployment"

    def test_no_captured_file_without_shasum(self, db):
        db.add(Session(session_id="s1", src_ip="1.2.3.4",
                       start_time=datetime(2025, 6, 15), protocol="ssh"))
        db.commit()

        event = {
            "eventid": "cowrie.session.file_download",
            "session": "s1",
            "src_ip": "1.2.3.4",
            "timestamp": "2025-06-15T10:00:00Z",
            "url": "http://evil.com/x",
            "shasum": "",
        }
        with _patch_geoip():
            _, captured_id = _process_event(event, db)

        assert captured_id is None
        assert db.query(CapturedFile).count() == 0
        # Attempt should still be created
        assert db.query(Attempt).count() == 1


# ---------------------------------------------------------------------------
# _process_event — session.closed
# ---------------------------------------------------------------------------

class TestProcessSessionClosed:
    def test_sets_end_time_and_duration(self, db):
        db.add(Session(session_id="s1", src_ip="1.2.3.4",
                       start_time=datetime(2025, 6, 15, 10, 0, 0), protocol="ssh"))
        db.commit()

        event = {
            "eventid": "cowrie.session.closed",
            "session": "s1",
            "src_ip": "1.2.3.4",
            "timestamp": "2025-06-15T10:05:30Z",
        }
        with _patch_geoip():
            payload, _ = _process_event(event, db)

        assert payload is None  # session.closed doesn't emit SSE

        sess = db.query(Session).filter_by(session_id="s1").first()
        assert sess.end_time == datetime(2025, 6, 15, 10, 5, 30)
        assert sess.duration_secs == 330.0


# ---------------------------------------------------------------------------
# _increment_session_field
# ---------------------------------------------------------------------------

class TestIncrementSessionField:
    def test_increments(self, db):
        db.add(Session(session_id="s1", src_ip="1.2.3.4",
                       start_time=datetime(2025, 6, 15), protocol="ssh",
                       login_attempts=3))
        db.commit()
        _increment_session_field(db, "s1", "login_attempts")
        db.commit()

        sess = db.query(Session).filter_by(session_id="s1").first()
        assert sess.login_attempts == 4

    def test_no_session_is_noop(self, db):
        # Should not raise
        _increment_session_field(db, "nonexistent", "login_attempts")
