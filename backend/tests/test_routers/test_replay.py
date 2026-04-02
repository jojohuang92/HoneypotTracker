"""Tests for the session replay endpoint."""

from datetime import datetime

from tests.conftest import make_attempt, make_session


def test_replay_session_not_found(client):
    resp = client.get("/api/replay/nonexistent-session")
    assert resp.status_code == 404


def test_replay_returns_events_in_order(client, db_session):
    make_session(db_session, session_id="replay-001", src_ip="1.2.3.4")
    make_attempt(db_session, session_id="replay-001", src_ip="1.2.3.4",
                 timestamp=datetime(2025, 6, 15, 12, 0, 3), event_id="cowrie.command.input", command="id")
    make_attempt(db_session, session_id="replay-001", src_ip="1.2.3.4",
                 timestamp=datetime(2025, 6, 15, 12, 0, 1), event_id="cowrie.login.failed")
    make_attempt(db_session, session_id="replay-001", src_ip="1.2.3.4",
                 timestamp=datetime(2025, 6, 15, 12, 0, 2), event_id="cowrie.login.success")

    resp = client.get("/api/replay/replay-001")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 3
    # Should be chronological
    assert data[0]["event_id"] == "cowrie.login.failed"
    assert data[1]["event_id"] == "cowrie.login.success"
    assert data[2]["event_id"] == "cowrie.command.input"


def test_replay_only_returns_session_events(client, db_session):
    make_session(db_session, session_id="replay-002", src_ip="1.2.3.4")
    make_session(db_session, session_id="replay-003", src_ip="1.2.3.5")
    make_attempt(db_session, session_id="replay-002", src_ip="1.2.3.4")
    make_attempt(db_session, session_id="replay-003", src_ip="1.2.3.5")

    resp = client.get("/api/replay/replay-002")
    data = resp.json()
    assert len(data) == 1
    assert data[0]["session_id"] == "replay-002"


def test_replay_empty_session(client, db_session):
    make_session(db_session, session_id="replay-empty", src_ip="1.2.3.4")

    resp = client.get("/api/replay/replay-empty")
    assert resp.status_code == 200
    assert resp.json() == []
