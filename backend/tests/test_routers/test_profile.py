"""Tests for the attacker profile endpoint."""

from tests.conftest import make_attempt, make_session, make_ip_score, make_captured_file


def test_profile_not_found(client):
    resp = client.get("/api/profile/9.9.9.9")
    assert resp.status_code == 404


def test_profile_basic_info(client, db_session):
    make_attempt(db_session, src_ip="5.5.5.5", country_code="DE", country_name="Germany", city="Berlin")
    make_session(db_session, session_id="sess-001", src_ip="5.5.5.5")

    resp = client.get("/api/profile/5.5.5.5")
    assert resp.status_code == 200
    data = resp.json()
    assert data["src_ip"] == "5.5.5.5"
    assert data["country_code"] == "DE"
    assert data["country_name"] == "Germany"
    assert data["total_attempts"] == 1
    assert data["total_sessions"] == 1


def test_profile_counts(client, db_session):
    ip = "6.6.6.6"
    make_attempt(db_session, src_ip=ip, event_id="cowrie.login.failed", session_id="s1")
    make_attempt(db_session, src_ip=ip, event_id="cowrie.command.input", command="whoami", session_id="s1")
    make_attempt(db_session, src_ip=ip, event_id="cowrie.command.input", command="id", session_id="s1")
    make_session(db_session, session_id="s1", src_ip=ip)
    make_session(db_session, session_id="s2", src_ip=ip)

    resp = client.get(f"/api/profile/{ip}")
    data = resp.json()
    assert data["total_attempts"] == 3
    assert data["total_commands"] == 2
    assert data["total_sessions"] == 2


def test_profile_intent_breakdown(client, db_session):
    ip = "7.7.7.7"
    make_attempt(db_session, src_ip=ip, intent="recon", session_id="s1")
    make_attempt(db_session, src_ip=ip, intent="recon", session_id="s1")
    make_attempt(db_session, src_ip=ip, intent="brute_force", session_id="s1")

    resp = client.get(f"/api/profile/{ip}")
    data = resp.json()
    intents = {i["intent"]: i["count"] for i in data["intents"]}
    assert intents["recon"] == 2
    assert intents["brute_force"] == 1


def test_profile_top_commands(client, db_session):
    ip = "8.8.8.1"
    make_attempt(db_session, src_ip=ip, event_id="cowrie.command.input", command="whoami", session_id="s1")
    make_attempt(db_session, src_ip=ip, event_id="cowrie.command.input", command="whoami", session_id="s1")
    make_attempt(db_session, src_ip=ip, event_id="cowrie.command.input", command="id", session_id="s1")

    resp = client.get(f"/api/profile/{ip}")
    data = resp.json()
    cmds = {c["command"]: c["count"] for c in data["top_commands"]}
    assert cmds["whoami"] == 2
    assert cmds["id"] == 1


def test_profile_credentials(client, db_session):
    ip = "10.10.10.1"
    make_attempt(db_session, src_ip=ip, username="root", password="root", session_id="s1")
    make_attempt(db_session, src_ip=ip, username="root", password="root", session_id="s1")
    make_attempt(db_session, src_ip=ip, username="admin", password="admin", session_id="s1")

    resp = client.get(f"/api/profile/{ip}")
    data = resp.json()
    creds = {f"{c['username']}:{c['password']}": c["count"] for c in data["top_credentials"]}
    assert creds["root:root"] == 2
    assert creds["admin:admin"] == 1


def test_profile_abuse_score(client, db_session):
    ip = "11.11.11.11"
    make_attempt(db_session, src_ip=ip, session_id="s1")
    make_ip_score(db_session, ip=ip, abuse_score=95, isp="Bad ISP")

    resp = client.get(f"/api/profile/{ip}")
    data = resp.json()
    assert data["abuse_score"] == 95
    assert data["isp"] == "Bad ISP"


def test_profile_timeline(client, db_session):
    ip = "12.12.12.12"
    from datetime import datetime
    make_attempt(db_session, src_ip=ip, timestamp=datetime(2025, 6, 1, 10, 0), session_id="s1")
    make_attempt(db_session, src_ip=ip, timestamp=datetime(2025, 6, 1, 14, 0), session_id="s1")
    make_attempt(db_session, src_ip=ip, timestamp=datetime(2025, 6, 2, 8, 0), session_id="s1")

    resp = client.get(f"/api/profile/{ip}")
    data = resp.json()
    buckets = {t["bucket"]: t["count"] for t in data["timeline"]}
    assert buckets["2025-06-01"] == 2
    assert buckets["2025-06-02"] == 1


def test_profile_sessions_list(client, db_session):
    ip = "13.13.13.13"
    make_attempt(db_session, src_ip=ip, session_id="s1")
    make_session(db_session, session_id="s1", src_ip=ip)
    make_session(db_session, session_id="s2", src_ip=ip)

    resp = client.get(f"/api/profile/{ip}")
    data = resp.json()
    session_ids = [s["session_id"] for s in data["sessions"]]
    assert "s1" in session_ids
    assert "s2" in session_ids
