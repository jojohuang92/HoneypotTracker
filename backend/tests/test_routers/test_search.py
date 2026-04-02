"""Tests for the search endpoint."""

from tests.conftest import make_attempt


def test_search_requires_query(client):
    resp = client.get("/api/search")
    assert resp.status_code == 422


def test_search_by_ip(client, db_session):
    make_attempt(db_session, src_ip="99.99.99.99", session_id="s1")
    make_attempt(db_session, src_ip="1.1.1.1", session_id="s2")

    resp = client.get("/api/search?q=99.99")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert data["items"][0]["src_ip"] == "99.99.99.99"
    assert data["query"] == "99.99"


def test_search_by_command(client, db_session):
    make_attempt(db_session, src_ip="1.1.1.1", event_id="cowrie.command.input", command="cat /etc/passwd", session_id="s1")
    make_attempt(db_session, src_ip="1.1.1.2", event_id="cowrie.command.input", command="whoami", session_id="s2")

    resp = client.get("/api/search?q=passwd")
    data = resp.json()
    assert data["total"] == 1
    assert "passwd" in data["items"][0]["command"]


def test_search_by_username(client, db_session):
    make_attempt(db_session, src_ip="1.1.1.1", username="administrator", session_id="s1")
    make_attempt(db_session, src_ip="1.1.1.2", username="root", session_id="s2")

    resp = client.get("/api/search?q=administrator")
    data = resp.json()
    assert data["total"] == 1
    assert data["items"][0]["username"] == "administrator"


def test_search_by_password(client, db_session):
    make_attempt(db_session, src_ip="1.1.1.1", password="supersecret123", session_id="s1")

    resp = client.get("/api/search?q=supersecret")
    data = resp.json()
    assert data["total"] == 1


def test_search_by_country(client, db_session):
    make_attempt(db_session, src_ip="1.1.1.1", country_name="Brazil", session_id="s1")
    make_attempt(db_session, src_ip="1.1.1.2", country_name="Japan", session_id="s2")

    resp = client.get("/api/search?q=Brazil")
    data = resp.json()
    assert data["total"] == 1


def test_search_case_insensitive(client, db_session):
    make_attempt(db_session, src_ip="1.1.1.1", username="Admin", session_id="s1")

    resp = client.get("/api/search?q=admin")
    data = resp.json()
    assert data["total"] == 1


def test_search_limit(client, db_session):
    for i in range(5):
        make_attempt(db_session, src_ip=f"2.2.2.{i}", session_id=f"s{i}", username="testuser")

    resp = client.get("/api/search?q=testuser&limit=3")
    data = resp.json()
    assert data["total"] == 5
    assert len(data["items"]) == 3


def test_search_no_results(client, db_session):
    make_attempt(db_session, src_ip="1.1.1.1", session_id="s1")

    resp = client.get("/api/search?q=nonexistent_xyz")
    data = resp.json()
    assert data["total"] == 0
    assert data["items"] == []
