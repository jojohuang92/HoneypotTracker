"""Tests for /api/attempts endpoints."""

from tests.conftest import make_attempt, seed_attempts, NOW


class TestListAttempts:
    def test_empty_db(self, client, db_session):
        resp = client.get("/api/attempts")
        assert resp.status_code == 200
        data = resp.json()
        assert data["items"] == []
        assert data["total"] == 0
        assert data["page"] == 1
        assert data["pages"] == 1

    def test_pagination(self, client, db_session):
        seed_attempts(db_session, count=10)
        resp = client.get("/api/attempts?page=1&limit=3")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["items"]) == 3
        assert data["total"] == 10
        assert data["pages"] == 4

    def test_filter_by_country(self, client, db_session):
        make_attempt(db_session, src_ip="1.1.1.1", country_code="US", session_id="s1")
        make_attempt(db_session, src_ip="2.2.2.2", country_code="CN", session_id="s2")
        make_attempt(db_session, src_ip="3.3.3.3", country_code="US", session_id="s3")

        resp = client.get("/api/attempts?country=US")
        data = resp.json()
        assert data["total"] == 2
        assert all(i["country_code"] == "US" for i in data["items"])

    def test_filter_by_intent(self, client, db_session):
        make_attempt(db_session, intent="brute_force", session_id="s1")
        make_attempt(db_session, intent="cryptomining", session_id="s2")

        resp = client.get("/api/attempts?intent=cryptomining")
        data = resp.json()
        assert data["total"] == 1
        assert data["items"][0]["intent"] == "cryptomining"

    def test_filter_by_ip(self, client, db_session):
        make_attempt(db_session, src_ip="5.5.5.5", session_id="s1")
        make_attempt(db_session, src_ip="6.6.6.6", session_id="s2")

        resp = client.get("/api/attempts?ip=5.5.5.5")
        data = resp.json()
        assert data["total"] == 1
        assert data["items"][0]["src_ip"] == "5.5.5.5"

    def test_filter_by_event_id(self, client, db_session):
        make_attempt(db_session, event_id="cowrie.login.failed", session_id="s1")
        make_attempt(db_session, event_id="cowrie.command.input", session_id="s2")

        resp = client.get("/api/attempts?event_id=cowrie.command.input")
        data = resp.json()
        assert data["total"] == 1
        assert data["items"][0]["event_id"] == "cowrie.command.input"

    def test_order_by_timestamp_desc(self, client, db_session):
        attempts = seed_attempts(db_session, count=3)
        resp = client.get("/api/attempts")
        items = resp.json()["items"]
        # Most recent first
        assert items[0]["id"] == attempts[0].id


class TestGetAttempt:
    def test_found(self, client, db_session):
        a = make_attempt(db_session)
        resp = client.get(f"/api/attempts/{a.id}")
        assert resp.status_code == 200
        assert resp.json()["id"] == a.id

    def test_not_found(self, client, db_session):
        resp = client.get("/api/attempts/99999")
        assert resp.status_code == 404


class TestRecentAttempts:
    def test_returns_limited(self, client, db_session):
        seed_attempts(db_session, count=5)
        resp = client.get("/api/attempts/recent?limit=2")
        assert resp.status_code == 200
        assert len(resp.json()) == 2


class TestFilterOptions:
    def test_returns_distinct_values(self, client, db_session):
        make_attempt(db_session, country_code="US", country_name="United States",
                     intent="brute_force", event_id="cowrie.login.failed", session_id="s1")
        make_attempt(db_session, country_code="CN", country_name="China",
                     intent="cryptomining", event_id="cowrie.command.input", session_id="s2")

        resp = client.get("/api/attempts/filter-options")
        assert resp.status_code == 200
        data = resp.json()
        codes = [c["code"] for c in data["countries"]]
        assert "US" in codes
        assert "CN" in codes
        assert "cowrie.login.failed" in data["events"]
        assert "cryptomining" in data["intents"]
