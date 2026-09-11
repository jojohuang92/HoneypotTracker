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


class TestProtocolAndPortFilters:
    def test_filter_by_protocol_case_insensitive(self, client, db_session):
        make_attempt(db_session, protocol="ssh", dst_port=22, session_id="s1")
        make_attempt(db_session, protocol="telnet", dst_port=23, session_id="s2")

        data = client.get("/api/attempts?protocol=TELNET").json()
        assert data["total"] == 1
        assert data["items"][0]["protocol"] == "telnet"

    def test_filter_by_port(self, client, db_session):
        make_attempt(db_session, protocol="ssh", dst_port=22, session_id="s1")
        make_attempt(db_session, protocol="telnet", dst_port=23, session_id="s2")

        assert client.get("/api/attempts?port=23").json()["total"] == 1
        assert client.get("/api/attempts?port=22&port=23").json()["total"] == 2
        assert client.get("/api/attempts?port=abc").status_code == 422

    def test_filter_options_include_protocols(self, client, db_session):
        make_attempt(db_session, protocol="ssh", session_id="s1")
        make_attempt(db_session, protocol="telnet", session_id="s2")
        assert client.get("/api/attempts/filter-options").json()["protocols"] == ["ssh", "telnet"]


class TestExportCsv:
    def test_export_matches_filters_and_order(self, client, db_session):
        from datetime import timedelta
        make_attempt(db_session, src_ip="1.1.1.1", country_code="US", session_id="s1",
                     timestamp=NOW - timedelta(hours=2))
        make_attempt(db_session, src_ip="2.2.2.2", country_code="CN", session_id="s2",
                     timestamp=NOW - timedelta(hours=1))
        make_attempt(db_session, src_ip="3.3.3.3", country_code="US", session_id="s3",
                     event_id="cowrie.command.input", command="uname -a",
                     username=None, password=None, timestamp=NOW)

        resp = client.get("/api/attempts/export.csv?country=US")

        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/csv")
        assert 'attachment; filename="attempts-' in resp.headers["content-disposition"]
        lines = resp.text.strip().splitlines()
        assert lines[0].startswith("timestamp,sensor_id,session_id,event_id,src_ip")
        assert len(lines) == 3
        assert lines[1].split(",")[4] == "3.3.3.3"   # newest first
        assert lines[2].split(",")[4] == "1.1.1.1"
        assert "uname -a" in lines[1]
        assert "2025-06-15T12:00:00Z" in lines[1]

    def test_export_neutralises_spreadsheet_formulas(self, client, db_session):
        make_attempt(db_session, event_id="cowrie.command.input", session_id="s1",
                     command="=HYPERLINK(\"http://evil\")", username=None, password=None)
        make_attempt(db_session, session_id="s2", username="-root", password="+1")

        text = client.get("/api/attempts/export.csv").text
        assert "'=HYPERLINK" in text
        assert ",'-root,'+1," in text

    def test_export_empty(self, client, db_session):
        text = client.get("/api/attempts/export.csv").text
        assert text.strip().splitlines() == [
            "timestamp,sensor_id,session_id,event_id,src_ip,src_port,dst_port,protocol,"
            "country_code,country_name,city,username,password,command,success,intent,mitre_id"
        ]

    def test_export_row_cap(self, client, db_session, monkeypatch):
        from app.routers import attempts as attempts_router
        monkeypatch.setattr(attempts_router, "EXPORT_MAX_ROWS", 3)
        monkeypatch.setattr(attempts_router, "EXPORT_CHUNK", 2)
        seed_attempts(db_session, count=5)

        lines = client.get("/api/attempts/export.csv").text.strip().splitlines()
        assert len(lines) == 4  # header + cap
