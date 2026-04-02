"""Tests for /api/stats endpoints."""

from datetime import datetime, timedelta

from tests.conftest import make_attempt, seed_attempts, NOW


class TestOverview:
    def test_empty_db(self, client, db_session):
        resp = client.get("/api/stats/overview")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_attempts"] == 0
        assert data["unique_ips"] == 0
        assert data["unique_countries"] == 0

    def test_counts(self, client, db_session):
        make_attempt(db_session, src_ip="1.1.1.1", country_code="US", session_id="s1")
        make_attempt(db_session, src_ip="2.2.2.2", country_code="CN", session_id="s2")
        make_attempt(db_session, src_ip="1.1.1.1", country_code="US", session_id="s3")

        resp = client.get("/api/stats/overview")
        data = resp.json()
        assert data["total_attempts"] == 3
        assert data["unique_ips"] == 2
        assert data["unique_countries"] == 2


class TestCountryRankings:
    def test_ordered_desc(self, client, db_session):
        for i in range(3):
            make_attempt(db_session, country_code="US", session_id=f"us-{i}", src_ip=f"1.1.1.{i}")
        make_attempt(db_session, country_code="CN", session_id="cn-0", src_ip="2.2.2.1")

        resp = client.get("/api/stats/countries")
        data = resp.json()
        assert len(data) == 2
        assert data[0]["country_code"] == "US"
        assert data[0]["count"] == 3
        assert data[1]["country_code"] == "CN"
        assert data[1]["count"] == 1

    def test_percentage_present(self, client, db_session):
        make_attempt(db_session, country_code="US")
        resp = client.get("/api/stats/countries")
        assert "percentage" in resp.json()[0]

    def test_limit(self, client, db_session):
        for i, code in enumerate(["US", "CN", "RU", "DE", "BR"]):
            make_attempt(db_session, country_code=code, session_id=f"s-{i}", src_ip=f"1.1.{i}.1")
        resp = client.get("/api/stats/countries?limit=2")
        assert len(resp.json()) == 2


class TestIntentBreakdown:
    def test_includes_description(self, client, db_session):
        make_attempt(db_session, intent="brute_force")
        resp = client.get("/api/stats/intents")
        data = resp.json()
        assert len(data) == 1
        assert data[0]["intent"] == "brute_force"
        assert data[0]["description"] is not None
        assert data[0]["mitre_id"] is not None

    def test_multiple_intents(self, client, db_session):
        make_attempt(db_session, intent="brute_force", session_id="s1")
        make_attempt(db_session, intent="cryptomining", session_id="s2", src_ip="2.2.2.2")
        make_attempt(db_session, intent="cryptomining", session_id="s3", src_ip="3.3.3.3")

        resp = client.get("/api/stats/intents")
        data = resp.json()
        assert len(data) == 2
        # Most frequent first
        assert data[0]["intent"] == "cryptomining"
        assert data[0]["count"] == 2


class TestTopCommands:
    def test_returns_commands(self, client, db_session):
        make_attempt(db_session, command="uname -a", event_id="cowrie.command.input",
                     intent="reconnaissance", session_id="s1")
        make_attempt(db_session, command="uname -a", event_id="cowrie.command.input",
                     intent="reconnaissance", session_id="s2", src_ip="2.2.2.2")

        resp = client.get("/api/stats/commands")
        data = resp.json()
        assert len(data) == 1
        assert data[0]["command"] == "uname -a"
        assert data[0]["count"] == 2

    def test_empty(self, client, db_session):
        resp = client.get("/api/stats/commands")
        assert resp.json() == []


class TestTopCredentials:
    def test_returns_pairs(self, client, db_session):
        make_attempt(db_session, username="root", password="admin", session_id="s1")
        make_attempt(db_session, username="root", password="admin", session_id="s2", src_ip="2.2.2.2")
        make_attempt(db_session, username="admin", password="1234", session_id="s3", src_ip="3.3.3.3")

        resp = client.get("/api/stats/credentials")
        data = resp.json()
        assert len(data) == 2
        assert data[0]["username"] == "root"
        assert data[0]["count"] == 2


class TestTopPorts:
    def test_returns_ports(self, client, db_session):
        make_attempt(db_session, dst_port=22, session_id="s1")
        make_attempt(db_session, dst_port=22, session_id="s2", src_ip="2.2.2.2")
        make_attempt(db_session, dst_port=2222, session_id="s3", src_ip="3.3.3.3")

        resp = client.get("/api/stats/ports")
        data = resp.json()
        assert data[0]["port"] == 22
        assert data[0]["count"] == 2
        assert "percentage" in data[0]


class TestTimeline:
    def test_hourly_buckets(self, client, db_session):
        # Use recent timestamps so they fall within the "days" window
        now = datetime.utcnow()
        h1 = now.replace(minute=15, second=0, microsecond=0)
        h0 = h1 - timedelta(hours=1)
        bucket_h0 = h0.strftime("%Y-%m-%d %H:00")
        bucket_h1 = h1.strftime("%Y-%m-%d %H:00")

        make_attempt(db_session, timestamp=h0, session_id="s1")
        make_attempt(db_session, timestamp=h0.replace(minute=30), session_id="s2", src_ip="2.2.2.2")
        make_attempt(db_session, timestamp=h1, session_id="s3", src_ip="3.3.3.3")

        resp = client.get("/api/stats/timeline?granularity=hour&days=1&tz_offset=0")
        data = resp.json()
        buckets = {b["bucket"]: b["count"] for b in data}
        assert buckets.get(bucket_h0) == 2
        assert buckets.get(bucket_h1) == 1

    def test_daily_buckets(self, client, db_session):
        now = datetime.utcnow()
        today = now.replace(hour=8, minute=0, second=0, microsecond=0)
        yesterday = today - timedelta(days=1)

        make_attempt(db_session, timestamp=yesterday, session_id="s1")
        make_attempt(db_session, timestamp=today, session_id="s2", src_ip="2.2.2.2")

        resp = client.get("/api/stats/timeline?granularity=day&days=7&tz_offset=0")
        data = resp.json()
        buckets = {b["bucket"]: b["count"] for b in data}
        assert buckets.get(yesterday.strftime("%Y-%m-%d")) == 1
        assert buckets.get(today.strftime("%Y-%m-%d")) == 1
