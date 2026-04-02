"""Tests for /api/ips endpoints."""

from tests.conftest import make_attempt, make_ip_score


class TestListUniqueIPs:
    def test_empty(self, client, db_session):
        resp = client.get("/api/ips")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_ranked_by_count(self, client, db_session):
        # IP with 2 attempts
        make_attempt(db_session, src_ip="1.1.1.1", session_id="s1")
        make_attempt(db_session, src_ip="1.1.1.1", session_id="s2")
        # IP with 1 attempt
        make_attempt(db_session, src_ip="2.2.2.2", session_id="s3")

        resp = client.get("/api/ips")
        data = resp.json()
        assert len(data) == 2
        assert data[0]["src_ip"] == "1.1.1.1"
        assert data[0]["count"] == 2
        assert data[1]["src_ip"] == "2.2.2.2"
        assert data[1]["count"] == 1

    def test_includes_abuse_score_when_cached(self, client, db_session):
        make_attempt(db_session, src_ip="1.1.1.1")
        make_ip_score(db_session, ip="1.1.1.1", abuse_score=95)

        resp = client.get("/api/ips")
        data = resp.json()
        assert data[0]["abuse_score"] == 95
        assert data[0]["isp"] == "Evil ISP"

    def test_null_abuse_score_when_not_cached(self, client, db_session):
        make_attempt(db_session, src_ip="1.1.1.1")
        resp = client.get("/api/ips")
        assert resp.json()[0]["abuse_score"] is None
