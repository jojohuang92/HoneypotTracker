"""Tests for /api/geo endpoints."""

from tests.conftest import make_attempt


class TestGeoPins:
    def test_empty(self, client, db_session):
        resp = client.get("/api/geo/pins")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_clusters_by_ip(self, client, db_session):
        from datetime import timedelta
        from tests.conftest import NOW
        # Same IP, different timestamps → one pin with count=2
        make_attempt(db_session, src_ip="1.1.1.1", latitude=34.0, longitude=-118.0,
                     session_id="s1", timestamp=NOW)
        make_attempt(db_session, src_ip="1.1.1.1", latitude=34.0, longitude=-118.0,
                     session_id="s2", timestamp=NOW - timedelta(hours=1))
        # Different IP → separate pin
        make_attempt(db_session, src_ip="2.2.2.2", latitude=51.5, longitude=-0.1,
                     session_id="s3", timestamp=NOW - timedelta(hours=2))

        resp = client.get("/api/geo/pins")
        data = resp.json()
        assert len(data) == 2

        by_ip = {p["latest_src_ip"]: p for p in data}
        assert by_ip["1.1.1.1"]["count"] == 2
        assert by_ip["2.2.2.2"]["count"] == 1

    def test_excludes_null_lat(self, client, db_session):
        make_attempt(db_session, latitude=None, longitude=None)
        resp = client.get("/api/geo/pins")
        assert resp.json() == []

    def test_limit(self, client, db_session):
        for i in range(5):
            make_attempt(db_session, src_ip=f"1.1.1.{i+1}", latitude=float(i), longitude=float(i),
                         session_id=f"s{i}")
        resp = client.get("/api/geo/pins?limit=2")
        assert len(resp.json()) == 2
