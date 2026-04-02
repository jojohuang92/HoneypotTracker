"""Tests for /api/stats/view and /api/stats/viewers endpoints."""


class TestRecordView:
    def test_records_view(self, client, db_session):
        resp = client.post("/api/stats/view")
        assert resp.status_code == 200
        assert resp.json()["ok"] is True


class TestGetViewers:
    def test_empty(self, client, db_session):
        resp = client.get("/api/stats/viewers")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_views"] == 0
        assert data["unique_visitors"] == 0

    def test_counts_views(self, client, db_session):
        # Record a few views
        client.post("/api/stats/view")
        client.post("/api/stats/view")

        resp = client.get("/api/stats/viewers")
        data = resp.json()
        assert data["total_views"] == 2
