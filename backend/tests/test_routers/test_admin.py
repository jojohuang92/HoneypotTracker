"""Tests for /api/admin endpoints."""

from unittest.mock import patch

from tests.conftest import make_attempt, make_session


ADMIN_KEY = "test-admin-secret"


class TestAdminAuth:
    @patch("app.routers.admin.settings")
    def test_missing_header_returns_422(self, mock_settings, client, db_session):
        mock_settings.admin_api_key = ADMIN_KEY
        resp = client.get("/api/admin/private-ips")
        assert resp.status_code == 422

    @patch("app.routers.admin.settings")
    def test_wrong_key_returns_403(self, mock_settings, client, db_session):
        mock_settings.admin_api_key = ADMIN_KEY
        resp = client.get("/api/admin/private-ips", headers={"X-Admin-Key": "wrong"})
        assert resp.status_code == 403

    @patch("app.routers.admin.settings")
    def test_no_configured_key_returns_403(self, mock_settings, client, db_session):
        mock_settings.admin_api_key = ""
        resp = client.get("/api/admin/private-ips", headers={"X-Admin-Key": "anything"})
        assert resp.status_code == 403


class TestListPrivateIPs:
    @patch("app.routers.admin.settings")
    def test_lists_private_ips(self, mock_settings, client, db_session):
        mock_settings.admin_api_key = ADMIN_KEY
        make_attempt(db_session, src_ip="192.168.1.1", session_id="s1")
        make_attempt(db_session, src_ip="8.8.8.8", session_id="s2")

        resp = client.get("/api/admin/private-ips", headers={"X-Admin-Key": ADMIN_KEY})
        assert resp.status_code == 200
        data = resp.json()
        assert "192.168.1.1" in data["private_ips"]
        assert "8.8.8.8" not in data["private_ips"]


class TestDeletePrivateIPs:
    @patch("app.routers.admin.settings")
    def test_deletes_private_ip_data(self, mock_settings, client, db_session):
        mock_settings.admin_api_key = ADMIN_KEY
        make_attempt(db_session, src_ip="10.0.0.1", session_id="s-priv")
        make_session(db_session, src_ip="10.0.0.1", session_id="s-priv")
        make_attempt(db_session, src_ip="8.8.8.8", session_id="s-pub")

        resp = client.delete("/api/admin/private-ips", headers={"X-Admin-Key": ADMIN_KEY})
        assert resp.status_code == 200
        data = resp.json()
        assert data["attempts_deleted"] == 1
        assert data["sessions_deleted"] == 1

        # Public data should still exist
        resp = client.get("/api/attempts")
        assert resp.json()["total"] == 1

    @patch("app.routers.admin.settings")
    def test_no_private_ips(self, mock_settings, client, db_session):
        mock_settings.admin_api_key = ADMIN_KEY
        make_attempt(db_session, src_ip="8.8.8.8")

        resp = client.delete("/api/admin/private-ips", headers={"X-Admin-Key": ADMIN_KEY})
        assert resp.status_code == 200
        assert resp.json()["deleted"] == 0
