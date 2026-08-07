"""Tests for /api/stats/mitre and /api/meta/honeypot."""

from tests.conftest import make_attempt


class TestMitreMatrix:
    def test_empty_when_no_attempts(self, client, db_session):
        resp = client.get("/api/stats/mitre")
        assert resp.status_code == 200
        data = resp.json()
        assert data["tactics"] == []
        assert data["grand_total"] == 0

    def test_groups_techniques_by_tactic(self, client, db_session):
        # T1110 → credential-access; T1082 → discovery; T1053 → persistence
        for _ in range(10):
            make_attempt(db_session, mitre_id="T1110")
        for _ in range(5):
            make_attempt(db_session, mitre_id="T1082", session_id="s-082")
        make_attempt(db_session, mitre_id="T1053", session_id="s-053")

        resp = client.get("/api/stats/mitre")
        data = resp.json()

        tactic_ids = [t["tactic_id"] for t in data["tactics"]]
        # MITRE Navigator order: persistence comes before credential-access which comes before discovery
        assert tactic_ids == ["persistence", "credential-access", "discovery"]
        assert data["grand_total"] == 16

        creds = next(t for t in data["tactics"] if t["tactic_id"] == "credential-access")
        assert creds["total"] == 10
        assert creds["techniques"][0]["mitre_id"] == "T1110"
        assert creds["techniques"][0]["technique_name"] == "Brute Force"
        assert creds["techniques"][0]["count"] == 10

    def test_falls_back_to_parent_technique(self, client, db_session):
        # T1003.008 is a sub-technique; should map via its parent T1003 → credential-access
        make_attempt(db_session, mitre_id="T1003.008")
        resp = client.get("/api/stats/mitre")
        data = resp.json()
        tactic_ids = [t["tactic_id"] for t in data["tactics"]]
        assert "credential-access" in tactic_ids

    def test_drops_unknown_technique_ids(self, client, db_session):
        # Unmapped ID — should not raise and should not inject a fake tactic
        make_attempt(db_session, mitre_id="T9999")
        resp = client.get("/api/stats/mitre")
        data = resp.json()
        assert data["tactics"] == []
        assert data["grand_total"] == 0

    def test_techniques_sorted_by_count_within_tactic(self, client, db_session):
        # All discovery techniques with different counts
        for _ in range(3):
            make_attempt(db_session, mitre_id="T1082")
        for _ in range(7):
            make_attempt(db_session, mitre_id="T1083", session_id="s-083")
        make_attempt(db_session, mitre_id="T1057", session_id="s-057")

        resp = client.get("/api/stats/mitre")
        discovery = next(t for t in resp.json()["tactics"] if t["tactic_id"] == "discovery")
        counts = [t["count"] for t in discovery["techniques"]]
        assert counts == sorted(counts, reverse=True)


class TestHoneypotMeta:
    def test_returns_label(self, client, monkeypatch):
        from app.config import settings
        monkeypatch.setattr(settings, "honeypot_label", "SF Pi")

        resp = client.get("/api/meta/honeypot")
        assert resp.status_code == 200
        assert resp.json() == {"label": "SF Pi"}

    def test_does_not_expose_coordinates(self, client):
        resp = client.get("/api/meta/honeypot")
        data = resp.json()
        assert "latitude" not in data
        assert "longitude" not in data
