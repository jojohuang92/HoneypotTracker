"""Tests for the fleet view, cross-sensor overlap, threat scoring, campaigns,
credential analytics, and the sensor_id migration."""

from datetime import datetime, timedelta

from sqlalchemy import create_engine, text

from app.migrations import run_migrations
from app.services.threat_score import score_ip
from tests.conftest import make_attempt, make_captured_file, make_sensor, NOW


class TestSensorsEndpoint:
    def test_lists_sensors_with_activity(self, client, db_session):
        make_sensor(db_session, sensor_id="pi", label="Pi", is_local=True, country_code="US")
        make_sensor(db_session, sensor_id="acer", label="Acer", country_code="TW")
        make_attempt(db_session, sensor_id="pi", src_ip="1.2.3.4", protocol="ssh",
                     timestamp=datetime.utcnow())
        make_attempt(db_session, sensor_id="acer", src_ip="1.2.3.5", protocol="telnet",
                     session_id="s2", timestamp=datetime.utcnow())

        data = client.get("/api/sensors").json()
        by_id = {s["sensor_id"]: s for s in data}
        assert by_id["pi"]["total_attempts"] == 1
        assert by_id["acer"]["protocol_breakdown"] == {"telnet": 1}
        # Local sensor sorts first so the hub is always the top row.
        assert data[0]["is_local"] is True

    def test_coarse_sensor_hides_city(self, client, db_session):
        make_sensor(db_session, sensor_id="acer", city="Taipei",
                    location_precision="country")
        row = next(s for s in client.get("/api/sensors").json() if s["sensor_id"] == "acer")
        assert row["city"] is None
        assert row["country_code"] == "TW"

    def test_status_reflects_staleness(self, client, db_session):
        make_sensor(db_session, sensor_id="fresh", last_heartbeat_at=datetime.utcnow())
        make_sensor(db_session, sensor_id="stale",
                    last_heartbeat_at=datetime.utcnow() - timedelta(days=1))
        by_id = {s["sensor_id"]: s for s in client.get("/api/sensors").json()}
        assert by_id["fresh"]["status"] == "online"
        assert by_id["stale"]["status"] == "offline"


class TestOverlap:
    def _seed_two_sensors(self, db_session):
        now = datetime.utcnow()
        # 1.2.3.4 hits both sensors; the others hit only one each.
        for i, (ip, sensor) in enumerate(
            [("1.2.3.4", "pi"), ("1.2.3.4", "acer"), ("1.2.3.5", "pi"), ("1.2.3.6", "acer")]
        ):
            make_attempt(db_session, src_ip=ip, sensor_id=sensor,
                         session_id=f"s{i}", timestamp=now)

    def test_identifies_shared_attackers(self, client, db_session):
        self._seed_two_sensors(db_session)
        data = client.get("/api/sensors/overlap?days=7").json()
        assert data["sensors_reporting"] == 2
        assert data["total_ips"] == 3
        assert data["shared_ips"] == 1
        assert data["overlap_rate"] == 33.33
        assert data["exclusive_by_sensor"] == {"pi": 1, "acer": 1}
        assert data["pairs"][0]["shared_ips"] == 1
        assert data["top_shared"][0]["src_ip"] == "1.2.3.4"

    def test_single_sensor_reports_zero_overlap(self, client, db_session):
        """With one sensor the metric is definitionally zero, and says why."""
        make_attempt(db_session, src_ip="1.2.3.4", sensor_id="pi",
                     timestamp=datetime.utcnow())
        data = client.get("/api/sensors/overlap?days=7").json()
        assert data["sensors_reporting"] == 1
        assert data["shared_ips"] == 0
        assert data["overlap_rate"] == 0.0

    def test_empty_db_does_not_divide_by_zero(self, client, db_session):
        data = client.get("/api/sensors/overlap").json()
        assert data["total_ips"] == 0
        assert data["overlap_rate"] == 0.0


class TestThreatScore:
    def test_low_volume_recon_scores_low(self, client, db_session):
        make_attempt(db_session, src_ip="1.2.3.4", intent="reconnaissance",
                     command="uname -a", event_id="cowrie.command.input")
        score = score_ip(db_session, "1.2.3.4")
        assert score.total < 25
        assert score.level == "low"

    def test_malware_and_breadth_raise_the_score(self, db_session):
        """Same IP, worse behaviour: score and explanation must both grow."""
        quiet = score_ip(db_session, "1.2.3.4")

        for i in range(40):
            make_attempt(db_session, src_ip="1.2.3.4", sensor_id="pi",
                         session_id=f"a{i}", intent="malware_deployment",
                         timestamp=NOW - timedelta(days=i % 20))
        make_attempt(db_session, src_ip="1.2.3.4", sensor_id="acer",
                     session_id="other-sensor", intent="malware_deployment")
        attempt = make_attempt(db_session, src_ip="1.2.3.4", sensor_id="pi",
                               session_id="dl", intent="malware_deployment")
        make_captured_file(db_session, attempt_id=attempt.id, vt_positives=30,
                           vt_total=60, sha256="b" * 64)

        loud = score_ip(db_session, "1.2.3.4")
        assert loud.total > quiet.total
        assert loud.level in ("high", "critical")
        assert loud.components["malware"] > 0
        assert loud.components["breadth"] > 0
        assert any("VT engines" in r for r in loud.reasons)
        assert any("2 sensors" in r for r in loud.reasons)

    def test_unknown_ip_scores_zero(self, db_session):
        score = score_ip(db_session, "9.9.9.9")
        assert score.total == 0
        assert score.level == "low"

    def test_score_is_capped_at_100(self, db_session):
        for i in range(200):
            make_attempt(db_session, src_ip="1.2.3.4", session_id=f"x{i}",
                         intent="sabotage", success=True,
                         timestamp=NOW - timedelta(days=i % 30))
        assert score_ip(db_session, "1.2.3.4").total <= 100

    def test_endpoint_exposes_components(self, client, db_session):
        make_attempt(db_session, src_ip="1.2.3.4", intent="brute_force")
        data = client.get("/api/ips/1.2.3.4/threat").json()
        assert set(data["components"]) == {
            "volume", "persistence", "intent", "reputation", "malware", "breadth"
        }

    def test_ips_list_scores_only_on_request(self, client, db_session):
        make_attempt(db_session, src_ip="1.2.3.4", intent="brute_force")
        plain = client.get("/api/ips").json()[0]
        scored = client.get("/api/ips?scored=true").json()[0]
        assert plain["threat_score"] is None
        assert scored["threat_score"] is not None


class TestCampaigns:
    def test_shared_credential_list_groups_ips(self, client, db_session):
        now = datetime.utcnow()
        creds = [("root", "admin1"), ("admin", "admin2"), ("test", "admin3")]
        for ip in ("1.2.3.4", "1.2.3.5"):
            for i, (user, pw) in enumerate(creds):
                make_attempt(db_session, src_ip=ip, username=user, password=pw,
                             session_id=f"{ip}-{i}", timestamp=now)

        campaigns = client.get("/api/campaigns?days=7").json()
        cred = [c for c in campaigns if c["kind"] == "credentials"]
        assert cred, "expected a credential campaign"
        assert cred[0]["ip_count"] == 2
        assert sorted(cred[0]["ips"]) == ["1.2.3.4", "1.2.3.5"]

    def test_lone_ip_is_not_a_campaign(self, client, db_session):
        now = datetime.utcnow()
        for i, pw in enumerate(["a", "b", "c"]):
            make_attempt(db_session, src_ip="1.2.3.4", username="root", password=pw,
                         session_id=f"solo-{i}", timestamp=now)
        assert client.get("/api/campaigns?days=7").json() == []

    def test_shared_payload_groups_ips(self, client, db_session):
        now = datetime.utcnow()
        for ip in ("1.2.3.4", "1.2.3.5"):
            attempt = make_attempt(db_session, src_ip=ip, session_id=f"dl-{ip}",
                                   timestamp=now, username=None, password=None)
            make_captured_file(db_session, attempt_id=attempt.id, sha256="c" * 64,
                               session_id=f"dl-{ip}")
        payload = [c for c in client.get("/api/campaigns?days=7").json()
                   if c["kind"] == "payload"]
        assert payload and payload[0]["ip_count"] == 2

    def test_multi_sensor_campaign_ranks_first(self, client, db_session):
        now = datetime.utcnow()
        # Campaign A: 2 IPs, both sensors. Campaign B: 3 IPs, one sensor.
        for ip, sensor in (("1.2.3.4", "pi"), ("1.2.3.5", "acer")):
            for i in range(3):
                make_attempt(db_session, src_ip=ip, sensor_id=sensor,
                             username="root", password=f"shared{i}",
                             session_id=f"A-{ip}-{i}", timestamp=now)
        for ip in ("1.2.4.1", "1.2.4.2", "1.2.4.3"):
            for i in range(3):
                make_attempt(db_session, src_ip=ip, sensor_id="pi",
                             username="admin", password=f"other{i}",
                             session_id=f"B-{ip}-{i}", timestamp=now)

        campaigns = client.get("/api/campaigns?days=7").json()
        assert len(campaigns[0]["sensors"]) == 2

    def test_sensor_filter_scopes_correlation(self, client, db_session):
        now = datetime.utcnow()
        for ip in ("1.2.3.4", "1.2.3.5"):
            for i in range(3):
                make_attempt(db_session, src_ip=ip, sensor_id="acer",
                             username="root", password=f"p{i}",
                             session_id=f"{ip}-{i}", timestamp=now)
        assert client.get("/api/campaigns?days=7&sensor=acer").json() != []
        assert client.get("/api/campaigns?days=7&sensor=pi").json() == []


class TestCredentialAnalytics:
    def test_usernames_report_ip_breadth(self, client, db_session):
        make_attempt(db_session, src_ip="1.2.3.4", username="root", session_id="a")
        make_attempt(db_session, src_ip="1.2.3.5", username="root", session_id="b")
        make_attempt(db_session, src_ip="1.2.3.4", username="oracle", session_id="c")

        rows = client.get("/api/stats/usernames").json()
        top = rows[0]
        assert top["value"] == "root"
        assert top["count"] == 2
        assert top["ip_count"] == 2

    def test_passwords_endpoint(self, client, db_session):
        make_attempt(db_session, src_ip="1.2.3.4", password="123456")
        rows = client.get("/api/stats/passwords").json()
        assert rows[0]["value"] == "123456"

    def test_sensor_scope_applies(self, client, db_session):
        make_attempt(db_session, src_ip="1.2.3.4", username="root", sensor_id="pi")
        make_attempt(db_session, src_ip="1.2.3.5", username="guest", sensor_id="acer",
                     session_id="b")
        rows = client.get("/api/stats/usernames?sensor=acer").json()
        assert [r["value"] for r in rows] == ["guest"]


class TestHourlyDistribution:
    def test_returns_all_24_hours(self, client, db_session):
        make_attempt(db_session, src_ip="1.2.3.4", timestamp=datetime.utcnow())
        rows = client.get("/api/stats/hourly?days=30").json()
        assert len(rows) == 24
        assert [r["hour"] for r in rows] == list(range(24))
        assert sum(r["count"] for r in rows) == 1

    def test_unknown_sensor_timezone_falls_back(self, client, db_session):
        make_sensor(db_session, sensor_id="odd", timezone="Not/AZone")
        make_attempt(db_session, src_ip="1.2.3.4", sensor_id="odd",
                     timestamp=datetime.utcnow())
        rows = client.get("/api/stats/hourly?sensor=odd").json()
        assert sum(r["count"] for r in rows) == 1


class TestMigration:
    def _legacy_db(self, tmp_path):
        """A database shaped like one deployed before multi-sensor support."""
        engine = create_engine(f"sqlite:///{tmp_path}/legacy.db")
        with engine.begin() as conn:
            conn.execute(text(
                "CREATE TABLE attempts (id INTEGER PRIMARY KEY, session_id VARCHAR,"
                " event_id VARCHAR, timestamp DATETIME, src_ip VARCHAR, protocol VARCHAR)"
            ))
            conn.execute(text(
                "CREATE TABLE sessions (id INTEGER PRIMARY KEY, session_id VARCHAR,"
                " src_ip VARCHAR, start_time DATETIME, protocol VARCHAR)"
            ))
            conn.execute(text(
                "CREATE TABLE captured_files (id INTEGER PRIMARY KEY,"
                " attempt_id INTEGER, session_id VARCHAR, timestamp DATETIME,"
                " sha256 VARCHAR)"
            ))
            conn.execute(text(
                "INSERT INTO attempts (session_id, event_id, timestamp, src_ip, protocol)"
                " VALUES ('s1', 'cowrie.login.failed', '2026-01-01', '1.2.3.4', 'ssh')"
            ))
        return engine

    def test_backfills_existing_rows(self, tmp_path):
        engine = self._legacy_db(tmp_path)
        applied = run_migrations(engine, "pi-cerritos")

        assert "attempts.sensor_id" in applied
        with engine.begin() as conn:
            row = conn.execute(text("SELECT sensor_id FROM attempts")).fetchone()
            # Pre-existing rows read back as the hub's own sensor.
            assert row[0] == "pi-cerritos"
        engine.dispose()

    def test_is_idempotent(self, tmp_path):
        engine = self._legacy_db(tmp_path)
        run_migrations(engine, "pi")
        assert run_migrations(engine, "pi") == []
        engine.dispose()

    def test_creates_lookup_indexes(self, tmp_path):
        engine = self._legacy_db(tmp_path)
        run_migrations(engine, "pi")
        with engine.begin() as conn:
            names = {
                r[0] for r in conn.execute(
                    text("SELECT name FROM sqlite_master WHERE type='index'")
                ).fetchall()
            }
        assert "ix_attempts_sensor_id" in names
        engine.dispose()

    def test_indexes_captured_files_attempt_id(self, tmp_path):
        """Threat scoring joins captured_files to attempts on this column.

        Unindexed, SQLite scans every captured file once per matching attempt,
        which took a single-IP score from milliseconds to minutes.
        """
        engine = self._legacy_db(tmp_path)
        run_migrations(engine, "pi")
        with engine.begin() as conn:
            names = {
                r[0] for r in conn.execute(
                    text("SELECT name FROM sqlite_master WHERE type='index'")
                ).fetchall()
            }
        assert "ix_captured_files_attempt_id" in names
        engine.dispose()

    def test_quotes_hostile_sensor_ids(self, tmp_path):
        """Sensor ids are operator input and end up in DDL — must not inject."""
        engine = self._legacy_db(tmp_path)
        run_migrations(engine, "it's-a-sensor")
        with engine.begin() as conn:
            row = conn.execute(text("SELECT sensor_id FROM attempts")).fetchone()
            assert row[0] == "it's-a-sensor"
            # The tables must all still be there.
            tables = {
                r[0] for r in conn.execute(
                    text("SELECT name FROM sqlite_master WHERE type='table'")
                ).fetchall()
            }
        assert {"attempts", "sessions", "captured_files"} <= tables
        engine.dispose()
