"""Tests for remote sensor ingestion: auth, replay protection, and trust."""

from datetime import datetime, timedelta

import pytest

from app.models import Attempt, Sensor
from app.services import sensor_registry
from tests.conftest import make_sensor


TOKEN = "test-token-abc123"


@pytest.fixture()
def sensor(db_session):
    return make_sensor(db_session, token_hash=sensor_registry.hash_token(TOKEN))


def cowrie_login(session="remote-sess-1", ip="1.2.3.9", ts=None):
    return {
        "eventid": "cowrie.login.failed",
        "session": session,
        "src_ip": ip,
        "username": "root",
        "password": "hunter2",
        "timestamp": (ts or datetime.utcnow()).isoformat() + "Z",
        "protocol": "telnet",
    }


def batch(events, epoch="epoch-1", start_seq=1):
    return {
        "epoch": epoch,
        "events": [{"seq": start_seq + i, "event": e} for i, e in enumerate(events)],
    }


class TestIngestAuth:
    def test_rejects_missing_key(self, client, sensor):
        resp = client.post("/api/ingest", json=batch([cowrie_login()]))
        assert resp.status_code == 422  # header is required

    def test_rejects_bad_key(self, client, sensor):
        resp = client.post(
            "/api/ingest",
            json=batch([cowrie_login()]),
            headers={"X-Sensor-Key": "wrong"},
        )
        assert resp.status_code == 403

    def test_rejects_disabled_sensor(self, client, db_session, sensor):
        sensor.enabled = False
        db_session.commit()
        resp = client.post(
            "/api/ingest",
            json=batch([cowrie_login()]),
            headers={"X-Sensor-Key": TOKEN},
        )
        assert resp.status_code == 403

    def test_accepts_valid_key(self, client, sensor):
        resp = client.post(
            "/api/ingest",
            json=batch([cowrie_login()]),
            headers={"X-Sensor-Key": TOKEN},
        )
        assert resp.status_code == 200
        assert resp.json()["accepted"] == 1


class TestIngestAttribution:
    def test_events_carry_the_sensor_id(self, client, db_session, sensor):
        client.post(
            "/api/ingest",
            json=batch([cowrie_login()]),
            headers={"X-Sensor-Key": TOKEN},
        )
        row = db_session.query(Attempt).filter_by(src_ip="1.2.3.9").first()
        assert row is not None
        assert row.sensor_id == "remote-1"

    def test_sensor_cannot_forge_intent_or_geo(self, client, db_session, sensor):
        """Classification and geolocation are the hub's job, not the sensor's."""
        event = cowrie_login()
        event.update(
            intent="reconnaissance",
            mitre_id="T9999",
            country_name="Narnia",
            latitude=1.0,
            longitude=2.0,
        )
        client.post(
            "/api/ingest",
            json=batch([event]),
            headers={"X-Sensor-Key": TOKEN},
        )
        row = db_session.query(Attempt).filter_by(src_ip="1.2.3.9").first()
        # Hub-side classifier decides: a failed login is brute force.
        assert row.intent == "brute_force"
        assert row.mitre_id == "T1110"
        assert row.country_name != "Narnia"

    def test_updates_liveness(self, client, db_session, sensor):
        client.post(
            "/api/ingest",
            json=batch([cowrie_login()]),
            headers={"X-Sensor-Key": TOKEN},
        )
        db_session.refresh(sensor)
        assert sensor.last_event_at is not None
        assert sensor.last_heartbeat_at is not None


class TestReplayProtection:
    def test_same_batch_twice_counts_once(self, client, db_session, sensor):
        payload = batch([cowrie_login()])
        first = client.post("/api/ingest", json=payload, headers={"X-Sensor-Key": TOKEN})
        second = client.post("/api/ingest", json=payload, headers={"X-Sensor-Key": TOKEN})

        assert first.json()["accepted"] == 1
        assert second.json()["accepted"] == 0
        assert second.json()["skipped"] == 1
        assert db_session.query(Attempt).filter_by(src_ip="1.2.3.9").count() == 1

    def test_advances_high_water_mark(self, client, db_session, sensor):
        client.post(
            "/api/ingest",
            json=batch([cowrie_login("s1"), cowrie_login("s2")]),
            headers={"X-Sensor-Key": TOKEN},
        )
        db_session.refresh(sensor)
        assert sensor.last_seq == 2
        assert sensor.last_epoch == "epoch-1"

    def test_new_epoch_resets_sequence(self, client, db_session, sensor):
        """A rebuilt agent restarts at seq 1 and must not be treated as a replay."""
        client.post(
            "/api/ingest",
            json=batch([cowrie_login("s1")], epoch="epoch-1", start_seq=5),
            headers={"X-Sensor-Key": TOKEN},
        )
        resp = client.post(
            "/api/ingest",
            json=batch(
                [cowrie_login("s2", ip="1.2.3.10")], epoch="epoch-2", start_seq=1
            ),
            headers={"X-Sensor-Key": TOKEN},
        )
        assert resp.json()["accepted"] == 1
        db_session.refresh(sensor)
        assert sensor.last_epoch == "epoch-2"
        assert sensor.last_seq == 1

    def test_oversized_batch_rejected(self, client, sensor):
        events = [cowrie_login(f"s{i}") for i in range(600)]
        resp = client.post(
            "/api/ingest", json=batch(events), headers={"X-Sensor-Key": TOKEN}
        )
        assert resp.status_code == 413


class TestHeartbeat:
    def test_records_telemetry(self, client, db_session, sensor):
        resp = client.post(
            "/api/ingest/heartbeat",
            json={
                "agent_version": "1.0.0",
                "disk_free_bytes": 5_000_000_000,
                "disk_total_bytes": 20_000_000_000,
            },
            headers={"X-Sensor-Key": TOKEN},
        )
        assert resp.status_code == 200
        db_session.refresh(sensor)
        assert sensor.agent_version == "1.0.0"
        assert sensor.disk_free_bytes == 5_000_000_000
        assert sensor.last_heartbeat_at is not None

    def test_requires_key(self, client, sensor):
        resp = client.post("/api/ingest/heartbeat", json={})
        assert resp.status_code == 422


class TestSensorRegistry:
    def test_coords_coarsened_by_precision(self, db_session):
        # Chosen so each precision level yields a visibly different answer.
        lat, lon = 23.55, 120.44
        exact = Sensor(
            sensor_id="e", label="e", latitude=lat, longitude=lon,
            location_precision="exact",
        )
        city = Sensor(
            sensor_id="c", label="c", latitude=lat, longitude=lon,
            location_precision="city",
        )
        country = Sensor(
            sensor_id="n", label="n", latitude=lat, longitude=lon,
            location_precision="country",
        )
        assert sensor_registry.publish_coords(exact) == (lat, lon)
        assert sensor_registry.publish_coords(city) == (23.6, 120.4)
        assert sensor_registry.publish_coords(country) == (24.0, 120.0)

    def test_unknown_precision_is_treated_as_coarse(self, db_session):
        """A bad precision value must never leak an exact position."""
        sensor = Sensor(
            sensor_id="bad", label="bad", latitude=23.55, longitude=120.44,
            location_precision="garbage",
        )
        assert sensor_registry.publish_coords(sensor) == (24.0, 120.0)

    def test_missing_coords_stay_missing(self, db_session):
        sensor = Sensor(sensor_id="x", label="x", location_precision="country")
        assert sensor_registry.publish_coords(sensor) == (None, None)

    def test_offline_by_heartbeat_for_remote(self, db_session):
        stale = make_sensor(
            db_session,
            sensor_id="stale",
            last_heartbeat_at=datetime.utcnow() - timedelta(hours=2),
        )
        fresh = make_sensor(
            db_session,
            sensor_id="fresh",
            last_heartbeat_at=datetime.utcnow(),
        )
        assert sensor_registry.is_offline(stale) is True
        assert sensor_registry.is_offline(fresh) is False

    def test_token_is_never_stored_in_clear(self, db_session):
        token = sensor_registry.generate_token()
        sensor = make_sensor(
            db_session, sensor_id="hashed", token_hash=sensor_registry.hash_token(token)
        )
        assert token not in (sensor.token_hash or "")
        assert sensor_registry.authenticate(db_session, token).sensor_id == "hashed"
        assert sensor_registry.authenticate(db_session, "nope") is None
