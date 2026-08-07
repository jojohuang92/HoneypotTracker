"""Tests for the /api/export IOC endpoints."""

from datetime import datetime, timedelta

from tests.conftest import make_attempt, make_captured_file

UTCNOW = datetime.utcnow()
RECENT = UTCNOW - timedelta(days=1)
OLD = UTCNOW - timedelta(days=90)


def test_blocklist_content_and_type(client, db_session):
    make_attempt(db_session, src_ip="1.2.3.4", timestamp=RECENT)
    make_attempt(db_session, src_ip="192.168.1.5", timestamp=RECENT)  # private: excluded
    make_attempt(db_session, src_ip="1.2.3.5", timestamp=OLD)         # stale: excluded

    resp = client.get("/api/export/blocklist.txt")

    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")
    ips = [l for l in resp.text.splitlines() if not l.startswith("#")]
    assert ips == ["1.2.3.4"]


def test_days_param_widens_window(client, db_session):
    make_attempt(db_session, src_ip="1.2.3.5", timestamp=OLD)

    default = client.get("/api/export/blocklist.txt")
    wide = client.get("/api/export/blocklist.txt?days=120")

    assert "1.2.3.5" not in default.text
    assert "1.2.3.5" in wide.text


def test_days_param_validation(client):
    assert client.get("/api/export/blocklist.txt?days=0").status_code == 422
    assert client.get("/api/export/blocklist.txt?days=366").status_code == 422
    assert client.get("/api/export/blocklist.txt?days=abc").status_code == 422


def test_csv_endpoint(client, db_session):
    make_attempt(db_session, src_ip="1.2.3.4", timestamp=RECENT)
    make_captured_file(db_session, sha256="a" * 64, timestamp=RECENT)

    resp = client.get("/api/export/iocs.csv")

    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    assert "attachment" in resp.headers["content-disposition"]
    lines = resp.text.strip().splitlines()
    assert lines[0] == "type,value,first_seen,last_seen,count,intent,country,extra"
    types = {l.split(",")[0] for l in lines[1:]}
    assert types == {"ip", "sha256", "url"}  # conftest file fixture includes a url


def test_stix_endpoint(client, db_session):
    make_attempt(db_session, src_ip="1.2.3.4", timestamp=RECENT)

    resp = client.get("/api/export/stix.json")

    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/stix+json")
    bundle = resp.json()
    assert bundle["type"] == "bundle"
    patterns = [o.get("pattern") for o in bundle["objects"] if o["type"] == "indicator"]
    assert "[ipv4-addr:value = '1.2.3.4']" in patterns


def test_empty_db_valid_output_all_formats(client):
    txt = client.get("/api/export/blocklist.txt")
    csv_ = client.get("/api/export/iocs.csv")
    stix = client.get("/api/export/stix.json")

    assert txt.status_code == csv_.status_code == stix.status_code == 200
    assert all(l.startswith("#") for l in txt.text.splitlines())
    assert csv_.text.strip() == "type,value,first_seen,last_seen,count,intent,country,extra"
    b = stix.json()
    assert [o["type"] for o in b["objects"]] == ["identity"]
