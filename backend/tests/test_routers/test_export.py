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


# ---------------------------------------------------------------------------
# Caching, conditional requests, tags and the top-attackers feed
# ---------------------------------------------------------------------------

from unittest.mock import patch

from app.services.export_cache import export_cache
from app.services.ip_intel import parse_internetdb, store_intel


def test_cache_headers_and_etag_304(client, db_session):
    make_attempt(db_session, src_ip="1.2.3.4", timestamp=RECENT)

    first = client.get("/api/export/blocklist.txt")
    assert first.status_code == 200
    assert first.headers["cache-control"] == "public, max-age=300"
    assert first.headers["etag"].startswith('"')
    assert "last-modified" in first.headers

    again = client.get("/api/export/blocklist.txt",
                       headers={"If-None-Match": first.headers["etag"]})
    assert again.status_code == 304
    assert again.content == b""

    other = client.get("/api/export/blocklist.txt", headers={"If-None-Match": '"nope"'})
    assert other.status_code == 200


def test_cached_body_is_reused_until_cleared(client, db_session):
    make_attempt(db_session, src_ip="1.2.3.4", timestamp=RECENT)
    assert "1.2.3.4" in client.get("/api/export/blocklist.txt").text

    make_attempt(db_session, src_ip="1.2.3.5", timestamp=RECENT, session_id="s2")
    assert "1.2.3.5" not in client.get("/api/export/blocklist.txt").text  # served from cache

    export_cache.clear()
    assert "1.2.3.5" in client.get("/api/export/blocklist.txt").text


def test_cache_disabled_by_setting(client, db_session):
    make_attempt(db_session, src_ip="1.2.3.4", timestamp=RECENT)
    with patch("app.routers.export.settings.export_cache_seconds", 0):
        first = client.get("/api/export/blocklist.txt")
        make_attempt(db_session, src_ip="1.2.3.5", timestamp=RECENT, session_id="s2")
        second = client.get("/api/export/blocklist.txt")
    assert first.headers["cache-control"] == "no-cache"
    assert "1.2.3.5" in second.text


def test_exclude_tor_and_csv_tags(client, db_session):
    make_attempt(db_session, src_ip="1.2.3.4", timestamp=RECENT)
    make_attempt(db_session, src_ip="1.2.3.5", timestamp=RECENT, session_id="s2")
    store_intel(db_session, "1.2.3.5", parse_internetdb({"tags": ["tor", "vpn"]}))

    full = client.get("/api/export/blocklist.txt")
    assert "# tor_exits: included" in full.text
    assert "1.2.3.5" in full.text

    trimmed = client.get("/api/export/blocklist.txt?exclude_tor=true")
    assert "# tor_exits: excluded" in trimmed.text
    assert "1.2.3.5" not in trimmed.text
    assert "1.2.3.4" in trimmed.text
    assert trimmed.headers["etag"] != full.headers["etag"]

    csv_ = client.get("/api/export/iocs.csv")
    row = [l for l in csv_.text.splitlines() if l.startswith("ip,1.2.3.5")][0]
    assert row.endswith(",tags=tor;vpn")


def test_top_attackers_feed(client, db_session):
    for i in range(3):
        make_attempt(db_session, src_ip="1.2.3.4", timestamp=RECENT, session_id=f"a{i}")
    make_attempt(db_session, src_ip="1.2.3.5", timestamp=RECENT, session_id="b",
                 intent="malware_deployment")
    make_attempt(db_session, src_ip="192.168.0.9", timestamp=RECENT, session_id="c")

    resp = client.get("/api/export/top-attackers.json?limit=1")

    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/json")
    body = resp.json()
    assert body["window_days"] == 30
    assert body["count"] == 1
    assert body["attackers"][0]["ip"] == "1.2.3.4"
    assert body["attackers"][0]["attempts"] == 3
    assert body["attackers"][0]["tags"] == []

    everything = client.get("/api/export/top-attackers.json").json()
    assert [a["ip"] for a in everything["attackers"]] == ["1.2.3.4", "1.2.3.5"]
    assert everything["attackers"][1]["intent"] == "malware_deployment"


def test_top_attackers_validation(client):
    assert client.get("/api/export/top-attackers.json?limit=0").status_code == 422
    assert client.get("/api/export/top-attackers.json?limit=1001").status_code == 422
