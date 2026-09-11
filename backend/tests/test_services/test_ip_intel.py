"""Tests for the keyless IP intel enrichment (InternetDB + Tor exit list)."""

from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import httpx
import pytest

from app.models import IPIntel
from app.services import ip_intel
from app.services.ip_intel import (
    LookupThrottled,
    apply_tor_flags,
    fetch_internetdb,
    intel_for_ips,
    parse_internetdb,
    parse_tor_list,
    promoted_tags,
    store_intel,
    summarize,
)
from tests.conftest import NOW, make_attempt


@pytest.fixture(autouse=True)
def _reset_module_state():
    ip_intel._failed_ips.clear()
    ip_intel._tor_exits = set()
    ip_intel._tor_fetched_at = None
    yield
    ip_intel._failed_ips.clear()
    ip_intel._tor_exits = set()
    ip_intel._tor_fetched_at = None


class TestParsing:
    def test_tor_list_ignores_junk(self):
        body = "171.25.193.25\n# comment\n\nnot-an-ip\n 80.67.167.81 \n2001:db8::1\n"
        assert parse_tor_list(body) == {"171.25.193.25", "80.67.167.81", "2001:db8::1"}

    def test_internetdb_normalises_types(self):
        parsed = parse_internetdb({
            "ports": [22, 80, "x", 70000, 22],
            "tags": ["VPN", "cloud"],
            "hostnames": ["a.example", 5],
            "cpes": ["cpe:/a:openbsd:openssh:8.9"],
            "vulns": ["CVE-2024-6387", "CVE-2024-6387"],
            "unexpected": {"ignored": True},
        })
        assert parsed == {
            "tags": ["cloud", "vpn"],
            "ports": [22, 80],
            "hostnames": ["a.example", "5"],
            "cpes": ["cpe:/a:openbsd:openssh:8.9"],
            "vulns": ["CVE-2024-6387"],
        }

    def test_internetdb_tolerates_missing_fields(self):
        assert parse_internetdb({}) == {
            "tags": [], "ports": [], "hostnames": [], "cpes": [], "vulns": [],
        }

    def test_promoted_tags_orders_and_prefers_exit_list(self):
        assert promoted_tags(["self-signed", "vpn", "cloud"], is_tor=False) == ["vpn", "cloud"]
        assert promoted_tags(["vpn"], is_tor=True) == ["tor", "vpn"]
        assert promoted_tags(["tor"], is_tor=False) == ["tor"]


class TestStorage:
    def test_store_and_summarize_found(self, db_session):
        parsed = parse_internetdb({"ports": [22], "tags": ["proxy"], "vulns": ["CVE-1"]})
        store_intel(db_session, "1.2.3.4", parsed, now=NOW)

        summary = summarize(db_session.get(IPIntel, "1.2.3.4"), "1.2.3.4")
        assert summary.tags == ["proxy"]
        assert summary.open_ports == [22]
        assert summary.vulns == ["CVE-1"]
        assert summary.is_tor is False
        assert summary.fetched_at == NOW

    def test_store_not_found_is_recorded(self, db_session):
        row = store_intel(db_session, "1.2.3.4", None, now=NOW)
        assert row.found is False
        assert summarize(row, "1.2.3.4").tags == []

    def test_store_flags_tor_from_exit_list(self, db_session):
        ip_intel._tor_exits = {"1.2.3.4"}
        row = store_intel(db_session, "1.2.3.4", None, now=NOW)
        assert row.is_tor is True
        assert summarize(row, "1.2.3.4").tags == ["tor"]

    def test_intel_for_ips_batches(self, db_session):
        for i in range(3):
            store_intel(db_session, f"1.2.3.{i}", parse_internetdb({"tags": ["vpn"]}), now=NOW)
        out = intel_for_ips(db_session, ["1.2.3.0", "1.2.3.2", "9.9.9.9"])
        assert set(out) == {"1.2.3.0", "1.2.3.2"}
        assert intel_for_ips(db_session, []) == {}

    def test_apply_tor_flags_reconciles_both_ways(self, db_session):
        store_intel(db_session, "1.1.1.1", None, now=NOW)
        ip_intel._tor_exits = {"2.2.2.2"}
        store_intel(db_session, "2.2.2.2", None, now=NOW)

        changed = apply_tor_flags(db_session, {"1.1.1.1"})

        assert changed == 2
        assert db_session.get(IPIntel, "1.1.1.1").is_tor is True
        assert db_session.get(IPIntel, "2.2.2.2").is_tor is False


class TestPendingSelection:
    def test_prefers_recent_ips_and_skips_fresh_rows(self, db_session):
        now = datetime.utcnow()
        make_attempt(db_session, src_ip="1.1.1.1", session_id="s1", timestamp=now)
        make_attempt(db_session, src_ip="2.2.2.2", session_id="s2", timestamp=now - timedelta(days=30))
        make_attempt(db_session, src_ip="3.3.3.3", session_id="s3", timestamp=now)
        store_intel(db_session, "3.3.3.3", None, now=now)                        # fresh
        store_intel(db_session, "2.2.2.2", None, now=now - ip_intel.CACHE_TTL * 2)  # stale

        pending = ip_intel._pending_ips(db_session, limit=10)

        assert pending[0] == "1.1.1.1"
        assert set(pending) == {"1.1.1.1", "2.2.2.2"}

    def test_limit_is_respected(self, db_session):
        for i in range(5):
            make_attempt(db_session, src_ip=f"1.1.1.{i}", session_id=f"s{i}")
        assert len(ip_intel._pending_ips(db_session, limit=2)) == 2


class TestFetch:
    def _resp(self, status, body=None, text=""):
        resp = MagicMock()
        resp.status_code = status
        resp.json.return_value = body
        resp.text = text
        return resp

    def test_404_means_no_record(self):
        with patch("app.services.ip_intel.httpx.get", return_value=self._resp(404)):
            assert fetch_internetdb("1.2.3.4") is None

    def test_200_is_parsed(self):
        body = {"ports": [22], "tags": [], "hostnames": [], "cpes": [], "vulns": []}
        with patch("app.services.ip_intel.httpx.get", return_value=self._resp(200, body)):
            assert fetch_internetdb("1.2.3.4")["ports"] == [22]

    def test_429_and_network_errors_throttle(self):
        with patch("app.services.ip_intel.httpx.get", return_value=self._resp(429)):
            with pytest.raises(LookupThrottled):
                fetch_internetdb("1.2.3.4")
        with patch("app.services.ip_intel.httpx.get", side_effect=httpx.ConnectError("down")):
            with pytest.raises(LookupThrottled):
                fetch_internetdb("1.2.3.4")

    def test_unexpected_payload_is_an_error(self):
        with patch("app.services.ip_intel.httpx.get", return_value=self._resp(200, ["nope"])):
            with pytest.raises(ValueError):
                fetch_internetdb("1.2.3.4")

    def test_failure_backoff(self):
        assert ip_intel._recently_failed("1.2.3.4") is False
        ip_intel._mark_failed("1.2.3.4")
        assert ip_intel._recently_failed("1.2.3.4") is True
        ip_intel._failed_ips["1.2.3.4"] -= ip_intel.FAILURE_BACKOFF + 1
        assert ip_intel._recently_failed("1.2.3.4") is False
