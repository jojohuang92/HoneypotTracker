"""Tests for the auto IP-lookup service's failure backoff."""

from unittest.mock import patch, MagicMock

import pytest

from app.services import ip_lookup
from app.services.abuseipdb import RateLimitedError, fetch_and_cache_score


@pytest.fixture(autouse=True)
def _reset_backoff_state():
    ip_lookup._failed_ips.clear()
    yield
    ip_lookup._failed_ips.clear()


class TestFailureBackoff:
    def test_fresh_ip_is_not_backed_off(self):
        assert ip_lookup._recently_failed("1.2.3.4") is False

    def test_failed_ip_is_skipped(self):
        ip_lookup._mark_failed("1.2.3.4")
        assert ip_lookup._recently_failed("1.2.3.4") is True

    def test_backoff_expires(self):
        ip_lookup._mark_failed("1.2.3.4")
        ip_lookup._failed_ips["1.2.3.4"] -= ip_lookup.FAILURE_BACKOFF + 1
        assert ip_lookup._recently_failed("1.2.3.4") is False

    def test_other_ips_unaffected(self):
        ip_lookup._mark_failed("1.2.3.4")
        assert ip_lookup._recently_failed("5.6.7.8") is False


class TestFetchAndCacheScore429:
    @patch("app.services.abuseipdb.settings")
    def test_429_raises_rate_limited(self, mock_settings, db_session):
        mock_settings.abuseipdb_api_key = "key"
        resp = MagicMock()
        resp.status_code = 429

        with patch("app.services.abuseipdb.httpx.get", return_value=resp):
            with pytest.raises(RateLimitedError):
                fetch_and_cache_score(db_session, "1.2.3.4")

    @patch("app.services.abuseipdb.settings")
    def test_other_http_errors_return_none(self, mock_settings, db_session):
        import httpx as _httpx
        mock_settings.abuseipdb_api_key = "key"

        with patch(
            "app.services.abuseipdb.httpx.get",
            side_effect=_httpx.ConnectError("boom"),
        ):
            assert fetch_and_cache_score(db_session, "1.2.3.4") is None
