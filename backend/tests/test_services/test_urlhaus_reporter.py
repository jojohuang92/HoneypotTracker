"""Tests for the URLhaus URL reporter: eligibility, tags, dedup, response handling."""

from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import httpx
import pytest

from app.models import ReportLog
from app.services import urlhaus_reporter as ur
from tests.conftest import make_captured_file


def _log(db, url, success, reported_at=None, detail="x"):
    entry = ReportLog(report_type="urlhaus", identifier=url, success=success, detail=detail)
    db.add(entry)
    db.commit()
    if reported_at:
        entry.reported_at = reported_at
        db.commit()
    return entry


class TestEligibility:
    @pytest.mark.parametrize("url", [
        "http://94.154.43.200/Sakura.sh",
        "https://cdn.example.com/x/bins.sh",
        "http://example.com:8080/dl?arch=mips",
    ])
    def test_public_http_urls_pass(self, url):
        assert ur.eligible_url(url) is True

    @pytest.mark.parametrize("url", [
        None, "", "ftp://1.2.3.4/x", "tftp://1.2.3.4/x", "http://",
        "http://10.0.0.5/bot.sh", "http://192.168.1.1/x", "http://127.0.0.1/x",
        "http://localhost/x", "http://router.local/x", "http://nas/x",
        "http://[::1]/x", "http://" + "a" * 2100 + ".com/x",
    ])
    def test_private_or_malformed_urls_fail(self, url):
        assert ur.eligible_url(url) is False


class TestTags:
    def test_provenance_plus_analysis(self):
        assert ur.build_tags("MIPS", "Mirai") == ["honeypot", "cowrie", "elf", "MIPS", "Mirai"]

    def test_no_analysis(self):
        assert ur.build_tags(None, None) == ["honeypot", "cowrie"]

    def test_illegal_characters_and_duplicates_dropped(self):
        assert ur.build_tags("x86-64", "gafgyt/bashlite;drop") == [
            "honeypot", "cowrie", "elf", "x86-64", "gafgytbashlitedrop",
        ]
        assert ur.build_tags(None, "Cowrie") == ["honeypot", "cowrie"]

    def test_submission_shape(self):
        with patch.object(ur.settings, "urlhaus_anonymous", False):
            body = ur.build_submission("http://1.2.3.4/x", ["honeypot"])
        assert body == {
            "anonymous": "0",
            "submission": [{"url": "http://1.2.3.4/x", "threat": "malware_download",
                            "tags": ["honeypot"]}],
        }
        with patch.object(ur.settings, "urlhaus_anonymous", True):
            assert ur.build_submission("u", [])["anonymous"] == "1"


class TestCandidates:
    def test_only_fresh_distinct_eligible_urls(self, db_session):
        now = datetime.utcnow()
        fresh = now - timedelta(hours=1)
        stale = now - timedelta(hours=48)
        make_captured_file(db_session, url="http://1.2.3.4/a.sh", timestamp=fresh,
                           sha256="a" * 64, arch="ARM", session_id="s1")
        make_captured_file(db_session, url="http://1.2.3.4/a.sh", timestamp=fresh,
                           sha256="a" * 64, session_id="s2")        # duplicate URL
        make_captured_file(db_session, url="http://1.2.3.4/old.sh", timestamp=stale,
                           sha256="b" * 64, session_id="s3")        # too old
        make_captured_file(db_session, url="http://10.0.0.1/lan.sh", timestamp=fresh,
                           sha256="c" * 64, session_id="s4")        # private
        make_captured_file(db_session, url="http://5.6.7.8/done.sh", timestamp=fresh,
                           sha256="d" * 64, session_id="s5")
        _log(db_session, "http://5.6.7.8/done.sh", True)            # already sent

        candidates = ur.find_candidates(db_session, now=now)

        assert candidates == [("http://1.2.3.4/a.sh", ["honeypot", "cowrie", "elf", "ARM"])]

    def test_spent_attempts_skip(self, db_session):
        now = datetime.utcnow()
        make_captured_file(db_session, url="http://1.2.3.4/a.sh", timestamp=now,
                           sha256="a" * 64)
        for _ in range(ur.MAX_ATTEMPTS):
            _log(db_session, "http://1.2.3.4/a.sh", False)

        assert ur.find_candidates(db_session, now=now) == []

    def test_old_failures_do_not_count(self, db_session):
        now = datetime.utcnow()
        make_captured_file(db_session, url="http://1.2.3.4/a.sh", timestamp=now,
                           sha256="a" * 64)
        for _ in range(ur.MAX_ATTEMPTS):
            _log(db_session, "http://1.2.3.4/a.sh", False,
                 reported_at=now - ur.RETRY_WINDOW - timedelta(days=1))

        assert [u for u, _ in ur.find_candidates(db_session, now=now)] == ["http://1.2.3.4/a.sh"]


class TestSubmit:
    def _resp(self, status, text):
        resp = MagicMock()
        resp.status_code = status
        resp.text = text
        return resp

    def test_ok_json(self):
        with patch("app.services.urlhaus_reporter.httpx.post",
                   return_value=self._resp(200, '{"query_status":"ok"}')) as post:
            ok, detail = ur.submit_url("http://1.2.3.4/x", ["honeypot"])
        assert ok is True
        assert "ok" in detail
        assert post.call_args.kwargs["headers"]["Auth-Key"] == ur.settings.urlhaus_auth_key

    def test_rejected_json(self):
        with patch("app.services.urlhaus_reporter.httpx.post",
                   return_value=self._resp(200, '{"query_status":"invalid_url"}')):
            ok, detail = ur.submit_url("http://1.2.3.4/x", [])
        assert ok is False and "invalid_url" in detail

    def test_auth_rejection_raises(self):
        for status, text in ((401, "nope"), (403, "nope"),
                             (200, '{"query_status":"invalid_auth_key"}'),
                             (200, "Error: invalid Auth-Key")):
            with patch("app.services.urlhaus_reporter.httpx.post",
                       return_value=self._resp(status, text)):
                with pytest.raises(ur.AuthRejected):
                    ur.submit_url("http://1.2.3.4/x", [])

    def test_rate_limit_and_errors_fail_softly(self):
        with patch("app.services.urlhaus_reporter.httpx.post",
                   return_value=self._resp(429, "")):
            assert ur.submit_url("u", []) == (False, "Rate limit hit")
        with patch("app.services.urlhaus_reporter.httpx.post",
                   return_value=self._resp(500, "boom")):
            ok, detail = ur.submit_url("u", [])
            assert ok is False and "500" in detail
        with patch("app.services.urlhaus_reporter.httpx.post",
                   side_effect=httpx.ConnectError("down")):
            ok, detail = ur.submit_url("u", [])
            assert ok is False and "request failed" in detail
