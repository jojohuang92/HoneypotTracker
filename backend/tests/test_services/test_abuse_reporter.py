"""Tests for the AbuseIPDB auto-reporter's dedup / session-coverage logic."""

from datetime import datetime, timedelta

from app.models import ReportLog
from app.services.abuse_reporter import (
    _build_report_comment,
    _session_already_covered,
    _was_recently_reported,
)
from tests.conftest import NOW, make_attempt


def _log_report(db_session, ip: str, reported_at: datetime, success: bool = True):
    entry = ReportLog(
        report_type="abuseipdb",
        identifier=ip,
        success=success,
        detail="test",
    )
    db_session.add(entry)
    db_session.commit()
    # server_default would stamp the current wall clock; tests need control
    entry.reported_at = reported_at
    db_session.commit()
    return entry


class TestWasRecentlyReported:
    def test_recent_success_dedupes(self, db_session):
        _log_report(db_session, "1.2.3.4", datetime.utcnow() - timedelta(minutes=5))
        assert _was_recently_reported(db_session, "1.2.3.4") is True

    def test_old_report_does_not_dedup(self, db_session):
        _log_report(db_session, "1.2.3.4", datetime.utcnow() - timedelta(hours=2))
        assert _was_recently_reported(db_session, "1.2.3.4") is False

    def test_failed_report_does_not_dedup(self, db_session):
        _log_report(
            db_session, "1.2.3.4", datetime.utcnow() - timedelta(minutes=5),
            success=False,
        )
        assert _was_recently_reported(db_session, "1.2.3.4") is False


class TestSessionAlreadyCovered:
    """A session reported once must never be re-reported, no matter how old."""

    def test_report_after_session_end_covers_it(self, db_session):
        session_end = datetime.utcnow() - timedelta(days=3)
        _log_report(db_session, "1.2.3.4", session_end + timedelta(minutes=1))
        assert _session_already_covered(db_session, "1.2.3.4", session_end) is True

    def test_report_before_session_end_does_not_cover_it(self, db_session):
        # The IP was reported for an *earlier* session; this newer session
        # contains fresh activity and should be reported.
        session_end = datetime.utcnow() - timedelta(minutes=10)
        _log_report(db_session, "1.2.3.4", session_end - timedelta(hours=1))
        assert _session_already_covered(db_session, "1.2.3.4", session_end) is False

    def test_failed_report_does_not_cover(self, db_session):
        session_end = datetime.utcnow() - timedelta(days=3)
        _log_report(
            db_session, "1.2.3.4", session_end + timedelta(minutes=1), success=False
        )
        assert _session_already_covered(db_session, "1.2.3.4", session_end) is False

    def test_open_session_is_not_covered(self, db_session):
        _log_report(db_session, "1.2.3.4", datetime.utcnow())
        assert _session_already_covered(db_session, "1.2.3.4", None) is False


class TestBuildReportComment:
    def test_comment_summarizes_session(self, db_session):
        make_attempt(db_session, session_id="s1", src_ip="1.2.3.4",
                     username="root", password="123456")
        make_attempt(db_session, session_id="s1", src_ip="1.2.3.4",
                     event_id="cowrie.command.input", timestamp=NOW + timedelta(seconds=1),
                     username=None, password=None,
                     command="uname -a", intent="reconnaissance", mitre_id="T1082")

        comment, categories = _build_report_comment(db_session, "1.2.3.4", "s1")

        assert "s1" in comment
        assert "1 login attempt(s)" in comment
        assert "uname -a" in comment
        assert 22 in categories  # SSH
        assert 18 in categories  # Brute-Force

    def test_comment_never_exceeds_abuseipdb_limit(self, db_session):
        for i in range(30):
            make_attempt(db_session, session_id="s1", src_ip="1.2.3.4",
                         event_id="cowrie.command.input",
                         timestamp=NOW + timedelta(seconds=i),
                         username=None, password=None,
                         command="x" * 100, intent="reconnaissance", mitre_id="T1082")

        comment, _ = _build_report_comment(db_session, "1.2.3.4", "s1")
        assert len(comment) <= 1024
