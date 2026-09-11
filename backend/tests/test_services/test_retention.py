"""Tests for the retention service: daily aggregation and pruning."""

from datetime import date, datetime, timedelta
from unittest.mock import patch

from sqlalchemy import text

from app.config import settings
from app.models import Attempt, DailyStat, PageView, ReportLog, Session
from app.services.retention import (
    aggregate_day,
    aggregate_missing_days,
    prune,
    prune_report_logs,
)
from tests.conftest import make_attempt, make_session

DAY = date(2025, 6, 10)
DAY_NOON = datetime(2025, 6, 10, 12, 0, 0)
NOW = datetime(2025, 6, 15, 12, 0, 0)


class TestAggregateDay:
    def test_empty_day_writes_nothing(self, db_session):
        assert aggregate_day(db_session, DAY) is None
        assert db_session.query(DailyStat).count() == 0

    def test_computes_totals_and_top_values(self, db_session):
        make_attempt(db_session, timestamp=DAY_NOON, src_ip="1.1.1.1",
                     country_code="CN", country_name="China",
                     username="root", password="123456", session_id="s1")
        make_attempt(db_session, timestamp=DAY_NOON + timedelta(hours=1),
                     src_ip="1.1.1.1", country_code="CN", country_name="China",
                     username="root", password="admin", session_id="s2")
        make_attempt(db_session, timestamp=DAY_NOON + timedelta(hours=2),
                     src_ip="2.2.2.2", country_code="US", country_name="United States",
                     username="admin", password="123456", session_id="s3")
        # Outside the day — must not count
        make_attempt(db_session, timestamp=DAY_NOON + timedelta(days=1),
                     src_ip="3.3.3.3", session_id="s4")

        stat = aggregate_day(db_session, DAY)

        assert stat.date == "2025-06-10"
        assert stat.total_attempts == 3
        assert stat.unique_ips == 2
        assert stat.unique_countries == 2
        assert stat.top_country == "China"
        assert stat.top_username == "root"
        assert stat.top_password == "123456"

    def test_upsert_is_idempotent(self, db_session):
        make_attempt(db_session, timestamp=DAY_NOON)
        aggregate_day(db_session, DAY)
        aggregate_day(db_session, DAY)
        assert db_session.query(DailyStat).count() == 1


class TestAggregateMissingDays:
    def test_fills_all_past_days_but_not_today(self, db_session):
        make_attempt(db_session, timestamp=DAY_NOON, session_id="s1", src_ip="1.1.1.1")
        make_attempt(db_session, timestamp=DAY_NOON + timedelta(days=2),
                     session_id="s2", src_ip="2.2.2.2")
        # "Today" relative to NOW — must not be aggregated yet
        make_attempt(db_session, timestamp=NOW - timedelta(hours=1),
                     session_id="s3", src_ip="3.3.3.3")

        written = aggregate_missing_days(db_session, now=NOW)

        assert written == 2
        dates = {s.date for s in db_session.query(DailyStat).all()}
        assert dates == {"2025-06-10", "2025-06-12"}

    def test_existing_days_not_rewritten(self, db_session):
        make_attempt(db_session, timestamp=DAY_NOON, session_id="s1")
        aggregate_missing_days(db_session, now=NOW)
        # Second pass has nothing new to do
        assert aggregate_missing_days(db_session, now=NOW) == 0

    def test_yesterday_always_reaggregated(self, db_session):
        yesterday_noon = NOW - timedelta(days=1)
        make_attempt(db_session, timestamp=yesterday_noon, session_id="s1")
        aggregate_missing_days(db_session, now=NOW)

        # A late event lands for yesterday after the first pass
        make_attempt(db_session, timestamp=yesterday_noon + timedelta(hours=1),
                     session_id="s2", src_ip="9.9.9.9")
        aggregate_missing_days(db_session, now=NOW)

        stat = db_session.query(DailyStat).filter_by(date="2025-06-14").one()
        assert stat.total_attempts == 2


class TestPrune:
    @patch("app.services.retention.settings")
    def test_disabled_by_default_deletes_nothing(self, mock_settings, db_session):
        mock_settings.retention_days = 0
        make_attempt(db_session, timestamp=NOW - timedelta(days=400))

        deleted = prune(db_session, now=NOW)

        assert deleted == {"attempts": 0, "sessions": 0, "page_views": 0}
        assert db_session.query(Attempt).count() == 1

    @patch("app.services.retention.settings")
    def test_deletes_only_rows_older_than_window(self, mock_settings, db_session):
        mock_settings.retention_days = 90
        old = NOW - timedelta(days=91)
        recent = NOW - timedelta(days=89)

        make_attempt(db_session, timestamp=old, session_id="old", src_ip="1.1.1.1")
        make_attempt(db_session, timestamp=recent, session_id="new", src_ip="2.2.2.2")
        make_session(db_session, session_id="old", start_time=old)
        make_session(db_session, session_id="new", start_time=recent)
        db_session.add(PageView(visitor_ip="9.9.9.9", visited_at=old))
        db_session.add(PageView(visitor_ip="9.9.9.9", visited_at=recent))
        db_session.commit()

        deleted = prune(db_session, now=NOW)

        assert deleted == {"attempts": 1, "sessions": 1, "page_views": 1}
        assert db_session.query(Attempt).one().session_id == "new"
        assert db_session.query(Session).one().session_id == "new"
        assert db_session.query(PageView).one().visited_at == recent

    @patch("app.services.retention.settings")
    def test_daily_stats_survive_pruning(self, mock_settings, db_session):
        mock_settings.retention_days = 1
        make_attempt(db_session, timestamp=DAY_NOON)
        aggregate_day(db_session, DAY)

        prune(db_session, now=NOW)

        assert db_session.query(Attempt).count() == 0
        assert db_session.query(DailyStat).count() == 1


class TestPruneReportLogs:
    """Trimming the reporting audit trail.

    Most of this table is diagnostic noise nothing reads once it is a few days
    old — but one slice of it is live state, not audit, and deleting it causes
    real harm.
    """

    def _log(self, db, report_type, success, ago_days, detail="x"):
        row = ReportLog(
            report_type=report_type, identifier="i", success=success,
            detail=detail, reported_at=NOW - timedelta(days=ago_days),
        )
        db.add(row)
        db.commit()
        return row

    def test_deletes_failures_past_the_window(self, db_session):
        self._log(db_session, "virustotal", False, 120)
        with patch.object(settings, "report_log_retention_days", 90):
            assert prune_report_logs(db_session, NOW) == 1
        assert db_session.query(ReportLog).count() == 0

    def test_keeps_rows_inside_the_window(self, db_session):
        self._log(db_session, "virustotal", False, 10)
        self._log(db_session, "abuseipdb", True, 10)
        with patch.object(settings, "report_log_retention_days", 90):
            assert prune_report_logs(db_session, NOW) == 0
        assert db_session.query(ReportLog).count() == 2

    def test_never_deletes_a_successful_virustotal_submission(self, db_session):
        """Not audit — vt_reporter reads these with no time bound to avoid
        re-uploading a sample. Deleting one costs quota and duplicates work."""
        self._log(db_session, "virustotal", True, 3650)
        with patch.object(settings, "report_log_retention_days", 90):
            assert prune_report_logs(db_session, NOW) == 0
        assert db_session.query(ReportLog).count() == 1

    def test_deletes_old_abuseipdb_successes(self, db_session):
        """Only ever read through the 50 newest closed sessions and a
        15-minute dedup window, so old ones are genuinely dead."""
        self._log(db_session, "abuseipdb", True, 120)
        with patch.object(settings, "report_log_retention_days", 90):
            assert prune_report_logs(db_session, NOW) == 1

    def test_deletes_old_virustotal_failures_but_not_successes(self, db_session):
        self._log(db_session, "virustotal", False, 120)
        kept = self._log(db_session, "virustotal", True, 120)
        with patch.object(settings, "report_log_retention_days", 90):
            assert prune_report_logs(db_session, NOW) == 1
        remaining = db_session.query(ReportLog).all()
        assert [r.id for r in remaining] == [kept.id]

    def test_null_success_is_not_mistaken_for_a_kept_submission(self, db_session):
        """`NOT (type=vt AND success=1)` must not go NULL and spare the row.

        Written through raw SQL on purpose: the column's Python-side default
        rewrites an explicit None to True, so the ORM cannot produce the row
        this guards against — only legacy data or a direct write can.
        """
        db_session.execute(text(
            "INSERT INTO report_logs (report_type, identifier, success, detail,"
            " reported_at) VALUES ('virustotal', 'i', NULL, 'x', '2020-01-01')"
        ))
        db_session.commit()
        with patch.object(settings, "report_log_retention_days", 90):
            assert prune_report_logs(db_session, NOW) == 1

    def test_disabled_window_is_a_noop(self, db_session):
        self._log(db_session, "abuseipdb", True, 3650)
        with patch.object(settings, "report_log_retention_days", 0):
            assert prune_report_logs(db_session, NOW) == 0
        assert db_session.query(ReportLog).count() == 1
