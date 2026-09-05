"""Tests for VT reporter file-path resolution.

Cowrie logs 'outfile' relative to its own working directory, so the stored
path rarely resolves from here. Resolution is confined to the configured
downloads directory: the path travels through the database from an event
payload, and anything it resolves to gets uploaded to a third party.
"""

from datetime import datetime, timedelta
from unittest.mock import patch

from app.models import ReportLog
from app.services.vt_reporter import (
    MAX_UPLOAD_ATTEMPTS,
    UPLOAD_RETRY_WINDOW,
    _resolve_file_path,
    _spent_attempts,
)

SHA = "a" * 64


class TestResolveFilePath:
    @patch("app.services.vt_reporter.settings")
    def test_absolute_path_inside_downloads_dir_used(self, mock_settings, tmp_path):
        mock_settings.cowrie_downloads_dir = str(tmp_path)
        f = tmp_path / SHA
        f.write_bytes(b"x")

        assert _resolve_file_path(str(f), SHA) == f

    @patch("app.services.vt_reporter.settings")
    def test_absolute_path_outside_downloads_dir_refused(self, mock_settings, tmp_path):
        """The exfiltration case: a path pointing at anything but a sample."""
        downloads = tmp_path / "downloads"
        downloads.mkdir()
        secret = tmp_path / ".env"
        secret.write_text("ADMIN_API_KEY=hunter2")
        mock_settings.cowrie_downloads_dir = str(downloads)

        assert _resolve_file_path(str(secret), SHA) is None

    @patch("app.services.vt_reporter.settings")
    def test_symlink_escaping_downloads_dir_refused(self, mock_settings, tmp_path):
        downloads = tmp_path / "downloads"
        downloads.mkdir()
        secret = tmp_path / ".env"
        secret.write_text("ADMIN_API_KEY=hunter2")
        (downloads / SHA).symlink_to(secret)
        mock_settings.cowrie_downloads_dir = str(downloads)

        assert _resolve_file_path(f"var/lib/cowrie/downloads/{SHA}", SHA) is None

    @patch("app.services.vt_reporter.settings")
    def test_relative_path_resolved_by_sha_in_downloads_dir(self, mock_settings, tmp_path):
        (tmp_path / SHA).write_bytes(b"x")
        mock_settings.cowrie_downloads_dir = str(tmp_path)

        resolved = _resolve_file_path(f"var/lib/cowrie/downloads/{SHA}", SHA)

        assert resolved == tmp_path / SHA

    @patch("app.services.vt_reporter.settings")
    def test_relative_path_resolved_by_basename(self, mock_settings, tmp_path):
        # File kept under its original name rather than its hash
        (tmp_path / "dropper.sh").write_bytes(b"x")
        mock_settings.cowrie_downloads_dir = str(tmp_path)

        resolved = _resolve_file_path("var/lib/cowrie/downloads/dropper.sh", SHA)

        assert resolved == tmp_path / "dropper.sh"

    @patch("app.services.vt_reporter.settings")
    def test_unresolvable_relative_path_returns_none(self, mock_settings, tmp_path):
        mock_settings.cowrie_downloads_dir = str(tmp_path)
        assert _resolve_file_path(f"var/lib/cowrie/downloads/{SHA}", SHA) is None

    @patch("app.services.vt_reporter.settings")
    def test_no_downloads_dir_configured_returns_none(self, mock_settings):
        mock_settings.cowrie_downloads_dir = ""
        assert _resolve_file_path(f"var/lib/cowrie/downloads/{SHA}", SHA) is None

    @patch("app.services.vt_reporter.settings")
    def test_no_downloads_dir_falls_back_to_literal_path(self, mock_settings, tmp_path):
        """Only reachable for locally-tailed events — remote ones store no path."""
        mock_settings.cowrie_downloads_dir = ""
        f = tmp_path / "sample.bin"
        f.write_bytes(b"x")

        assert _resolve_file_path(str(f), SHA) == f


class TestSpentAttempts:
    """Bounding upload retries.

    Dedup only recognises a *successful* submission, so a sample that cannot be
    uploaded — its bytes deleted by retention, or unreadable because Cowrie
    wrote it 0600 — was retried every scan forever. One hash reached 42,769
    failed attempts in production, and the audit table grew to 51 MB of rows
    recording the same error.
    """

    def _fail(self, db, sha, detail="File not found: x", ago=timedelta(hours=1)):
        db.add(ReportLog(
            report_type="virustotal", identifier=sha, success=False,
            detail=detail, reported_at=datetime.utcnow() - ago,
        ))
        db.commit()

    def test_a_fresh_hash_is_not_spent(self, db_session):
        assert _spent_attempts(db_session, SHA) is False

    def test_under_the_cap_is_not_spent(self, db_session):
        for _ in range(MAX_UPLOAD_ATTEMPTS - 1):
            self._fail(db_session, SHA)
        assert _spent_attempts(db_session, SHA) is False

    def test_at_the_cap_is_spent(self, db_session):
        for _ in range(MAX_UPLOAD_ATTEMPTS):
            self._fail(db_session, SHA)
        assert _spent_attempts(db_session, SHA) is True

    def test_rate_limiting_does_not_burn_an_attempt(self, db_session):
        """The account was throttled; that says nothing about this sample."""
        for _ in range(MAX_UPLOAD_ATTEMPTS * 3):
            self._fail(db_session, SHA, detail="Rate limit hit")
        assert _spent_attempts(db_session, SHA) is False

    def test_failures_outside_the_window_are_forgiven(self, db_session):
        """Whatever blocked the upload may since have been fixed — try again."""
        for _ in range(MAX_UPLOAD_ATTEMPTS * 2):
            self._fail(db_session, SHA, ago=UPLOAD_RETRY_WINDOW + timedelta(days=1))
        assert _spent_attempts(db_session, SHA) is False

    def test_another_hash_is_unaffected(self, db_session):
        for _ in range(MAX_UPLOAD_ATTEMPTS):
            self._fail(db_session, SHA)
        assert _spent_attempts(db_session, "b" * 64) is False

    def test_successes_do_not_count_against_the_cap(self, db_session):
        for _ in range(MAX_UPLOAD_ATTEMPTS):
            db_session.add(ReportLog(
                report_type="virustotal", identifier=SHA, success=True,
                detail="Submitted", reported_at=datetime.utcnow(),
            ))
        db_session.commit()
        assert _spent_attempts(db_session, SHA) is False
