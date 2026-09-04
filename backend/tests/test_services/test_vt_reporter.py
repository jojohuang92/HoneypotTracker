"""Tests for VT reporter file-path resolution.

Cowrie logs 'outfile' relative to its own working directory, so the stored
path rarely resolves from here. Resolution is confined to the configured
downloads directory: the path travels through the database from an event
payload, and anything it resolves to gets uploaded to a third party.
"""

from unittest.mock import patch

from app.services.vt_reporter import _resolve_file_path

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
