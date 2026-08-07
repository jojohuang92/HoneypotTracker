"""Tests for VT reporter file-path resolution (Cowrie logs relative paths)."""

from unittest.mock import patch

from app.services.vt_reporter import _resolve_file_path

SHA = "a" * 64


class TestResolveFilePath:
    def test_absolute_existing_path_used_directly(self, tmp_path):
        f = tmp_path / "sample.bin"
        f.write_bytes(b"x")
        assert _resolve_file_path(str(f), SHA) == f

    def test_absolute_missing_path_returns_none(self, tmp_path):
        assert _resolve_file_path(str(tmp_path / "gone"), SHA) is None

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
