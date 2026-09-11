"""The alert that fires when a scheduled backup fails.

A backup that fails silently is indistinguishable from no backup at all, which
is the failure mode this whole feature exists to prevent. So the notifier gets
the same treatment as the scripts it watches.
"""

import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
NOTIFY_SH = REPO_ROOT / "scripts" / "notify-failure.sh"


class _Collector(BaseHTTPRequestHandler):
    received: list[tuple[str, str]] = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        type(self).received.append((self.path, self.rfile.read(length).decode()))
        self.send_response(200)
        self.end_headers()

    def log_message(self, *_args):
        pass


@pytest.fixture()
def ntfy():
    """A stand-in ntfy endpoint that records what was posted to it."""
    _Collector.received = []
    server = HTTPServer(("127.0.0.1", 0), _Collector)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}/honeypot", _Collector
    server.shutdown()
    server.server_close()


def run_notify(env_file: Path, unit: str = "honeypot-backup.service"):
    return subprocess.run(
        [str(NOTIFY_SH), unit],
        env={"PATH": "/usr/bin:/bin", "HP_ENV_FILE": str(env_file)},
        capture_output=True,
        text=True,
    )


def test_posts_the_failing_unit_name_to_ntfy(tmp_path, ntfy):
    url, collector = ntfy
    env_file = tmp_path / ".env"
    env_file.write_text(f"NTFY_URL={url}\nADMIN_API_KEY=irrelevant\n")

    result = run_notify(env_file)

    assert result.returncode == 0, result.stderr
    assert len(collector.received) == 1
    path, body = collector.received[0]
    assert path == "/honeypot"
    assert "honeypot-backup.service" in body


def test_stays_quiet_and_succeeds_when_no_url_is_configured(tmp_path, ntfy):
    _url, collector = ntfy
    env_file = tmp_path / ".env"
    env_file.write_text("NTFY_URL=\n")

    result = run_notify(env_file)

    assert result.returncode == 0
    assert collector.received == []


def test_succeeds_when_the_env_file_is_missing(tmp_path):
    """A misconfigured notifier must not itself become a failing unit."""
    result = run_notify(tmp_path / "absent.env")

    assert result.returncode == 0
