"""Tests for the push-alert service (ntfy / Discord)."""

from unittest.mock import patch, MagicMock, AsyncMock

import pytest

from app.services import alerts


@pytest.fixture(autouse=True)
def _reset_alert_state():
    """Alert cooldowns and the seen-country cache are module-global."""
    alerts._last_sent.clear()
    alerts._known_countries = None
    yield
    alerts._last_sent.clear()
    alerts._known_countries = None


def _mock_client(status_code: int = 200):
    resp = MagicMock()
    resp.status_code = status_code
    client = AsyncMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    client.post = AsyncMock(return_value=resp)
    return client


def _configure(mock_settings, ntfy="https://ntfy.sh/test", discord=""):
    mock_settings.ntfy_url = ntfy
    mock_settings.discord_webhook_url = discord
    mock_settings.alert_cooldown_minutes = 30
    mock_settings.alert_vt_min_positives = 3


@pytest.mark.asyncio
class TestSendAlert:
    @patch("app.services.alerts.settings")
    async def test_disabled_without_urls(self, mock_settings):
        _configure(mock_settings, ntfy="", discord="")
        client = _mock_client()
        with patch("app.services.alerts.httpx.AsyncClient", return_value=client):
            await alerts.send_alert("t", "m")
        client.post.assert_not_called()

    @patch("app.services.alerts.settings")
    async def test_posts_to_ntfy_with_title_and_priority(self, mock_settings):
        _configure(mock_settings)
        client = _mock_client()
        with patch("app.services.alerts.httpx.AsyncClient", return_value=client):
            await alerts.send_alert("Title here", "body", priority="high")

        call = client.post.call_args
        assert call.args[0] == "https://ntfy.sh/test"
        assert call.kwargs["headers"]["Title"] == "Title here"
        assert call.kwargs["headers"]["Priority"] == "high"
        assert call.kwargs["content"] == b"body"

    @patch("app.services.alerts.settings")
    async def test_posts_to_discord_as_json(self, mock_settings):
        _configure(mock_settings, ntfy="", discord="https://discord.com/api/webhooks/x")
        client = _mock_client()
        with patch("app.services.alerts.httpx.AsyncClient", return_value=client):
            await alerts.send_alert("Title", "body")

        call = client.post.call_args
        assert call.args[0] == "https://discord.com/api/webhooks/x"
        assert "**Title**" in call.kwargs["json"]["content"]
        assert "body" in call.kwargs["json"]["content"]

    @patch("app.services.alerts.settings")
    async def test_sends_to_both_channels_when_configured(self, mock_settings):
        _configure(mock_settings, discord="https://discord.com/api/webhooks/x")
        client = _mock_client()
        with patch("app.services.alerts.httpx.AsyncClient", return_value=client):
            await alerts.send_alert("t", "m")
        assert client.post.call_count == 2

    @patch("app.services.alerts.settings")
    async def test_swallows_network_errors(self, mock_settings):
        """An alerting outage must never propagate to ingestion."""
        import httpx as _httpx
        _configure(mock_settings)
        client = _mock_client()
        client.post = AsyncMock(side_effect=_httpx.ConnectError("boom"))
        with patch("app.services.alerts.httpx.AsyncClient", return_value=client):
            await alerts.send_alert("t", "m")  # must not raise


class TestCooldown:
    @patch("app.services.alerts.settings")
    def test_first_send_allowed_repeat_suppressed(self, mock_settings):
        _configure(mock_settings)
        assert alerts._should_send("k") is True
        assert alerts._should_send("k") is False

    @patch("app.services.alerts.settings")
    def test_distinct_keys_independent(self, mock_settings):
        _configure(mock_settings)
        assert alerts._should_send("a") is True
        assert alerts._should_send("b") is True

    @patch("app.services.alerts.settings")
    def test_allowed_again_after_cooldown(self, mock_settings):
        _configure(mock_settings)
        assert alerts._should_send("k") is True
        # Simulate the cooldown having elapsed
        alerts._last_sent["k"] -= 31 * 60
        assert alerts._should_send("k") is True


@pytest.mark.asyncio
class TestAlertForEvent:
    @patch("app.services.alerts.send_alert", new_callable=AsyncMock)
    @patch("app.services.alerts.settings")
    async def test_noop_when_disabled(self, mock_settings, mock_send):
        _configure(mock_settings, ntfy="", discord="")
        await alerts.alert_for_event(
            {"type": "login_attempt", "success": True, "src_ip": "1.2.3.4"}
        )
        mock_send.assert_not_called()

    @patch("app.services.alerts.send_alert", new_callable=AsyncMock)
    @patch("app.services.alerts.settings")
    async def test_successful_login_alerts(self, mock_settings, mock_send):
        _configure(mock_settings)
        await alerts.alert_for_event({
            "type": "login_attempt", "success": True,
            "src_ip": "1.2.3.4", "username": "root", "country": "France",
        })
        mock_send.assert_called_once()
        title, message = mock_send.call_args.args[:2]
        assert "successful login" in title.lower()
        assert "1.2.3.4" in message
        assert "root" in message

    @patch("app.services.alerts.send_alert", new_callable=AsyncMock)
    @patch("app.services.alerts.settings")
    async def test_failed_login_does_not_alert(self, mock_settings, mock_send):
        _configure(mock_settings)
        await alerts.alert_for_event({
            "type": "login_attempt", "success": False, "src_ip": "1.2.3.4",
        })
        mock_send.assert_not_called()

    @patch("app.services.alerts.send_alert", new_callable=AsyncMock)
    @patch("app.services.alerts.settings")
    async def test_file_download_alerts_once_per_hash(self, mock_settings, mock_send):
        _configure(mock_settings)
        event = {
            "type": "file_download", "src_ip": "1.2.3.4",
            "sha256": "ab" * 32, "url": "http://evil.com/x",
        }
        await alerts.alert_for_event(event)
        await alerts.alert_for_event(event)
        mock_send.assert_called_once()

    @patch("app.services.alerts.send_alert", new_callable=AsyncMock)
    @patch("app.services.alerts.settings")
    async def test_command_events_do_not_alert(self, mock_settings, mock_send):
        _configure(mock_settings)
        await alerts.alert_for_event({
            "type": "command", "src_ip": "1.2.3.4", "command": "uname -a",
        })
        mock_send.assert_not_called()

    @patch("app.services.alerts._load_known_countries", return_value={"Germany"})
    @patch("app.services.alerts.send_alert", new_callable=AsyncMock)
    @patch("app.services.alerts.settings")
    async def test_new_country_alerts(self, mock_settings, mock_send, _mock_load):
        _configure(mock_settings)
        await alerts.alert_for_event({
            "type": "session_start", "src_ip": "1.2.3.4", "country": "Peru",
        })
        mock_send.assert_called_once()
        assert "Peru" in mock_send.call_args.args[1]

    @patch("app.services.alerts._load_known_countries", return_value={"Germany"})
    @patch("app.services.alerts.send_alert", new_callable=AsyncMock)
    @patch("app.services.alerts.settings")
    async def test_known_country_does_not_alert(self, mock_settings, mock_send, _mock_load):
        _configure(mock_settings)
        await alerts.alert_for_event({
            "type": "session_start", "src_ip": "1.2.3.4", "country": "Germany",
        })
        mock_send.assert_not_called()


@pytest.mark.asyncio
class TestAlertVtResult:
    @patch("app.services.alerts.send_alert", new_callable=AsyncMock)
    @patch("app.services.alerts.settings")
    async def test_alerts_at_threshold(self, mock_settings, mock_send):
        _configure(mock_settings)
        await alerts.alert_vt_result("ab" * 32, positives=3, total=70, filename="mal.sh")
        mock_send.assert_called_once()
        assert "3/70" in mock_send.call_args.args[1]

    @patch("app.services.alerts.send_alert", new_callable=AsyncMock)
    @patch("app.services.alerts.settings")
    async def test_below_threshold_is_silent(self, mock_settings, mock_send):
        _configure(mock_settings)
        await alerts.alert_vt_result("ab" * 32, positives=2, total=70)
        mock_send.assert_not_called()

    @patch("app.services.alerts.send_alert", new_callable=AsyncMock)
    @patch("app.services.alerts.settings")
    async def test_same_hash_alerts_once(self, mock_settings, mock_send):
        _configure(mock_settings)
        await alerts.alert_vt_result("ab" * 32, positives=10, total=70)
        await alerts.alert_vt_result("ab" * 32, positives=10, total=70)
        mock_send.assert_called_once()
