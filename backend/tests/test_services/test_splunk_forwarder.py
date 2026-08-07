"""Tests for the Splunk HEC forwarder service."""

from unittest.mock import patch, MagicMock, AsyncMock

import httpx
import pytest


@pytest.mark.asyncio
class TestSplunkForwarderSend:
    @patch("app.services.splunk_forwarder.settings")
    async def test_skips_when_no_url(self, mock_settings):
        mock_settings.splunk_hec_url = ""
        mock_settings.splunk_hec_token = "some-token"

        mock_client = AsyncMock()
        with patch("app.services.splunk_forwarder.httpx.AsyncClient", return_value=mock_client):
            from app.services.splunk_forwarder import send
            await send({"type": "login_attempt", "src_ip": "1.2.3.4"})

        mock_client.__aenter__.assert_not_called()

    @patch("app.services.splunk_forwarder.settings")
    async def test_skips_when_no_token(self, mock_settings):
        mock_settings.splunk_hec_url = "https://splunk.example.com:8088"
        mock_settings.splunk_hec_token = ""

        mock_client = AsyncMock()
        with patch("app.services.splunk_forwarder.httpx.AsyncClient", return_value=mock_client):
            from app.services.splunk_forwarder import send
            await send({"type": "login_attempt", "src_ip": "1.2.3.4"})

        mock_client.__aenter__.assert_not_called()

    @patch("app.services.splunk_forwarder.settings")
    async def test_posts_to_hec_endpoint_with_auth(self, mock_settings):
        mock_settings.splunk_hec_url = "https://splunk.example.com:8088"
        mock_settings.splunk_hec_token = "test-token-xyz"
        mock_settings.splunk_hec_verify_ssl = True

        mock_resp = MagicMock()
        mock_resp.status_code = 200

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_resp)

        payload = {"type": "login_attempt", "src_ip": "1.2.3.4", "username": "root"}

        with patch(
            "app.services.splunk_forwarder.httpx.AsyncClient", return_value=mock_client
        ):
            from app.services.splunk_forwarder import send
            await send(payload)

        mock_client.post.assert_called_once()
        call = mock_client.post.call_args
        url = call.args[0] if call.args else call.kwargs["url"]
        assert url == "https://splunk.example.com:8088/services/collector/event"

        headers = call.kwargs["headers"]
        assert headers["Authorization"] == "Splunk test-token-xyz"

        body = call.kwargs["json"]
        assert body["event"] == payload
        assert body["sourcetype"] == "cowrie:honeypot"
        assert "time" in body

    @patch("app.services.splunk_forwarder.settings")
    async def test_strips_trailing_slash_from_url(self, mock_settings):
        mock_settings.splunk_hec_url = "https://splunk.example.com:8088/"
        mock_settings.splunk_hec_token = "t"
        mock_settings.splunk_hec_verify_ssl = True

        mock_resp = MagicMock()
        mock_resp.status_code = 200

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_resp)

        with patch(
            "app.services.splunk_forwarder.httpx.AsyncClient", return_value=mock_client
        ):
            from app.services.splunk_forwarder import send
            await send({"type": "command"})

        url = mock_client.post.call_args.args[0]
        assert url == "https://splunk.example.com:8088/services/collector/event"

    @patch("app.services.splunk_forwarder.settings")
    async def test_swallows_network_errors(self, mock_settings):
        """A Splunk outage must never propagate an exception to the caller."""
        mock_settings.splunk_hec_url = "https://splunk.example.com:8088"
        mock_settings.splunk_hec_token = "t"
        mock_settings.splunk_hec_verify_ssl = True

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(side_effect=httpx.ConnectError("boom"))

        with patch(
            "app.services.splunk_forwarder.httpx.AsyncClient", return_value=mock_client
        ):
            from app.services.splunk_forwarder import send
            # Must not raise
            await send({"type": "login_attempt"})

    @patch("app.services.splunk_forwarder.settings")
    async def test_logs_warning_on_non_2xx(self, mock_settings, caplog):
        mock_settings.splunk_hec_url = "https://splunk.example.com:8088"
        mock_settings.splunk_hec_token = "bad-token"
        mock_settings.splunk_hec_verify_ssl = True

        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.text = "invalid token"

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_resp)

        import logging
        with patch(
            "app.services.splunk_forwarder.httpx.AsyncClient", return_value=mock_client
        ), caplog.at_level(logging.WARNING, logger="app.services.splunk_forwarder"):
            from app.services.splunk_forwarder import send
            await send({"type": "command"})

        assert any("401" in rec.message for rec in caplog.records)
