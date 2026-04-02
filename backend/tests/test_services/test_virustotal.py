"""Tests for the VirusTotal enrichment service."""

from datetime import datetime
from unittest.mock import patch, MagicMock, AsyncMock

import pytest
from sqlalchemy import create_engine, event as sa_event
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import CapturedFile


@pytest.fixture()
def db_engine():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})

    @sa_event.listens_for(engine, "connect")
    def _pragma(conn, _):
        cur = conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    Base.metadata.create_all(bind=engine)
    yield engine
    engine.dispose()


@pytest.fixture()
def db(db_engine):
    DBSession = sessionmaker(bind=db_engine)
    session = DBSession()
    yield session
    session.close()


@pytest.mark.asyncio
class TestEnrichCapturedFile:
    @patch("app.services.virustotal.settings")
    async def test_no_api_key_skips(self, mock_settings):
        mock_settings.virustotal_api_key = ""
        from app.services.virustotal import enrich_captured_file
        await enrich_captured_file(999)

    @patch("app.services.virustotal.settings")
    async def test_successful_enrichment(self, mock_settings, db):
        mock_settings.virustotal_api_key = "test-key"

        cf = CapturedFile(
            session_id="s1", timestamp=datetime(2025, 6, 15),
            sha256="a" * 64,
        )
        db.add(cf)
        db.commit()
        db.refresh(cf)
        file_id = cf.id

        vt_response = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 42,
                        "undetected": 20,
                        "harmless": 5,
                    },
                    "size": 1024,
                    "type_description": "ELF executable",
                }
            }
        }

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = vt_response

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_resp)

        # Mock SessionLocal to return a fresh session bound to same engine
        mock_db = MagicMock(wraps=db)
        # Prevent the finally block from actually closing our test session
        mock_db.close = MagicMock()

        with patch("app.services.virustotal.httpx.AsyncClient", return_value=mock_client), \
             patch("app.services.virustotal.SessionLocal", return_value=mock_db):
            from app.services.virustotal import enrich_captured_file
            await enrich_captured_file(file_id)

        db.refresh(cf)
        assert cf.vt_positives == 42
        assert cf.vt_total == 67  # 42 + 20 + 5
        assert cf.file_size == 1024
        assert cf.file_type == "ELF executable"
        assert "virustotal.com" in cf.vt_link

    @patch("app.services.virustotal.settings")
    async def test_404_skips_gracefully(self, mock_settings, db):
        mock_settings.virustotal_api_key = "test-key"

        cf = CapturedFile(
            session_id="s1", timestamp=datetime(2025, 6, 15),
            sha256="b" * 64,
        )
        db.add(cf)
        db.commit()
        db.refresh(cf)
        file_id = cf.id

        mock_resp = MagicMock()
        mock_resp.status_code = 404

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_resp)

        mock_db = MagicMock(wraps=db)
        mock_db.close = MagicMock()

        with patch("app.services.virustotal.httpx.AsyncClient", return_value=mock_client), \
             patch("app.services.virustotal.SessionLocal", return_value=mock_db):
            from app.services.virustotal import enrich_captured_file
            await enrich_captured_file(file_id)

        db.refresh(cf)
        assert cf.vt_positives is None
