"""Storing static-analysis results: batching, deduplication, failure handling."""

import json
from datetime import datetime

import pytest

from app.models import CapturedFile
from app.services import static_analysis
from app.services.static_analysis import (
    pending_file_ids,
    propagate_to_duplicates,
)

SHA_A = "a" * 64
SHA_B = "b" * 64


def add_file(db, sha, **kw):
    f = CapturedFile(
        session_id="s1", sha256=sha, timestamp=datetime.utcnow(),
        filename="x", url="", local_path="", **kw
    )
    db.add(f)
    db.commit()
    return f


class TestPendingSelection:
    def test_returns_one_row_per_distinct_hash(self, db_session):
        """The same sample is captured thousands of times; the bytes are identical."""
        for _ in range(5):
            add_file(db_session, SHA_A)
        add_file(db_session, SHA_B)
        assert len(pending_file_ids(db_session)) == 2

    def test_skips_already_analyzed(self, db_session):
        add_file(db_session, SHA_A, static_analyzed_at=datetime.utcnow())
        add_file(db_session, SHA_B)
        ids = pending_file_ids(db_session)
        assert len(ids) == 1
        assert db_session.get(CapturedFile, ids[0]).sha256 == SHA_B

    def test_skips_rows_with_an_empty_hash(self, db_session):
        """NULL is impossible (sha256 is NOT NULL); empty string is not."""
        add_file(db_session, "")
        assert pending_file_ids(db_session) == []

    def test_respects_the_batch_limit(self, db_session):
        for i in range(10):
            add_file(db_session, f"{i:064d}")
        assert len(pending_file_ids(db_session, limit=3)) == 3


class TestPropagation:
    def test_copies_findings_onto_every_row_with_the_same_hash(self, db_session):
        src = add_file(db_session, SHA_A)
        others = [add_file(db_session, SHA_A) for _ in range(3)]
        add_file(db_session, SHA_B)  # untouched

        src.arch = "MIPS"
        src.malware_family = "mirai"
        src.yara_matches = json.dumps(["mirai.marker"])
        src.static_analyzed_at = datetime.utcnow()
        db_session.commit()

        assert propagate_to_duplicates(db_session, src.id) == 3
        for o in others:
            db_session.refresh(o)
            assert o.arch == "MIPS"
            assert o.malware_family == "mirai"

    def test_does_not_touch_other_hashes(self, db_session):
        src = add_file(db_session, SHA_A)
        other = add_file(db_session, SHA_B)
        src.arch = "ARM"
        src.static_analyzed_at = datetime.utcnow()
        db_session.commit()
        propagate_to_duplicates(db_session, src.id)
        db_session.refresh(other)
        assert other.arch is None

    def test_is_a_noop_when_source_was_never_analyzed(self, db_session):
        src = add_file(db_session, SHA_A)
        add_file(db_session, SHA_A)
        assert propagate_to_duplicates(db_session, src.id) == 0


class TestAnalyzeCapturedFile:
    def test_stores_findings_for_a_resolvable_sample(self, db_session, tmp_path, monkeypatch):
        sample = tmp_path / SHA_A
        sample.write_bytes(b"\x7fELF\x01\x02\x01" + b"\x00" * 9
                           + bytes([0, 2, 0, 8]) + b"\x00" * 40
                           + b"/bin/busybox MIRAI\x00talks to 45.9.148.99\x00")
        f = add_file(db_session, SHA_A)
        monkeypatch.setattr(static_analysis, "SessionLocal", lambda: db_session)
        monkeypatch.setattr(db_session, "close", lambda: None)
        monkeypatch.setattr(
            "app.services.vt_reporter._resolve_file_path", lambda p, s: sample
        )

        assert static_analysis.analyze_captured_file(f.id) is True
        db_session.refresh(f)
        assert f.malware_family == "mirai"
        assert f.arch == "MIPS"
        assert "45.9.148.99" in json.loads(f.static_iocs)["ipv4"]
        assert f.static_analyzed_at is not None

    def test_missing_sample_is_marked_examined_but_not_analyzed(
        self, db_session, monkeypatch
    ):
        """Leaving yara_matches NULL keeps the cleanup script from deleting it."""
        f = add_file(db_session, SHA_A)
        monkeypatch.setattr(static_analysis, "SessionLocal", lambda: db_session)
        monkeypatch.setattr(db_session, "close", lambda: None)
        monkeypatch.setattr(
            "app.services.vt_reporter._resolve_file_path", lambda p, s: None
        )

        assert static_analysis.analyze_captured_file(f.id) is False
        db_session.refresh(f)
        assert f.static_analyzed_at is not None
        assert f.yara_matches is None

    def test_unknown_id_is_handled(self, db_session, monkeypatch):
        monkeypatch.setattr(static_analysis, "SessionLocal", lambda: db_session)
        monkeypatch.setattr(db_session, "close", lambda: None)
        assert static_analysis.analyze_captured_file(999999) is False
