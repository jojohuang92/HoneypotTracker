"""Tests for the IOC collection query helper and export formatters."""

from datetime import datetime, timedelta
from ipaddress import ip_address

from app.services.ioc_export import (
    CSV_HEADER,
    HashIoc,
    IocSet,
    IpIoc,
    UrlIoc,
    build_blocklist,
    build_csv,
    build_stix_bundle,
    collect_iocs,
)
from tests.conftest import make_attempt, make_captured_file

UTCNOW = datetime.utcnow()
RECENT = UTCNOW - timedelta(days=1)
OLD = UTCNOW - timedelta(days=90)
CUTOFF_30D = UTCNOW - timedelta(days=30)


def test_window_filtering_excludes_old_attempts(db_session):
    make_attempt(db_session, src_ip="1.2.3.4", timestamp=RECENT)
    make_attempt(db_session, src_ip="1.2.3.5", timestamp=OLD)

    iocs = collect_iocs(db_session, cutoff=CUTOFF_30D)

    assert [ip.value for ip in iocs.ips] == ["1.2.3.4"]


def test_private_ips_excluded(db_session):
    for ip in ["192.168.1.5", "10.0.0.8", "127.0.0.1", "169.254.1.1"]:
        make_attempt(db_session, src_ip=ip, timestamp=RECENT)
    make_attempt(db_session, src_ip="1.2.3.4", timestamp=RECENT)

    iocs = collect_iocs(db_session, cutoff=CUTOFF_30D)

    assert [ip.value for ip in iocs.ips] == ["1.2.3.4"]


def test_ip_aggregation_and_dominant_intent(db_session):
    t1, t2, t3 = RECENT, RECENT + timedelta(hours=1), RECENT + timedelta(hours=2)
    make_attempt(db_session, src_ip="1.2.3.4", timestamp=t1, intent="brute_force")
    make_attempt(db_session, src_ip="1.2.3.4", timestamp=t2, intent="cryptomining")
    make_attempt(db_session, src_ip="1.2.3.4", timestamp=t3, intent="cryptomining")

    iocs = collect_iocs(db_session, cutoff=CUTOFF_30D)

    assert len(iocs.ips) == 1
    ip = iocs.ips[0]
    assert ip.count == 3
    assert ip.first_seen == t1
    assert ip.last_seen == t3
    assert ip.intent == "cryptomining"
    assert ip.country == "US"


def test_dominant_intent_falls_back_to_unknown(db_session):
    make_attempt(db_session, src_ip="1.2.3.4", timestamp=RECENT, intent="unknown")
    make_attempt(db_session, src_ip="1.2.3.4", timestamp=RECENT, intent=None)

    iocs = collect_iocs(db_session, cutoff=CUTOFF_30D)

    assert iocs.ips[0].intent == "unknown"


def test_hashes_deduped_by_sha256(db_session):
    make_captured_file(db_session, sha256="a" * 64, timestamp=RECENT,
                       vt_positives=42, vt_total=70)
    make_captured_file(db_session, sha256="a" * 64, timestamp=RECENT + timedelta(hours=2))
    make_captured_file(db_session, sha256="b" * 64, timestamp=OLD)  # outside window

    iocs = collect_iocs(db_session, cutoff=CUTOFF_30D)

    assert len(iocs.hashes) == 1
    h = iocs.hashes[0]
    assert h.sha256 == "a" * 64
    assert h.count == 2
    assert h.vt_positives == 42


def test_urls_deduped(db_session):
    make_captured_file(db_session, sha256="a" * 64, timestamp=RECENT,
                       url="http://1.2.3.9/bins.sh")
    make_captured_file(db_session, sha256="b" * 64, timestamp=RECENT,
                       url="http://1.2.3.9/bins.sh")
    make_captured_file(db_session, sha256="c" * 64, timestamp=RECENT, url=None)

    iocs = collect_iocs(db_session, cutoff=CUTOFF_30D)

    assert len(iocs.urls) == 1
    assert iocs.urls[0].value == "http://1.2.3.9/bins.sh"
    assert iocs.urls[0].count == 2


def test_empty_db_returns_empty_iocset(db_session):
    iocs = collect_iocs(db_session, cutoff=CUTOFF_30D)
    assert iocs.ips == [] and iocs.hashes == [] and iocs.urls == []


# ---------------------------------------------------------------------------
# Formatters (pure functions — no DB)
# ---------------------------------------------------------------------------

T1 = datetime(2026, 6, 21, 11, 0, 2)
T2 = datetime(2026, 7, 1, 22, 9, 14)


def _ip(value="1.2.3.4", **kw):
    defaults = dict(first_seen=T1, last_seen=T2, count=143,
                    intent="brute_force", country="CN")
    defaults.update(kw)
    return IpIoc(value=value, **defaults)


def _hash(**kw):
    defaults = dict(sha256="e3" * 32, md5="ab" * 16, sha1="cd" * 20,
                    filename="xmrig", vt_positives=42, vt_total=70,
                    first_seen=T1, last_seen=T1, count=1)
    defaults.update(kw)
    return HashIoc(**defaults)


def test_blocklist_sorted_with_header():
    iocs = IocSet(ips=[_ip("1.2.3.10"), _ip("1.2.3.4")], hashes=[], urls=[])
    # collect_iocs sorts; build_blocklist must preserve order and emit header
    iocs.ips.sort(key=lambda i: ip_address(i.value))

    out = build_blocklist(iocs, days=30, generated_at=T2)

    lines = out.splitlines()
    comments = [l for l in lines if l.startswith("#")]
    ips = [l for l in lines if not l.startswith("#")]
    assert ips == ["1.2.3.4", "1.2.3.10"]  # numeric sort, not lexicographic
    assert any("30" in c for c in comments)          # window in header
    assert any("2026-07-01T22:09:14Z" in c for c in comments)  # timestamp


def test_blocklist_empty_is_header_only():
    out = build_blocklist(IocSet([], [], []), days=30, generated_at=T2)
    assert all(l.startswith("#") for l in out.splitlines())


def test_csv_shape_and_rows():
    iocs = IocSet(
        ips=[_ip()],
        hashes=[_hash()],
        urls=[UrlIoc(value="http://1.2.3.9/a,b.sh", first_seen=T1,
                     last_seen=T1, count=1)],
    )

    out = build_csv(iocs)
    lines = out.strip().splitlines()

    assert lines[0] == CSV_HEADER
    assert lines[1] == "ip,1.2.3.4,2026-06-21T11:00:02Z,2026-07-01T22:09:14Z,143,brute_force,CN,"
    assert lines[2].startswith(f"sha256,{'e3' * 32},")
    assert "filename=xmrig;vt=42/70" in lines[2]
    assert "malware_deployment" in lines[2]
    # comma inside URL must be quoted
    assert '"http://1.2.3.9/a,b.sh"' in lines[3]


def test_csv_empty_is_header_only():
    assert build_csv(IocSet([], [], [])).strip() == CSV_HEADER


# ---------------------------------------------------------------------------
# STIX 2.1 bundle
# ---------------------------------------------------------------------------

def _bundle(iocs=None):
    return build_stix_bundle(iocs or IocSet([], [], []), generated_at=T2)


def test_stix_bundle_structure():
    b = _bundle()
    assert b["type"] == "bundle"
    assert b["id"].startswith("bundle--")
    identities = [o for o in b["objects"] if o["type"] == "identity"]
    assert len(identities) == 1
    assert identities[0]["name"] == "HoneypotTracker"
    assert identities[0]["spec_version"] == "2.1"


def test_stix_indicator_patterns():
    iocs = IocSet(
        ips=[_ip()],
        hashes=[_hash()],
        urls=[UrlIoc(value="http://1.2.3.9/it's.sh", first_seen=T1,
                     last_seen=T1, count=1)],
    )
    b = _bundle(iocs)
    indicators = [o for o in b["objects"] if o["type"] == "indicator"]
    patterns = {i["pattern"] for i in indicators}

    assert "[ipv4-addr:value = '1.2.3.4']" in patterns
    assert f"[file:hashes.'SHA-256' = '{'e3' * 32}']" in patterns
    assert "[url:value = 'http://1.2.3.9/it\\'s.sh']" in patterns  # quote escaped
    for i in indicators:
        assert i["spec_version"] == "2.1"
        assert i["pattern_type"] == "stix"
        assert "malicious-activity" in i["labels"]
        assert i["created_by_ref"].startswith("identity--")


def test_stix_intent_label_and_valid_from():
    b = _bundle(IocSet(ips=[_ip(intent="cryptomining")], hashes=[], urls=[]))
    ind = [o for o in b["objects"] if o["type"] == "indicator"][0]
    assert "cryptomining" in ind["labels"]
    assert ind["valid_from"] == "2026-06-21T11:00:02Z"


def test_stix_unknown_intent_not_labeled():
    b = _bundle(IocSet(ips=[_ip(intent="unknown")], hashes=[], urls=[]))
    ind = [o for o in b["objects"] if o["type"] == "indicator"][0]
    assert ind["labels"] == ["malicious-activity"]


def test_stix_ids_deterministic_across_exports():
    iocs = IocSet(ips=[_ip()], hashes=[_hash()], urls=[])
    ids_a = sorted(o["id"] for o in _bundle(iocs)["objects"] if o["type"] == "indicator")
    ids_b = sorted(o["id"] for o in _bundle(iocs)["objects"] if o["type"] == "indicator")
    assert ids_a == ids_b

    # identity id is stable too; bundle id is per-export
    ident_a = [o["id"] for o in _bundle()["objects"] if o["type"] == "identity"]
    ident_b = [o["id"] for o in _bundle()["objects"] if o["type"] == "identity"]
    assert ident_a == ident_b
