"""Collect and format the honeypot's IOCs for export (blocklist / CSV / STIX 2.1)."""

from __future__ import annotations

import csv
import io
import uuid
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from ipaddress import ip_address

from sqlalchemy import func
from sqlalchemy.orm import Session as DBSession

from app.models import Attempt, CapturedFile


@dataclass
class IpIoc:
    value: str
    first_seen: datetime
    last_seen: datetime
    count: int
    intent: str
    country: str | None


@dataclass
class HashIoc:
    sha256: str
    md5: str | None
    sha1: str | None
    filename: str | None
    vt_positives: int | None
    vt_total: int | None
    first_seen: datetime
    last_seen: datetime
    count: int


@dataclass
class UrlIoc:
    value: str
    first_seen: datetime
    last_seen: datetime
    count: int


@dataclass
class IocSet:
    ips: list[IpIoc]
    hashes: list[HashIoc]
    urls: list[UrlIoc]


def _is_exportable_ip(value: str) -> bool:
    """Only publicly-routable addresses may appear in a published feed."""
    try:
        addr = ip_address(value)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_multicast or addr.is_reserved or addr.is_unspecified)


def _dominant_intent(intent_counts: Counter) -> str:
    """Most frequent non-unknown intent, else 'unknown'."""
    for intent, _ in intent_counts.most_common():
        if intent and intent != "unknown":
            return intent
    return "unknown"


def collect_iocs(db: DBSession, cutoff: datetime) -> IocSet:
    # --- IPs: aggregate attempts per source address ---------------------
    ip_rows = (
        db.query(
            Attempt.src_ip,
            func.min(Attempt.timestamp),
            func.max(Attempt.timestamp),
            func.count(Attempt.id),
            func.max(Attempt.country_code),
        )
        .filter(Attempt.timestamp >= cutoff)
        .group_by(Attempt.src_ip)
        .all()
    )

    intent_rows = (
        db.query(Attempt.src_ip, Attempt.intent, func.count(Attempt.id))
        .filter(Attempt.timestamp >= cutoff)
        .group_by(Attempt.src_ip, Attempt.intent)
        .all()
    )
    intents_by_ip: dict[str, Counter] = {}
    for src_ip, intent, n in intent_rows:
        intents_by_ip.setdefault(src_ip, Counter())[intent] = n

    ips = [
        IpIoc(
            value=src_ip,
            first_seen=first,
            last_seen=last,
            count=n,
            intent=_dominant_intent(intents_by_ip.get(src_ip, Counter())),
            country=country,
        )
        for src_ip, first, last, n, country in ip_rows
        if _is_exportable_ip(src_ip)
    ]
    ips.sort(key=lambda i: ip_address(i.value))

    # --- File hashes: dedup by sha256 ------------------------------------
    hash_rows = (
        db.query(
            CapturedFile.sha256,
            func.max(CapturedFile.md5),
            func.max(CapturedFile.sha1),
            func.max(CapturedFile.filename),
            func.max(CapturedFile.vt_positives),
            func.max(CapturedFile.vt_total),
            func.min(CapturedFile.timestamp),
            func.max(CapturedFile.timestamp),
            func.count(CapturedFile.id),
        )
        .filter(CapturedFile.timestamp >= cutoff, CapturedFile.sha256.isnot(None))
        .group_by(CapturedFile.sha256)
        .all()
    )
    hashes = [
        HashIoc(sha256=s, md5=m5, sha1=s1, filename=fn,
                vt_positives=vp, vt_total=vt,
                first_seen=first, last_seen=last, count=n)
        for s, m5, s1, fn, vp, vt, first, last, n in hash_rows
    ]

    # --- URLs: dedup by value --------------------------------------------
    url_rows = (
        db.query(
            CapturedFile.url,
            func.min(CapturedFile.timestamp),
            func.max(CapturedFile.timestamp),
            func.count(CapturedFile.id),
        )
        .filter(
            CapturedFile.timestamp >= cutoff,
            CapturedFile.url.isnot(None),
            CapturedFile.url != "",
        )
        .group_by(CapturedFile.url)
        .all()
    )
    urls = [
        UrlIoc(value=u, first_seen=first, last_seen=last, count=n)
        for u, first, last, n in url_rows
    ]

    return IocSet(ips=ips, hashes=hashes, urls=urls)


# ---------------------------------------------------------------------------
# Formatters
# ---------------------------------------------------------------------------

CSV_HEADER = "type,value,first_seen,last_seen,count,intent,country,extra"


def _iso_z(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def build_blocklist(iocs: IocSet, days: int, generated_at: datetime) -> str:
    """One IP per line; '#' comment header with provenance."""
    lines = [
        "# HoneypotTracker blocklist",
        f"# generated_at: {_iso_z(generated_at)}",
        f"# window_days: {days}",
        f"# count: {len(iocs.ips)}",
    ]
    lines += [ip.value for ip in iocs.ips]
    return "\n".join(lines) + "\n"


def build_csv(iocs: IocSet) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(CSV_HEADER.split(","))

    for ip in iocs.ips:
        writer.writerow([
            "ip", ip.value, _iso_z(ip.first_seen), _iso_z(ip.last_seen),
            ip.count, ip.intent, ip.country or "", "",
        ])
    for h in iocs.hashes:
        extra_parts = []
        if h.filename:
            extra_parts.append(f"filename={h.filename}")
        if h.vt_positives is not None and h.vt_total is not None:
            extra_parts.append(f"vt={h.vt_positives}/{h.vt_total}")
        writer.writerow([
            "sha256", h.sha256, _iso_z(h.first_seen), _iso_z(h.last_seen),
            h.count, "malware_deployment", "", ";".join(extra_parts),
        ])
    for u in iocs.urls:
        writer.writerow([
            "url", u.value, _iso_z(u.first_seen), _iso_z(u.last_seen),
            u.count, "malware_deployment", "", "",
        ])
    return buf.getvalue()


# ---------------------------------------------------------------------------
# STIX 2.1
# ---------------------------------------------------------------------------

# Fixed namespace so indicator/identity ids are stable across exports —
# consumers can dedupe pulls. Do not change once published.
IOC_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_DNS, "honeypottracker.export")

_IDENTITY_ID = f"identity--{uuid.uuid5(IOC_NAMESPACE, 'honeypottracker-identity')}"


def _escape_stix(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _indicator(pattern_value: str, pattern: str, first_seen: datetime,
               generated_at: datetime, intent: str | None) -> dict:
    labels = ["malicious-activity"]
    if intent and intent != "unknown":
        labels.append(intent)
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{uuid.uuid5(IOC_NAMESPACE, pattern_value)}",
        "created_by_ref": _IDENTITY_ID,
        "created": _iso_z(generated_at),
        "modified": _iso_z(generated_at),
        "valid_from": _iso_z(first_seen),
        "pattern_type": "stix",
        "pattern": pattern,
        "labels": labels,
    }


def build_stix_bundle(iocs: IocSet, generated_at: datetime) -> dict:
    objects: list[dict] = [{
        "type": "identity",
        "spec_version": "2.1",
        "id": _IDENTITY_ID,
        "created": _iso_z(generated_at),
        "modified": _iso_z(generated_at),
        "name": "HoneypotTracker",
        "identity_class": "system",
    }]

    for ip in iocs.ips:
        objects.append(_indicator(
            ip.value, f"[ipv4-addr:value = '{_escape_stix(ip.value)}']",
            ip.first_seen, generated_at, ip.intent,
        ))
    for h in iocs.hashes:
        objects.append(_indicator(
            h.sha256, f"[file:hashes.'SHA-256' = '{_escape_stix(h.sha256)}']",
            h.first_seen, generated_at, "malware_deployment",
        ))
    for u in iocs.urls:
        objects.append(_indicator(
            u.value, f"[url:value = '{_escape_stix(u.value)}']",
            u.first_seen, generated_at, "malware_deployment",
        ))

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }
