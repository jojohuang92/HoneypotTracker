"""Campaign correlation: grouping IPs that are running the same operation.

A single attacking IP is an event; twenty IPs trying the identical credential
list, or fetching the identical payload, are one campaign wearing twenty
addresses. Three fingerprints are computed per source IP inside a time window
and any fingerprint shared by two or more IPs becomes a campaign:

- ``credentials`` — the exact set of username:password pairs attempted
- ``payload``     — the SHA-256 of a file the IP fetched onto the honeypot
- ``commands``    — the exact set of commands run after login

Fingerprints are order-independent (sets, not sequences), because bots
randomize order far more often than they change content.
"""

import hashlib
from datetime import datetime, timedelta

from sqlalchemy.orm import Session as DBSession

from app.models import Attempt, CapturedFile
from app.schemas import Campaign

# Below these sizes a "shared set" is coincidence, not a signature: everyone
# tries root:123456, and everyone runs uname -a.
MIN_CREDENTIALS = 3
MIN_COMMANDS = 2
# A campaign needs at least this many distinct IPs.
MIN_IPS = 2


def _fingerprint(kind: str, items: set[str]) -> str:
    joined = "\n".join(sorted(items))
    return f"{kind}:{hashlib.sha256(joined.encode()).hexdigest()[:12]}"


def find_campaigns(
    db: DBSession,
    days: int = 7,
    sensor_id: str | None = None,
    limit: int = 50,
) -> list[Campaign]:
    since = datetime.utcnow() - timedelta(days=days)

    rows = db.query(
        Attempt.src_ip,
        Attempt.sensor_id,
        Attempt.username,
        Attempt.password,
        Attempt.command,
        Attempt.country_name,
        Attempt.asn,
        Attempt.timestamp,
        Attempt.id,
    ).filter(Attempt.timestamp >= since)
    if sensor_id:
        rows = rows.filter(Attempt.sensor_id == sensor_id)

    creds: dict[str, set[str]] = {}
    commands: dict[str, set[str]] = {}
    meta: dict[str, dict] = {}

    for r in rows.all():
        ip = r.src_ip
        info = meta.setdefault(
            ip,
            {
                "sensors": set(),
                "countries": set(),
                "asns": set(),
                "first": r.timestamp,
                "last": r.timestamp,
                "events": 0,
            },
        )
        info["events"] += 1
        if r.sensor_id:
            info["sensors"].add(r.sensor_id)
        if r.country_name:
            info["countries"].add(r.country_name)
        if r.asn:
            info["asns"].add(r.asn)
        if r.timestamp < info["first"]:
            info["first"] = r.timestamp
        if r.timestamp > info["last"]:
            info["last"] = r.timestamp

        if r.username is not None:
            creds.setdefault(ip, set()).add(f"{r.username}:{r.password or ''}")
        if r.command:
            commands.setdefault(ip, set()).add(r.command.strip())

    # Payload fingerprints: which IPs fetched which file hashes.
    payloads: dict[str, set[str]] = {}
    payload_rows = (
        db.query(Attempt.src_ip, CapturedFile.sha256)
        .join(CapturedFile, CapturedFile.attempt_id == Attempt.id)
        .filter(Attempt.timestamp >= since)
    )
    if sensor_id:
        payload_rows = payload_rows.filter(Attempt.sensor_id == sensor_id)
    for ip, sha256 in payload_rows.all():
        if sha256:
            payloads.setdefault(ip, set()).add(sha256)

    # fingerprint → {ips, sample}
    groups: dict[str, dict] = {}

    def add(kind: str, ip: str, items: set[str], minimum: int) -> None:
        if len(items) < minimum:
            return
        fp = _fingerprint(kind, items)
        group = groups.setdefault(fp, {"kind": kind, "ips": set(), "sample": sorted(items)})
        group["ips"].add(ip)

    for ip, items in creds.items():
        add("credentials", ip, items, MIN_CREDENTIALS)
    for ip, items in commands.items():
        add("commands", ip, items, MIN_COMMANDS)
    for ip, hashes in payloads.items():
        # Each hash stands alone: sharing one payload is already a link.
        for sha256 in hashes:
            add("payload", ip, {sha256}, 1)

    campaigns: list[Campaign] = []
    for fp, group in groups.items():
        ips = sorted(group["ips"])
        if len(ips) < MIN_IPS:
            continue

        sensors: set[str] = set()
        countries: set[str] = set()
        asns: set[int] = set()
        events = 0
        first: datetime | None = None
        last: datetime | None = None
        for ip in ips:
            info = meta.get(ip)
            if not info:
                continue
            sensors |= info["sensors"]
            countries |= info["countries"]
            asns |= info["asns"]
            events += info["events"]
            first = info["first"] if first is None else min(first, info["first"])
            last = info["last"] if last is None else max(last, info["last"])

        kind = group["kind"]
        sample = group["sample"][:10]
        if kind == "credentials":
            summary = f"{len(ips)} IPs trying the same {len(group['sample'])}-credential list"
        elif kind == "commands":
            summary = f"{len(ips)} IPs running the same {len(group['sample'])}-command sequence"
        else:
            summary = f"{len(ips)} IPs delivering payload {group['sample'][0][:12]}"

        campaigns.append(
            Campaign(
                campaign_id=fp,
                kind=kind,
                summary=summary,
                ip_count=len(ips),
                event_count=events,
                sensors=sorted(sensors),
                countries=sorted(countries)[:10],
                asns=sorted(asns)[:10],
                first_seen=first,
                last_seen=last,
                sample=sample,
                ips=ips[:50],
            )
        )

    # Widest campaigns first; multi-sensor ones outrank single-sensor peers of
    # equal size because breadth is corroboration.
    campaigns.sort(key=lambda c: (len(c.sensors), c.ip_count, c.event_count), reverse=True)
    return campaigns[:limit]
