"""Composite per-IP threat score.

Ranking is the point: a list of IPs sorted by hit count says little, while one
sorted by risk says where to look first. The score is a weighted sum of six
observable signals, each capped, and every response carries its components and
a plain-language reason list — consistent with the rule-based classifier, an
operator can always see exactly why an IP scored what it did.

Weights sum to 100:
    volume 25 · persistence 20 · intent 25 · reputation 15 · malware 10 · breadth 5
"""

import math
from datetime import datetime

from sqlalchemy import func
from sqlalchemy.orm import Session as DBSession

from app.models import Attempt, CapturedFile, IPScore
from app.schemas import ThreatScore

WEIGHTS = {
    "volume": 25,
    "persistence": 20,
    "intent": 25,
    "reputation": 15,
    "malware": 10,
    "breadth": 5,
}

# How dangerous each observed intent is, 0..1. Reconnaissance is noise;
# sabotage and malware deployment are an attacker acting on access.
INTENT_SEVERITY = {
    "sabotage": 1.0,
    "malware_deployment": 1.0,
    "cryptomining": 0.9,
    "data_exfiltration": 0.9,
    "credential_theft": 0.85,
    "persistence": 0.8,
    "lateral_movement": 0.7,
    "brute_force": 0.4,
    "reconnaissance": 0.3,
    "scanning": 0.25,
}

# Attempt count that saturates the volume component.
VOLUME_SATURATION = 5000
# Distinct active days that saturate the persistence component.
PERSISTENCE_SATURATION = 14


def _level(total: int) -> str:
    if total >= 75:
        return "critical"
    if total >= 50:
        return "high"
    if total >= 25:
        return "medium"
    return "low"


def score_ips(db: DBSession, ips: list[str]) -> dict[str, ThreatScore]:
    """Score a batch of IPs with a fixed number of grouped queries."""
    if not ips:
        return {}

    agg = {
        r.src_ip: r
        for r in db.query(
            Attempt.src_ip,
            func.count(Attempt.id).label("attempts"),
            func.count(func.distinct(func.date(Attempt.timestamp))).label("days"),
            func.count(func.distinct(Attempt.sensor_id)).label("sensors"),
            func.max(Attempt.success).label("any_success"),
        )
        .filter(Attempt.src_ip.in_(ips))
        .group_by(Attempt.src_ip)
        .all()
    }

    intents: dict[str, set[str]] = {}
    for ip, intent in (
        db.query(Attempt.src_ip, Attempt.intent)
        .filter(Attempt.src_ip.in_(ips), Attempt.intent.isnot(None))
        .distinct()
        .all()
    ):
        intents.setdefault(ip, set()).add(intent)

    # Captured files join back to the IP through the attempt that produced them.
    malware: dict[str, dict] = {}
    for ip, positives in (
        db.query(Attempt.src_ip, func.max(CapturedFile.vt_positives))
        .join(CapturedFile, CapturedFile.attempt_id == Attempt.id)
        .filter(Attempt.src_ip.in_(ips))
        .group_by(Attempt.src_ip)
        .all()
    ):
        malware[ip] = {"positives": positives or 0}

    reputation = {
        r.ip: r.abuse_score
        for r in db.query(IPScore).filter(IPScore.ip.in_(ips)).all()
    }

    scored: dict[str, ThreatScore] = {}
    for ip in ips:
        row = agg.get(ip)
        attempts = row.attempts if row else 0
        days = row.days if row else 0
        sensors = row.sensors if row else 0
        seen_intents = intents.get(ip, set())
        reasons: list[str] = []

        # Log scale: the difference between 10 and 100 attempts matters more
        # than between 4000 and 5000.
        volume = 0
        if attempts > 0:
            volume = round(
                WEIGHTS["volume"]
                * min(1.0, math.log10(attempts + 1) / math.log10(VOLUME_SATURATION))
            )

        persistence = round(
            WEIGHTS["persistence"] * min(1.0, days / PERSISTENCE_SATURATION)
        )
        if days >= PERSISTENCE_SATURATION:
            reasons.append(f"persistent: active on {days} separate days")

        severity = max((INTENT_SEVERITY.get(i, 0.3) for i in seen_intents), default=0.0)
        intent_points = round(WEIGHTS["intent"] * severity)
        worst = max(
            seen_intents,
            key=lambda i: INTENT_SEVERITY.get(i, 0.3),
            default=None,
        )
        if worst and INTENT_SEVERITY.get(worst, 0) >= 0.8:
            reasons.append(f"high-severity intent: {worst.replace('_', ' ')}")

        abuse = reputation.get(ip)
        reputation_points = round(WEIGHTS["reputation"] * (abuse / 100)) if abuse else 0
        if abuse and abuse >= 75:
            reasons.append(f"AbuseIPDB confidence {abuse}%")

        mal = malware.get(ip)
        if mal is None:
            malware_points = 0
        elif mal["positives"] > 0:
            malware_points = WEIGHTS["malware"]
            reasons.append(f"dropped a file flagged by {mal['positives']} VT engines")
        else:
            malware_points = WEIGHTS["malware"] // 2
            reasons.append("dropped a captured file")

        # Breadth is small but meaningful: the same IP at several sensors is
        # confirmed indiscriminate scanning rather than a one-host fluke.
        if sensors >= 3:
            breadth = WEIGHTS["breadth"]
        elif sensors == 2:
            breadth = round(WEIGHTS["breadth"] * 0.6)
        else:
            breadth = 0
        if sensors > 1:
            reasons.append(f"seen by {sensors} sensors")

        if row is not None and row.any_success:
            reasons.append("logged in successfully")

        components = {
            "volume": volume,
            "persistence": persistence,
            "intent": intent_points,
            "reputation": reputation_points,
            "malware": malware_points,
            "breadth": breadth,
        }
        total = min(100, sum(components.values()))
        scored[ip] = ThreatScore(
            src_ip=ip,
            total=total,
            level=_level(total),
            components=components,
            reasons=reasons,
        )

    return scored


def score_ip(db: DBSession, ip: str) -> ThreatScore:
    return score_ips(db, [ip]).get(
        ip,
        ThreatScore(src_ip=ip, total=0, level="low", components={}, reasons=[]),
    )


def describe_weights() -> dict:
    """Expose the scoring model so the UI can explain it without duplicating it."""
    return {
        "weights": WEIGHTS,
        "intent_severity": INTENT_SEVERITY,
        "volume_saturation": VOLUME_SATURATION,
        "persistence_saturation": PERSISTENCE_SATURATION,
        "generated_at": datetime.utcnow(),
    }
