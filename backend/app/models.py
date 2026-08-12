from sqlalchemy import (
    Column, Integer, String, Text, Float, Boolean, DateTime, ForeignKey, Index
)
from sqlalchemy.sql import func

from app.database import Base


class Sensor(Base):
    """A honeypot sensor reporting into this hub.

    The hub always has one local sensor (its own Cowrie log); remote sensors
    push events to /api/ingest authenticated by a per-sensor token. Only the
    token's SHA-256 is stored, so the plaintext exists once, at creation.
    """

    __tablename__ = "sensors"

    sensor_id = Column(String, primary_key=True)
    label = Column(String, nullable=False)
    is_local = Column(Boolean, default=False, nullable=False)
    enabled = Column(Boolean, default=True, nullable=False)
    token_hash = Column(String)  # sha256 hex; NULL for the local sensor

    # Published location. Coordinates are rounded on output according to
    # location_precision, so a residential sensor never discloses more than
    # intended (see services/sensor_registry.publish_coords).
    country_code = Column(String)
    country_name = Column(String)
    city = Column(String)
    latitude = Column(Float)
    longitude = Column(Float)
    location_precision = Column(String, default="country", nullable=False)  # country|city|exact
    timezone = Column(String)  # IANA name, for local-hour analysis

    protocols = Column(String)  # comma-separated, e.g. "ssh,telnet"

    # Liveness / agent telemetry, updated by ingest and heartbeat
    last_event_at = Column(DateTime)
    last_heartbeat_at = Column(DateTime)
    agent_version = Column(String)
    disk_free_bytes = Column(Integer)
    disk_total_bytes = Column(Integer)

    # Replay protection for pushed batches: the agent's state generation and
    # the highest sequence number accepted from it.
    last_epoch = Column(String)
    last_seq = Column(Integer, default=0)

    created_at = Column(DateTime, server_default=func.now())


class Attempt(Base):
    __tablename__ = "attempts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    sensor_id = Column(String, index=True)
    session_id = Column(String, nullable=False, index=True)
    event_id = Column(String, nullable=False, index=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    src_ip = Column(String, nullable=False, index=True)
    src_port = Column(Integer)
    dst_port = Column(Integer)
    protocol = Column(String, nullable=False)

    # GeoIP (denormalized for query speed)
    country_code = Column(String, index=True)
    country_name = Column(String)
    city = Column(String)
    latitude = Column(Float)
    longitude = Column(Float)
    asn = Column(Integer)
    as_org = Column(String)

    # Event data
    username = Column(String)
    password = Column(String)
    command = Column(Text)
    input_raw = Column(Text)
    success = Column(Boolean, default=False)

    # Classification
    intent = Column(String, index=True)
    mitre_id = Column(String)

    created_at = Column(DateTime, server_default=func.now())


class CapturedFile(Base):
    __tablename__ = "captured_files"

    id = Column(Integer, primary_key=True, autoincrement=True)
    # Indexed: joined from attempts when scoring an IP's malware activity.
    # Without it SQLite scans every captured file per matching attempt.
    attempt_id = Column(Integer, ForeignKey("attempts.id"), index=True)
    sensor_id = Column(String, index=True)
    session_id = Column(String, nullable=False, index=True)
    timestamp = Column(DateTime, nullable=False)
    filename = Column(String)
    url = Column(String)
    sha256 = Column(String, nullable=False, index=True)
    md5 = Column(String)
    sha1 = Column(String)
    file_size = Column(Integer)
    file_type = Column(String)
    local_path = Column(String)

    # Analysis results
    vt_positives = Column(Integer)
    vt_total = Column(Integer)
    vt_link = Column(String)
    yara_matches = Column(Text)  # JSON array
    malware_family = Column(String)
    analyzed_at = Column(DateTime)

    created_at = Column(DateTime, server_default=func.now())


class Session(Base):
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    sensor_id = Column(String, index=True)
    session_id = Column(String, unique=True, nullable=False)
    src_ip = Column(String, nullable=False, index=True)
    start_time = Column(DateTime, nullable=False, index=True)
    end_time = Column(DateTime)
    protocol = Column(String, nullable=False)

    login_attempts = Column(Integer, default=0)
    commands_run = Column(Integer, default=0)
    files_downloaded = Column(Integer, default=0)
    duration_secs = Column(Float)

    country_code = Column(String)
    country_name = Column(String)
    latitude = Column(Float)
    longitude = Column(Float)

    abuseipdb_score = Column(Integer)
    is_tor = Column(Boolean, default=False)
    is_vpn = Column(Boolean, default=False)
    is_known_attacker = Column(Boolean, default=False)
    threat_tags = Column(Text)  # JSON array

    created_at = Column(DateTime, server_default=func.now())


class IPScore(Base):
    __tablename__ = "ip_scores"

    ip = Column(String, primary_key=True)
    abuse_score = Column(Integer, nullable=False)
    isp = Column(String)
    usage_type = Column(String)
    total_reports = Column(Integer, default=0)
    fetched_at = Column(DateTime, server_default=func.now())


class PageView(Base):
    __tablename__ = "page_views"

    id = Column(Integer, primary_key=True, autoincrement=True)
    visitor_ip = Column(String, nullable=False, index=True)
    user_agent = Column(String)
    visited_at = Column(DateTime, server_default=func.now(), index=True)


class DailyStat(Base):
    __tablename__ = "daily_stats"

    date = Column(String, primary_key=True)
    total_attempts = Column(Integer, default=0)
    unique_ips = Column(Integer, default=0)
    unique_countries = Column(Integer, default=0)
    top_country = Column(String)
    top_username = Column(String)
    top_password = Column(String)
    top_command = Column(String)


class ReportLog(Base):
    __tablename__ = "report_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    report_type = Column(String, nullable=False, index=True)  # "abuseipdb" or "virustotal"
    identifier = Column(String, nullable=False, index=True)   # IP address or SHA256
    reported_at = Column(DateTime, server_default=func.now())
    success = Column(Boolean, default=True)
    detail = Column(Text)  # API response or error message
