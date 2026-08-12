from pydantic import BaseModel, ConfigDict
from datetime import datetime


class AttemptOut(BaseModel):
    id: int
    session_id: str
    event_id: str
    timestamp: datetime
    src_ip: str
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str
    country_code: str | None = None
    country_name: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    asn: int | None = None
    as_org: str | None = None
    username: str | None = None
    password: str | None = None
    command: str | None = None
    success: bool = False
    intent: str | None = None
    mitre_id: str | None = None

    model_config = ConfigDict(from_attributes=True)


class GeoPin(BaseModel):
    latitude: float
    longitude: float
    count: int
    country_code: str | None = None
    country_name: str | None = None
    city: str | None = None
    latest_timestamp: datetime | None = None
    latest_event_id: str | None = None
    latest_src_ip: str | None = None


class OverviewStats(BaseModel):
    total_attempts: int
    unique_ips: int
    unique_countries: int
    attacks_today: int
    active_sessions: int
    # Attempts in the window of equal length immediately before the requested
    # window; only set when the request scopes to a window (days > 0).
    prev_attempts: int | None = None


class CountryRank(BaseModel):
    country_code: str
    country_name: str
    count: int
    percentage: float


class IntentBreakdown(BaseModel):
    intent: str
    count: int
    percentage: float
    mitre_id: str | None = None
    description: str | None = None


class CommandRank(BaseModel):
    command: str
    count: int
    intent: str | None = None


class CredentialPair(BaseModel):
    username: str
    password: str
    count: int


class TimelineBucket(BaseModel):
    bucket: str
    count: int


class CapturedFileOut(BaseModel):
    id: int
    session_id: str
    timestamp: datetime
    filename: str | None = None
    url: str | None = None
    sha256: str
    file_size: int | None = None
    file_type: str | None = None
    vt_positives: int | None = None
    vt_total: int | None = None
    vt_link: str | None = None
    yara_matches: str | None = None
    malware_family: str | None = None

    model_config = ConfigDict(from_attributes=True)


class UniqueIP(BaseModel):
    src_ip: str
    count: int
    country_code: str | None = None
    country_name: str | None = None
    city: str | None = None
    latest_timestamp: datetime | None = None
    abuse_score: int | None = None
    isp: str | None = None
    usage_type: str | None = None
    total_reports: int | None = None
    # How many sensors have seen this IP — breadth is corroboration.
    sensor_count: int = 0
    # Only populated when scoring is requested (see /api/ips?scored=true).
    threat_score: int | None = None
    threat_level: str | None = None


class PaginatedAttempts(BaseModel):
    items: list[AttemptOut]
    total: int
    page: int
    pages: int


# -- Attacker Profile --

class SessionSummary(BaseModel):
    session_id: str
    start_time: datetime | None = None
    end_time: datetime | None = None
    duration_secs: float | None = None
    login_attempts: int = 0
    commands_run: int = 0
    files_downloaded: int = 0

    model_config = ConfigDict(from_attributes=True)


class AttackerProfile(BaseModel):
    src_ip: str
    country_code: str | None = None
    country_name: str | None = None
    city: str | None = None
    asn: int | None = None
    as_org: str | None = None
    abuse_score: int | None = None
    isp: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    total_attempts: int = 0
    total_sessions: int = 0
    total_commands: int = 0
    total_files: int = 0
    intents: list[IntentBreakdown] = []
    top_commands: list[CommandRank] = []
    top_credentials: list[CredentialPair] = []
    sessions: list[SessionSummary] = []
    timeline: list[TimelineBucket] = []
    # Composite risk, with the inputs that produced it
    threat_score: int = 0
    threat_level: str = "low"
    threat_components: dict[str, int] = {}
    threat_reasons: list[str] = []
    sensors_seen: list[str] = []


# -- Search --

class SearchResult(BaseModel):
    items: list[AttemptOut]
    total: int
    query: str


# -- MITRE ATT&CK --

class MitreTechnique(BaseModel):
    mitre_id: str
    technique_name: str
    tactic_id: str
    tactic_name: str
    count: int


class MitreTactic(BaseModel):
    tactic_id: str
    tactic_name: str
    total: int
    techniques: list[MitreTechnique]


class MitreMatrix(BaseModel):
    tactics: list[MitreTactic]
    grand_total: int


# -- Meta --

class HoneypotMeta(BaseModel):
    label: str | None = None


# -- Sensors / fleet --

class SensorOut(BaseModel):
    """A sensor as shown in the dashboard. Coordinates are already coarsened
    to the sensor's declared precision — raw positions never leave the DB."""

    sensor_id: str
    label: str
    is_local: bool
    enabled: bool
    country_code: str | None = None
    country_name: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    location_precision: str = "country"
    timezone: str | None = None
    protocols: list[str] = []
    status: str = "unknown"          # online | offline | disabled
    last_event_at: datetime | None = None
    last_heartbeat_at: datetime | None = None
    agent_version: str | None = None
    disk_free_bytes: int | None = None
    disk_total_bytes: int | None = None
    low_disk: bool = False
    total_attempts: int = 0
    attempts_24h: int = 0
    unique_ips_24h: int = 0
    protocol_breakdown: dict[str, int] = {}


class SensorCreate(BaseModel):
    sensor_id: str
    label: str
    country_code: str | None = None
    country_name: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    location_precision: str = "country"
    timezone: str | None = None
    protocols: str = "ssh,telnet"


class SensorCreated(BaseModel):
    """Provisioning response. ``token`` is shown once and never stored."""

    sensor_id: str
    label: str
    token: str


class IngestEvent(BaseModel):
    seq: int
    event: dict


class IngestBatch(BaseModel):
    epoch: str
    events: list[IngestEvent]


class IngestResult(BaseModel):
    accepted: int
    skipped: int
    last_seq: int


class HeartbeatIn(BaseModel):
    epoch: str | None = None
    agent_version: str | None = None
    disk_free_bytes: int | None = None
    disk_total_bytes: int | None = None
    cowrie_log_age_secs: float | None = None


class SensorOverlapPair(BaseModel):
    sensor_a: str
    sensor_b: str
    shared_ips: int


class SensorOverlap(BaseModel):
    """How much attacker traffic is shared between sensors.

    An IP seen by several sensors is indiscriminate scanning; one seen by a
    single sensor is comparatively targeted. Needs two or more reporting
    sensors to mean anything, hence ``sensors_reporting``.
    """

    days: int
    sensors_reporting: int
    total_ips: int
    shared_ips: int
    overlap_rate: float
    exclusive_by_sensor: dict[str, int] = {}
    pairs: list[SensorOverlapPair] = []
    top_shared: list[dict] = []


# -- Threat scoring --

class ThreatScore(BaseModel):
    """Composite 0-100 risk score with its inputs, so a rank is explainable."""

    src_ip: str
    total: int
    level: str  # critical | high | medium | low
    components: dict[str, int]
    reasons: list[str] = []


# -- Campaigns --

class Campaign(BaseModel):
    campaign_id: str
    kind: str  # credentials | payload | commands
    summary: str
    ip_count: int
    event_count: int
    sensors: list[str] = []
    countries: list[str] = []
    asns: list[int] = []
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    sample: list[str] = []
    ips: list[str] = []


# -- Credential analytics --

class CredentialStat(BaseModel):
    value: str
    count: int
    ip_count: int


class HourBucket(BaseModel):
    hour: int
    count: int
