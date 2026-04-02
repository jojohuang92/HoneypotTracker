from pydantic import BaseModel
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

    class Config:
        from_attributes = True


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

    class Config:
        from_attributes = True


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

    class Config:
        from_attributes = True


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


# -- Search --

class SearchResult(BaseModel):
    items: list[AttemptOut]
    total: int
    query: str
