export interface Attempt {
  id: number;
  session_id: string;
  event_id: string;
  timestamp: string;
  src_ip: string;
  src_port: number | null;
  dst_port: number | null;
  protocol: string;
  country_code: string | null;
  country_name: string | null;
  city: string | null;
  latitude: number | null;
  longitude: number | null;
  asn: number | null;
  as_org: string | null;
  username: string | null;
  password: string | null;
  command: string | null;
  success: boolean;
  intent: string | null;
  mitre_id: string | null;
}

export interface GeoPin {
  latitude: number;
  longitude: number;
  count: number;
  country_code: string | null;
  country_name: string | null;
  city: string | null;
  latest_timestamp: string | null;
  latest_event_id: string | null;
  latest_src_ip: string | null;
}

export interface LiveAttackEvent {
  type: "session_start" | "login_attempt" | "command" | "file_download" | string;
  event_id?: string;
  session_id?: string;
  src_ip?: string;
  username?: string;
  password?: string;
  success?: boolean;
  command?: string;
  intent?: string | null;
  mitre_id?: string | null;
  country?: string | null;
  latitude?: number | null;
  longitude?: number | null;
  url?: string;
  sha256?: string;
  protocol?: string;
  sensor_id?: string;
}

export interface OverviewStats {
  total_attempts: number;
  unique_ips: number;
  unique_countries: number;
  attacks_today: number;
  active_sessions: number;
  /** Attempts in the equal-length window before the requested one (null when all-time). */
  prev_attempts?: number | null;
}

export interface CountryRank {
  country_code: string;
  country_name: string;
  count: number;
  percentage: number;
}

export interface IntentBreakdown {
  intent: string;
  count: number;
  percentage: number;
  mitre_id: string | null;
  description: string | null;
}

export interface CommandRank {
  command: string;
  count: number;
  intent: string | null;
}

export interface CredentialPair {
  username: string;
  password: string;
  count: number;
}

export interface TimelineBucket {
  bucket: string;
  count: number;
}

export interface CapturedFile {
  id: number;
  session_id: string;
  timestamp: string;
  filename: string | null;
  url: string | null;
  sha256: string;
  file_size: number | null;
  file_type: string | null;
  vt_positives: number | null;
  vt_total: number | null;
  vt_link: string | null;
  yara_matches: string | null;
  malware_family: string | null;
}

export interface PaginatedAttempts {
  items: Attempt[];
  total: number;
  page: number;
  pages: number;
}

export interface UniqueIP {
  src_ip: string;
  count: number;
  country_code: string | null;
  country_name: string | null;
  city: string | null;
  latest_timestamp: string | null;
  abuse_score: number | null;
  isp: string | null;
  usage_type: string | null;
  total_reports: number | null;
  sensor_count: number;
  threat_score: number | null;
  threat_level: string | null;
}

export interface SessionSummary {
  session_id: string;
  start_time: string | null;
  end_time: string | null;
  duration_secs: number | null;
  login_attempts: number;
  commands_run: number;
  files_downloaded: number;
}

export interface AttackerProfile {
  src_ip: string;
  country_code: string | null;
  country_name: string | null;
  city: string | null;
  asn: number | null;
  as_org: string | null;
  abuse_score: number | null;
  isp: string | null;
  first_seen: string | null;
  last_seen: string | null;
  total_attempts: number;
  total_sessions: number;
  total_commands: number;
  total_files: number;
  intents: IntentBreakdown[];
  top_commands: CommandRank[];
  top_credentials: CredentialPair[];
  sessions: SessionSummary[];
  timeline: TimelineBucket[];
  threat_score: number;
  threat_level: string;
  threat_components: Record<string, number>;
  threat_reasons: string[];
  sensors_seen: string[];
}

export interface SearchResult {
  items: Attempt[];
  total: number;
  query: string;
}

export interface MitreTechnique {
  mitre_id: string;
  technique_name: string;
  tactic_id: string;
  tactic_name: string;
  count: number;
}

export interface MitreTactic {
  tactic_id: string;
  tactic_name: string;
  total: number;
  techniques: MitreTechnique[];
}

export interface MitreMatrix {
  tactics: MitreTactic[];
  grand_total: number;
}


export interface Sensor {
  sensor_id: string;
  label: string;
  is_local: boolean;
  enabled: boolean;
  country_code: string | null;
  country_name: string | null;
  city: string | null;
  latitude: number | null;
  longitude: number | null;
  location_precision: string;
  timezone: string | null;
  protocols: string[];
  status: "online" | "offline" | "disabled" | "unknown";
  last_event_at: string | null;
  last_heartbeat_at: string | null;
  agent_version: string | null;
  disk_free_bytes: number | null;
  disk_total_bytes: number | null;
  low_disk: boolean;
  total_attempts: number;
  attempts_24h: number;
  unique_ips_24h: number;
  protocol_breakdown: Record<string, number>;
}

export interface SensorOverlapPair {
  sensor_a: string;
  sensor_b: string;
  shared_ips: number;
}

export interface SensorOverlap {
  days: number;
  sensors_reporting: number;
  total_ips: number;
  shared_ips: number;
  overlap_rate: number;
  exclusive_by_sensor: Record<string, number>;
  pairs: SensorOverlapPair[];
  top_shared: {
    src_ip: string;
    sensors: string[];
    total: number;
    per_sensor: Record<string, number>;
  }[];
}

export interface ThreatScoreDetail {
  src_ip: string;
  total: number;
  level: "critical" | "high" | "medium" | "low";
  components: Record<string, number>;
  reasons: string[];
}

export interface CampaignGroup {
  campaign_id: string;
  kind: "credentials" | "payload" | "commands";
  summary: string;
  ip_count: number;
  event_count: number;
  sensors: string[];
  countries: string[];
  asns: number[];
  first_seen: string | null;
  last_seen: string | null;
  sample: string[];
  ips: string[];
}

export interface CredentialStat {
  value: string;
  count: number;
  ip_count: number;
}

export interface HourBucket {
  hour: number;
  count: number;
}
