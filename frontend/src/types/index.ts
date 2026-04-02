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

export interface OverviewStats {
  total_attempts: number;
  unique_ips: number;
  unique_countries: number;
  attacks_today: number;
  active_sessions: number;
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
}

export interface SearchResult {
  items: Attempt[];
  total: number;
  query: string;
}

export type DashboardTab =
  | "overview"
  | "attempts"
  | "search"
  | "profile"
  | "ips"
  | "countries"
  | "intents"
  | "commands"
  | "files"
  | "malware";
