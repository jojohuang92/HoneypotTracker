import { useState, useEffect, useCallback } from "react";
import { fetchJSON } from "../utils/api";
import type {
  OverviewStats,
  GeoPin,
  PaginatedAttempts,
  CountryRank,
  IntentBreakdown,
  CommandRank,
  CapturedFile,
  TimelineBucket,
  CredentialPair,
  UniqueIP,
  AttackerProfile,
  SearchResult,
  Attempt,
  MitreMatrix,
  Sensor,
  SensorOverlap,
  CampaignGroup,
  CredentialStat,
  HourBucket,
  ThreatScoreDetail,
} from "../types";

const POLL_INTERVAL_MS = 3 * 60 * 1000; // 3 minutes

function useAPI<T>(path: string, defaultValue: T) {
  const [data, setData] = useState<T>(defaultValue);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(() => {
    if (!path) {
      setData(defaultValue);
      setLoading(false);
      return;
    }
    setLoading(true);
    fetchJSON<T>(path)
      .then(setData)
      .catch(console.error)
      .finally(() => setLoading(false));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [path]);

  useEffect(() => {
    refresh();
    if (!path) return;
    const id = setInterval(refresh, POLL_INTERVAL_MS);
    return () => clearInterval(id);
  }, [refresh, path]);

  return { data, loading, refresh };
}

/** Append query params, skipping empty ones, regardless of existing "?". */
function withParams(path: string, params: Record<string, string | number | undefined | null>): string {
  const parts = Object.entries(params)
    .filter(([, v]) => v !== undefined && v !== null && v !== "" && v !== 0)
    .map(([k, v]) => `${k}=${encodeURIComponent(String(v))}`);
  if (parts.length === 0) return path;
  return `${path}${path.includes("?") ? "&" : "?"}${parts.join("&")}`;
}

/** Shared scope for every aggregate view: time window plus sensor. */
function withScope(path: string, days: number, sensor?: string | null): string {
  return withParams(path, { days, sensor });
}

export function useOverview(days = 0, sensor?: string | null) {
  return useAPI<OverviewStats>(withScope("/stats/overview", days, sensor), {
    total_attempts: 0,
    unique_ips: 0,
    unique_countries: 0,
    attacks_today: 0,
    active_sessions: 0,
    prev_attempts: null,
  });
}

export function useGeoPins(sensor?: string | null) {
  return useAPI<GeoPin[]>(withScope("/geo/pins?limit=500", 0, sensor), []);
}

export function useSensors() {
  return useAPI<Sensor[]>("/sensors", []);
}

export function useSensorOverlap(days = 7) {
  return useAPI<SensorOverlap>(withParams("/sensors/overlap", { days }), {
    days,
    sensors_reporting: 0,
    total_ips: 0,
    shared_ips: 0,
    overlap_rate: 0,
    exclusive_by_sensor: {},
    pairs: [],
    top_shared: [],
  });
}

export function useCampaigns(days = 7, sensor?: string | null) {
  return useAPI<CampaignGroup[]>(withParams("/campaigns", { days, sensor }), []);
}

export function useTopUsernames(days = 0, sensor?: string | null) {
  return useAPI<CredentialStat[]>(withScope("/stats/usernames?limit=20", days, sensor), []);
}

export function useTopPasswords(days = 0, sensor?: string | null) {
  return useAPI<CredentialStat[]>(withScope("/stats/passwords?limit=20", days, sensor), []);
}

export function useHourly(days = 30, sensor?: string | null) {
  return useAPI<HourBucket[]>(withParams("/stats/hourly", { days, sensor }), []);
}

export function useThreatScore(ip: string) {
  return useAPI<ThreatScoreDetail | null>(
    ip ? `/ips/${encodeURIComponent(ip)}/threat` : "",
    null
  );
}

export interface AttemptFilters {
  countries?: string[];
  events?: string[];
  intents?: string[];
}

export function useAttempts(
  page = 1,
  limit = 50,
  filters?: AttemptFilters,
  days = 0,
  sensor?: string | null,
) {
  let params = `page=${page}&limit=${limit}`;
  if (days) params += `&days=${days}`;
  if (sensor) params += `&sensor=${encodeURIComponent(sensor)}`;
  if (filters?.countries?.length) {
    params += filters.countries.map((c) => `&country=${encodeURIComponent(c)}`).join("");
  }
  if (filters?.events?.length) {
    params += filters.events.map((e) => `&event_id=${encodeURIComponent(e)}`).join("");
  }
  if (filters?.intents?.length) {
    params += filters.intents.map((i) => `&intent=${encodeURIComponent(i)}`).join("");
  }
  return useAPI<PaginatedAttempts>(`/attempts?${params}`, {
    items: [],
    total: 0,
    page: 1,
    pages: 1,
  });
}

export interface FilterOptions {
  countries: { code: string; name: string }[];
  events: string[];
  intents: string[];
}

export function useFilterOptions() {
  return useAPI<FilterOptions>("/attempts/filter-options", {
    countries: [],
    events: [],
    intents: [],
  });
}

export function useCountryRanks(days = 0, sensor?: string | null) {
  return useAPI<CountryRank[]>(withScope("/stats/countries?limit=20", days, sensor), []);
}

export function useIntentBreakdown(days = 0, sensor?: string | null) {
  return useAPI<IntentBreakdown[]>(withScope("/stats/intents", days, sensor), []);
}

export function useCommandRanks(days = 0, sensor?: string | null) {
  return useAPI<CommandRank[]>(withScope("/stats/commands?limit=20", days, sensor), []);
}

export function useCredentials(days = 0, sensor?: string | null) {
  return useAPI<CredentialPair[]>(withScope("/stats/credentials?limit=20", days, sensor), []);
}

export function useCapturedFiles() {
  return useAPI<CapturedFile[]>("/malware/files", []);
}

export interface ViewerStats {
  total_views: number;
  unique_visitors: number;
  views_today: number;
  unique_last_24h: number;
}

export function useViewers() {
  return useAPI<ViewerStats>("/stats/viewers", {
    total_views: 0,
    unique_visitors: 0,
    views_today: 0,
    unique_last_24h: 0,
  });
}

export interface PortStat {
  port: number;
  count: number;
  percentage: number;
}

export function useTopPorts() {
  return useAPI<PortStat[]>("/stats/ports?limit=10", []);
}

export function useTimeline(granularity = "hour", days = 7, sensor?: string | null) {
  const tzOffset = -new Date().getTimezoneOffset(); // minutes ahead of UTC
  return useAPI<TimelineBucket[]>(
    withParams(
      `/stats/timeline?granularity=${granularity}&days=${days}&tz_offset=${tzOffset}`,
      { sensor }
    ),
    []
  );
}

export function useUniqueIPs(sensor?: string | null, scored = false) {
  return useAPI<UniqueIP[]>(
    withParams("/ips", { sensor, scored: scored ? "true" : undefined }),
    []
  );
}

export function useMitreMatrix(days = 0, sensor?: string | null) {
  return useAPI<MitreMatrix>(withScope("/stats/mitre", days, sensor), {
    tactics: [],
    grand_total: 0,
  });
}

export function useAttackerProfile(ip: string) {
  return useAPI<AttackerProfile | null>(
    ip ? `/profile/${encodeURIComponent(ip)}` : "",
    null
  );
}

export function useSearch(query: string) {
  return useAPI<SearchResult>(
    query ? `/search?q=${encodeURIComponent(query)}&limit=100` : "",
    { items: [], total: 0, query: "" }
  );
}

export function useSessionReplay(sessionId: string) {
  return useAPI<Attempt[]>(
    sessionId ? `/replay/${encodeURIComponent(sessionId)}` : "",
    []
  );
}
