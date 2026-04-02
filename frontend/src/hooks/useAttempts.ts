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

export function useOverview() {
  return useAPI<OverviewStats>("/stats/overview", {
    total_attempts: 0,
    unique_ips: 0,
    unique_countries: 0,
    attacks_today: 0,
    active_sessions: 0,
  });
}

export function useGeoPins() {
  return useAPI<GeoPin[]>("/geo/pins?limit=500", []);
}

export interface AttemptFilters {
  countries?: string[];
  events?: string[];
  intents?: string[];
}

export function useAttempts(page = 1, limit = 50, filters?: AttemptFilters) {
  let params = `page=${page}&limit=${limit}`;
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

export function useCountryRanks() {
  return useAPI<CountryRank[]>("/stats/countries?limit=20", []);
}

export function useIntentBreakdown() {
  return useAPI<IntentBreakdown[]>("/stats/intents", []);
}

export function useCommandRanks() {
  return useAPI<CommandRank[]>("/stats/commands?limit=20", []);
}

export function useCredentials() {
  return useAPI<CredentialPair[]>("/stats/credentials?limit=20", []);
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

export function useTimeline(granularity = "hour", days = 7) {
  const tzOffset = -new Date().getTimezoneOffset(); // minutes ahead of UTC
  return useAPI<TimelineBucket[]>(
    `/stats/timeline?granularity=${granularity}&days=${days}&tz_offset=${tzOffset}`,
    []
  );
}

export function useUniqueIPs() {
  return useAPI<UniqueIP[]>("/ips?limit=100", []);
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
