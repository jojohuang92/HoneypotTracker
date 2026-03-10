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
} from "../types";

function useAPI<T>(path: string, defaultValue: T) {
  const [data, setData] = useState<T>(defaultValue);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(() => {
    setLoading(true);
    fetchJSON<T>(path)
      .then(setData)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [path]);

  useEffect(() => {
    refresh();
  }, [refresh]);

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

export function useAttempts(page = 1, limit = 50) {
  return useAPI<PaginatedAttempts>(`/attempts?page=${page}&limit=${limit}`, {
    items: [],
    total: 0,
    page: 1,
    pages: 1,
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
  return useAPI<CapturedFile[]>("/malware/files?limit=50", []);
}

export function useTimeline(granularity = "hour", days = 7) {
  return useAPI<TimelineBucket[]>(
    `/stats/timeline?granularity=${granularity}&days=${days}`,
    []
  );
}
