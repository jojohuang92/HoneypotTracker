import { useState, useEffect, useRef } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Search, X } from "lucide-react";
import { fetchJSON } from "../../utils/api";
import { formatTimestamp, intentColor, intentLabel } from "../../utils/formatters";
import type { SearchResult, Attempt } from "../../types";
import AttemptDetail from "./AttemptDetail";
import Skeleton from "../common/Skeleton";
import EmptyState from "../common/EmptyState";

export default function SearchPanel() {
  const [searchParams, setSearchParams] = useSearchParams();
  const urlQuery = searchParams.get("q") ?? "";
  const [query, setQuery] = useState(urlQuery);
  const [results, setResults] = useState<SearchResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [selected, setSelected] = useState<Attempt | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  // Focus input on mount
  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  // Follow external URL changes (e.g. a pivot from another panel)
  useEffect(() => {
    setQuery(urlQuery);
  }, [urlQuery]);

  // Debounced search, synced to the URL so results are shareable
  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    const trimmed = query.trim();
    if (!trimmed) {
      setResults(null);
      return;
    }
    debounceRef.current = setTimeout(() => {
      setSearchParams({ q: trimmed }, { replace: true });
      setLoading(true);
      fetchJSON<SearchResult>(`/search?q=${encodeURIComponent(trimmed)}&limit=100`)
        .then(setResults)
        .catch(console.error)
        .finally(() => setLoading(false));
    }, 300);
    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current);
    };
  }, [query, setSearchParams]);

  const updateQuery = (value: string) => {
    setQuery(value);
    if (!value.trim()) {
      setResults(null);
      setSearchParams({}, { replace: true });
    }
  };

  return (
    <div className="flex flex-col h-full">
      {/* Search bar */}
      <div className="pb-2 border-b border-gray-700">
        <div className="relative">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-500" aria-hidden />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => updateQuery(e.target.value)}
            placeholder="Search IPs, commands, usernames, passwords, countries..."
            className="w-full pl-8 pr-8 py-2 text-xs bg-gray-800 border border-gray-600 rounded-lg text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500"
          />
          {query && (
            <button
              onClick={() => updateQuery("")}
              aria-label="Clear search"
              className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>

      {/* Results */}
      <div className="flex-1 overflow-auto">
        {loading && <Skeleton rows={10} className="pt-3" />}

        {!loading && !results && (
          <EmptyState
            icon={Search}
            title="Search across all attack data"
            hint="IPs, commands, usernames, passwords, and countries are all matched."
          />
        )}

        {!loading && results && results.total === 0 && (
          <EmptyState
            icon={Search}
            title={`No results for "${results.query}"`}
            hint="Try a shorter fragment — matches are substring-based."
          />
        )}

        {!loading && results && results.total > 0 && (
          <>
            <div className="px-3 py-2 text-xs text-gray-400 border-b border-gray-800">
              {results.total.toLocaleString()} results for "{results.query}"
            </div>
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-gray-900 z-10">
                <tr className="border-b border-gray-700">
                  <th className="text-left p-2 text-gray-400 font-medium">Time</th>
                  <th className="text-left p-2 text-gray-400 font-medium">IP</th>
                  <th className="text-left p-2 text-gray-400 font-medium">Event</th>
                  <th className="text-left p-2 text-gray-400 font-medium">Details</th>
                  <th className="text-left p-2 text-gray-400 font-medium">Intent</th>
                </tr>
              </thead>
              <tbody>
                {results.items.map((a) => (
                  <tr
                    key={a.id}
                    onClick={() => setSelected(a)}
                    className="border-b border-gray-800/50 hover:bg-gray-700/30 cursor-pointer"
                  >
                    <td className="p-2 font-mono text-gray-400 whitespace-nowrap">
                      {formatTimestamp(a.timestamp)}
                    </td>
                    <td className="p-2 font-mono whitespace-nowrap">
                      <Link
                        to={`/profile/${encodeURIComponent(a.src_ip)}`}
                        onClick={(e) => e.stopPropagation()}
                        className="text-cyan-400 hover:text-cyan-300 hover:underline"
                      >
                        {a.src_ip}
                      </Link>
                    </td>
                    <td className="p-2 text-gray-300">
                      {a.event_id.replace("cowrie.", "")}
                    </td>
                    <td className="p-2 text-gray-300 max-w-[180px] truncate">
                      {a.command || (a.username ? `${a.username}:${a.password}` : "—")}
                    </td>
                    <td className="p-2">
                      {a.intent && (
                        <span
                          className="inline-block px-1.5 py-0.5 rounded text-[10px] font-medium"
                          style={{
                            backgroundColor: intentColor(a.intent) + "20",
                            color: intentColor(a.intent),
                          }}
                        >
                          {intentLabel(a.intent)}
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
      </div>

      {selected && <AttemptDetail attempt={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}
