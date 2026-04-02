import { useState, useEffect, useRef } from "react";
import { fetchJSON } from "../../utils/api";
import { formatTimestamp, intentColor, intentLabel } from "../../utils/formatters";
import type { SearchResult, Attempt } from "../../types";
import AttemptDetail from "./AttemptDetail";

export default function SearchPanel({
  onNavigateToProfile,
}: {
  onNavigateToProfile?: (ip: string) => void;
}) {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<SearchResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [selected, setSelected] = useState<Attempt | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const debounceRef = useRef<ReturnType<typeof setTimeout>>();

  // Focus input on mount
  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  // Debounced search
  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    if (!query.trim()) {
      setResults(null);
      return;
    }
    debounceRef.current = setTimeout(() => {
      setLoading(true);
      fetchJSON<SearchResult>(`/search?q=${encodeURIComponent(query.trim())}&limit=100`)
        .then(setResults)
        .catch(console.error)
        .finally(() => setLoading(false));
    }, 300);
    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current);
    };
  }, [query]);

  return (
    <div className="flex flex-col h-full">
      {/* Search bar */}
      <div className="p-2 border-b border-gray-700">
        <div className="relative">
          <svg
            className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-500"
            fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2"
          >
            <circle cx="11" cy="11" r="8" />
            <path d="m21 21-4.35-4.35" />
          </svg>
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search IPs, commands, usernames, passwords, countries..."
            className="w-full pl-8 pr-3 py-2 text-xs bg-gray-800 border border-gray-600 rounded-lg text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500"
          />
          {query && (
            <button
              onClick={() => setQuery("")}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300"
            >
              ×
            </button>
          )}
        </div>
      </div>

      {/* Results */}
      <div className="flex-1 overflow-auto">
        {loading && (
          <div className="text-center text-gray-500 py-8 text-xs">Searching...</div>
        )}

        {!loading && !results && (
          <div className="text-center text-gray-600 py-12 text-xs">
            <div className="text-2xl mb-2">🔍</div>
            Type to search across all attack data
          </div>
        )}

        {!loading && results && results.total === 0 && (
          <div className="text-center text-gray-500 py-8 text-xs">
            No results for "{results.query}"
          </div>
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
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onNavigateToProfile?.(a.src_ip);
                        }}
                        className="text-cyan-400 hover:text-cyan-300 hover:underline"
                      >
                        {a.src_ip}
                      </button>
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
