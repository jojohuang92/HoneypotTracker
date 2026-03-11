import { useState, useRef, useEffect } from "react";
import { useAttempts } from "../../hooks/useAttempts";
import { formatTimestamp, intentLabel, intentColor } from "../../utils/formatters";

export default function AllAttemptsTable() {
  const [page, setPage] = useState(1);
  const { data, loading } = useAttempts(page, 50);
  const scrollRef = useRef<HTMLDivElement>(null);

  // Scroll to top when data refreshes (new attempts arrive at top)
  useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = 0;
  }, [data]);

  return (
    <div className="flex flex-col h-full">
      <div className="flex-1 overflow-auto" ref={scrollRef}>
        <table className="w-full text-xs">
          <thead className="sticky top-0 bg-gray-900 z-10">
            <tr className="border-b border-gray-700">
              <th className="text-left p-2 text-gray-400 font-medium">Time</th>
              <th className="text-left p-2 text-gray-400 font-medium">IP</th>
              <th className="text-left p-2 text-gray-400 font-medium">Location</th>
              <th className="text-left p-2 text-gray-400 font-medium">Event</th>
              <th className="text-left p-2 text-gray-400 font-medium">Details</th>
              <th className="text-left p-2 text-gray-400 font-medium">Intent</th>
            </tr>
          </thead>
          <tbody>
            {data.items.map((a) => (
              <tr
                key={a.id}
                className="border-b border-gray-800/50 hover:bg-gray-700/30 transition-colors"
              >
                <td className="p-2 font-mono text-gray-400 whitespace-nowrap">
                  {formatTimestamp(a.timestamp)}
                </td>
                <td className="p-2 font-mono text-cyan-400 whitespace-nowrap">
                  {a.src_ip}{a.dst_port != null ? <span className="text-gray-500">:{a.dst_port}</span> : ""}
                </td>
                <td className="p-2 max-w-[120px]">
                  <div className="text-gray-300 truncate">
                    {a.city || a.country_name || a.country_code || "?"}
                  </div>
                  {a.city && (
                    <div className="text-[10px] text-gray-500">{a.country_code}</div>
                  )}
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
        {loading && (
          <div className="text-center text-gray-500 py-8">Loading...</div>
        )}
      </div>

      {/* Pagination */}
      <div className="flex items-center justify-between p-2 border-t border-gray-700 bg-gray-900">
        <span className="text-xs text-gray-500">
          {data.total.toLocaleString()} total attempts
        </span>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            disabled={page <= 1}
            className="px-2 py-1 text-xs rounded bg-gray-700 text-gray-300 disabled:opacity-30 hover:bg-gray-600"
          >
            Prev
          </button>
          <span className="text-xs text-gray-400">
            {page} / {data.pages}
          </span>
          <button
            onClick={() => setPage((p) => Math.min(data.pages, p + 1))}
            disabled={page >= data.pages}
            className="px-2 py-1 text-xs rounded bg-gray-700 text-gray-300 disabled:opacity-30 hover:bg-gray-600"
          >
            Next
          </button>
        </div>
      </div>
    </div>
  );
}
