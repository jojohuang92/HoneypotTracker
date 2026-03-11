
import { useAttempts } from "../../hooks/useAttempts";
import { formatTimestamp } from "../../utils/formatters";

export default function FilesAccessed() {
  const { data, loading } = useAttempts(1, 100, "malware_deployment");

  if (loading) return <div className="text-gray-500 text-center py-8">Loading...</div>;

  return (
    <div className="space-y-3">
      <h3 className="text-sm font-semibold text-gray-300">
        Files Accessed / Downloaded
        <span className="ml-2 text-gray-500 font-normal">({data.total})</span>
      </h3>

      {data.items.length === 0 ? (
        <div className="text-center text-gray-500 py-8 text-sm">
          No file access events found
        </div>
      ) : (
        <div className="space-y-1.5">
          {data.items.map((f) => (
            <div
              key={f.id}
              className="bg-gray-800/50 rounded-lg p-2.5 border border-gray-700/50"
            >
              <div className="flex items-center justify-between">
                <code className="text-xs text-red-400 font-mono break-all">
                  {f.command || f.event_id}
                </code>
              </div>
              <div className="flex items-center gap-3 mt-1 text-[10px] text-gray-500">
                <span>{formatTimestamp(f.timestamp)}</span>
                <span className="font-mono">{f.src_ip}</span>
                <span>{f.country_code}</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
