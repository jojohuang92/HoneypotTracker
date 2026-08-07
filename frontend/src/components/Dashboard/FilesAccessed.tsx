import { Link } from "react-router-dom";
import { FolderOpen } from "lucide-react";
import { useAttempts } from "../../hooks/useAttempts";
import { useTimeRange } from "../../context/TimeRangeContext";
import { formatTimestamp, formatNumber } from "../../utils/formatters";
import Skeleton from "../common/Skeleton";
import EmptyState from "../common/EmptyState";

export default function FilesAccessed() {
  const { range } = useTimeRange();
  const { data, loading } = useAttempts(1, 100, { intents: ["malware_deployment"] }, range.days);

  if (loading && data.items.length === 0) return <Skeleton rows={10} />;

  return (
    <div className="space-y-3">
      <h3 className="text-sm font-semibold text-gray-300">
        Files Accessed / Downloaded
        <span className="ml-2 text-gray-500 font-normal">({formatNumber(data.total)})</span>
      </h3>

      {data.items.length === 0 ? (
        <EmptyState
          icon={FolderOpen}
          title="No file activity in this range"
          hint="File events appear when attackers fetch or touch payloads. Widen the time range to see older activity."
        />
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
                <Link
                  to={`/profile/${encodeURIComponent(f.src_ip)}`}
                  className="font-mono text-cyan-500 hover:text-cyan-300 hover:underline"
                >
                  {f.src_ip}
                </Link>
                <span>{f.country_code}</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
