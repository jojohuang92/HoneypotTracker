import { useState } from "react";
import { useUniqueIPs } from "../../hooks/useAttempts";
import { formatTimestamp } from "../../utils/formatters";
import { fetchJSON } from "../../utils/api";
import type { UniqueIP } from "../../types";

function scoreColor(score: number | null): string {
  if (score === null) return "text-gray-500";
  if (score >= 75) return "text-red-400";
  if (score >= 50) return "text-orange-400";
  if (score >= 25) return "text-yellow-400";
  return "text-green-400";
}

function scoreBg(score: number | null): string {
  if (score === null) return "bg-gray-700/30";
  if (score >= 75) return "bg-red-500/10";
  if (score >= 50) return "bg-orange-500/10";
  if (score >= 25) return "bg-yellow-500/10";
  return "bg-green-500/10";
}

export default function IPAddresses() {
  const { data, loading, refresh } = useUniqueIPs();
  const [lookingUp, setLookingUp] = useState<Set<string>>(new Set());

  const lookupScore = async (ip: string) => {
    setLookingUp((prev) => new Set(prev).add(ip));
    try {
      await fetchJSON<UniqueIP>(`/ips/${encodeURIComponent(ip)}/score`, {
        method: "POST",
      });
      refresh();
    } finally {
      setLookingUp((prev) => {
        const next = new Set(prev);
        next.delete(ip);
        return next;
      });
    }
  };

  const lookupAll = async () => {
    const missing = data.filter((d) => d.abuse_score === null);
    for (const ip of missing) {
      await lookupScore(ip.src_ip);
    }
  };

  if (loading) return <div className="text-gray-500 text-center py-8">Loading...</div>;

  const missingCount = data.filter((d) => d.abuse_score === null).length;

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <span className="text-xs text-gray-400">{data.length} unique IPs</span>
        {missingCount > 0 && (
          <button
            onClick={lookupAll}
            disabled={lookingUp.size > 0}
            className="px-2 py-1 text-xs rounded bg-blue-600 text-white hover:bg-blue-500 disabled:opacity-50"
          >
            {lookingUp.size > 0 ? `Looking up...` : `Lookup ${missingCount} scores`}
          </button>
        )}
      </div>

      <div className="bg-gray-800/50 rounded-lg border border-gray-700/50 overflow-x-auto">
        <table className="text-xs min-w-[700px]">
          <thead className="sticky top-0 bg-gray-900 z-10">
            <tr className="border-b border-gray-700">
              <th className="text-left p-2 text-gray-400 font-medium">IP Address</th>
              <th className="text-left p-2 text-gray-400 font-medium">Location</th>
              <th className="text-right p-2 text-gray-400 font-medium">Attacks</th>
              <th className="text-right p-2 text-gray-400 font-medium">Abuse Score</th>
              <th className="text-right p-2 text-gray-400 font-medium">Reports</th>
              <th className="text-left p-2 text-gray-400 font-medium">ISP</th>
              <th className="text-left p-2 text-gray-400 font-medium">Last Seen</th>
            </tr>
          </thead>
          <tbody>
            {data.map((ip) => (
              <tr key={ip.src_ip} className={`border-b border-gray-800/50 hover:bg-gray-700/30 ${scoreBg(ip.abuse_score)}`}>
                <td className="p-2 font-mono text-cyan-400 whitespace-nowrap">
                  {ip.src_ip}
                </td>
                <td className="p-2 text-gray-300 max-w-[120px]">
                  <div className="truncate">
                    {ip.city || ip.country_name || ip.country_code || "?"}
                  </div>
                  {ip.city && (
                    <div className="text-[10px] text-gray-500">{ip.country_code}</div>
                  )}
                </td>
                <td className="p-2 text-right font-mono text-orange-400">
                  {ip.count.toLocaleString()}
                </td>
                <td className="p-2 text-right">
                  {ip.abuse_score !== null ? (
                    <span className={`font-bold ${scoreColor(ip.abuse_score)}`}>
                      {ip.abuse_score}%
                    </span>
                  ) : (
                    <button
                      onClick={() => lookupScore(ip.src_ip)}
                      disabled={lookingUp.has(ip.src_ip)}
                      className="text-blue-400 hover:text-blue-300 disabled:text-gray-600"
                    >
                      {lookingUp.has(ip.src_ip) ? "..." : "lookup"}
                    </button>
                  )}
                </td>
                <td className="p-2 text-right text-gray-400">
                  {ip.total_reports ?? "—"}
                </td>
                <td className="p-2 text-gray-400 whitespace-nowrap">
                  {ip.isp || "—"}
                </td>
                <td className="p-2 text-gray-400 whitespace-nowrap">
                  {ip.latest_timestamp ? formatTimestamp(ip.latest_timestamp) : "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
