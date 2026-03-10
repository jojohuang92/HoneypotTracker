import StatCard from "../common/StatCard";
import TimelineChart from "../Charts/TimelineChart";
import type { OverviewStats } from "../../types";
import { useTimeline, useCredentials } from "../../hooks/useAttempts";

interface OverviewPanelProps {
  stats: OverviewStats;
}

export default function OverviewPanel({ stats }: OverviewPanelProps) {
  const { data: timeline } = useTimeline("hour", 7);
  const { data: creds } = useCredentials();

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-2">
        <StatCard label="Total Attacks" value={stats.total_attempts} icon="⚡" color="text-red-400" />
        <StatCard label="Unique IPs" value={stats.unique_ips} icon="🌐" color="text-blue-400" />
        <StatCard label="Countries" value={stats.unique_countries} icon="🗺️" color="text-green-400" />
        <StatCard label="Today" value={stats.attacks_today} icon="📅" color="text-yellow-400" />
      </div>

      <div>
        <h3 className="text-sm font-semibold text-gray-300 mb-2">Attack Timeline (7 days)</h3>
        <div className="h-48 bg-gray-800/50 rounded-lg p-2 border border-gray-700/50">
          <TimelineChart data={timeline} />
        </div>
      </div>

      <div>
        <h3 className="text-sm font-semibold text-gray-300 mb-2">Top Credentials Tried</h3>
        <div className="bg-gray-800/50 rounded-lg border border-gray-700/50 overflow-hidden">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-gray-700">
                <th className="text-left p-2 text-gray-400 font-medium">Username</th>
                <th className="text-left p-2 text-gray-400 font-medium">Password</th>
                <th className="text-right p-2 text-gray-400 font-medium">Count</th>
              </tr>
            </thead>
            <tbody>
              {creds.slice(0, 10).map((c, i) => (
                <tr key={i} className="border-b border-gray-800 hover:bg-gray-700/30">
                  <td className="p-2 font-mono text-cyan-400">{c.username}</td>
                  <td className="p-2 font-mono text-orange-400">{c.password}</td>
                  <td className="p-2 text-right text-gray-300">{c.count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
