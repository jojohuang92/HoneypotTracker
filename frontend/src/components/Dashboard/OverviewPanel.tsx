import { useState, useEffect, useRef } from "react";
import StatCard from "../common/StatCard";
import TimelineChart from "../Charts/TimelineChart";
import type { Attempt, OverviewStats, TimelineBucket } from "../../types";
import { useTimeline, useCredentials } from "../../hooks/useAttempts";

const TIMEFRAMES = [
  { label: "6h", days: 0.25, granularity: "hour" },
  { label: "24h", days: 1, granularity: "hour" },
  { label: "7d", days: 7, granularity: "day" },
  { label: "30d", days: 30, granularity: "day" },
] as const;

function getCurrentBucketKey(granularity: string): string {
  const now = new Date();
  const y = now.getFullYear();
  const m = String(now.getMonth() + 1).padStart(2, "0");
  const d = String(now.getDate()).padStart(2, "0");
  if (granularity === "hour") {
    const h = String(now.getHours()).padStart(2, "0");
    return `${y}-${m}-${d} ${h}:00`;
  }
  return `${y}-${m}-${d}`;
}

interface OverviewPanelProps {
  stats: OverviewStats;
  lastEvent: Attempt | null;
}

export default function OverviewPanel({ stats, lastEvent }: OverviewPanelProps) {
  const [tfIndex, setTfIndex] = useState(0);
  const tf = TIMEFRAMES[tfIndex];
  const { data: timeline } = useTimeline(tf.granularity, tf.days);

  // Live timeline: server data + SSE bumps applied to current bucket
  const [liveTimeline, setLiveTimeline] = useState<TimelineBucket[]>([]);
  const prevEventRef = useRef<Attempt | null>(null);
  const bumpRef = useRef(0);

  // When server data arrives, reset bumps and sync
  useEffect(() => {
    bumpRef.current = 0;
    setLiveTimeline(timeline);
  }, [timeline]);

  // On each new SSE event, bump the current bucket
  useEffect(() => {
    if (lastEvent && lastEvent !== prevEventRef.current) {
      prevEventRef.current = lastEvent;
      bumpRef.current += 1;
      const key = getCurrentBucketKey(tf.granularity);
      setLiveTimeline((prev) =>
        prev.map((b) =>
          b.bucket === key ? { ...b, count: b.count + 1 } : b
        )
      );
    }
  }, [lastEvent, tf.granularity]);

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
        <div className="flex items-center justify-between mb-2">
          <h3 className="text-sm font-semibold text-gray-300">Attack Timeline</h3>
          <div className="flex gap-1">
            {TIMEFRAMES.map((t, i) => (
              <button
                key={t.label}
                onClick={() => setTfIndex(i)}
                className={`px-2 py-0.5 rounded text-xs font-medium transition-colors ${
                  i === tfIndex
                    ? "bg-blue-600 text-white"
                    : "bg-gray-700/50 text-gray-400 hover:text-white hover:bg-gray-700"
                }`}
              >
                {t.label}
              </button>
            ))}
          </div>
        </div>
        <div className="bg-gray-800/50 rounded-lg border border-gray-700/50 p-2">
          <div className="h-44">
            <TimelineChart data={liveTimeline} />
          </div>
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
