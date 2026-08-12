import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Zap, Network, Globe, CalendarDays } from "lucide-react";
import StatCard from "../common/StatCard";
import TimelineChart from "../Charts/TimelineChart";
import ExportPanel from "./ExportPanel";
import Skeleton from "../common/Skeleton";
import type { LiveAttackEvent, TimelineBucket } from "../../types";
import { useOverview, useTimeline, useCredentials } from "../../hooks/useAttempts";
import { useTimeRange } from "../../context/TimeRangeContext";
import { useSensorScope } from "../../context/SensorContext";

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
  lastEvent: LiveAttackEvent | null;
}

export default function OverviewPanel({ lastEvent }: OverviewPanelProps) {
  const { range } = useTimeRange();
  const { sensorId } = useSensorScope();
  const { data: stats } = useOverview(range.days, sensorId);

  // The timeline endpoint always needs a window; "All" shows the last 30 days.
  const timelineDays = range.days || 30;
  const granularity = timelineDays <= 1 ? "hour" : "day";
  const { data: timeline } = useTimeline(granularity, timelineDays, sensorId);

  const [liveTimeline, setLiveTimeline] = useState<TimelineBucket[]>([]);

  useEffect(() => {
    setLiveTimeline(timeline);
  }, [timeline]);

  useEffect(() => {
    if (!lastEvent) return;
    const key = getCurrentBucketKey(granularity);
    setLiveTimeline((prev) => {
      let found = false;
      const next = prev.map((b) => {
        if (b.bucket !== key) return b;
        found = true;
        return { ...b, count: b.count + 1 };
      });
      return found ? next : [...next, { bucket: key, count: 1 }];
    });
  }, [lastEvent, granularity]);

  const { data: creds, loading: credsLoading } = useCredentials(range.days, sensorId);

  const delta =
    stats.prev_attempts != null
      ? { value: stats.total_attempts - stats.prev_attempts, label: `vs prev ${range.label}` }
      : null;

  const scopeHint = range.days > 0 ? range.label : undefined;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-2">
        <StatCard
          label="Attacks"
          value={stats.total_attempts}
          icon={Zap}
          color="text-red-400"
          hint={scopeHint}
          delta={delta}
        />
        <StatCard
          label="Unique IPs"
          value={stats.unique_ips}
          icon={Network}
          color="text-blue-400"
          hint={scopeHint}
        />
        <StatCard
          label="Countries"
          value={stats.unique_countries}
          icon={Globe}
          color="text-green-400"
          hint={scopeHint}
        />
        <StatCard
          label="Today"
          value={stats.attacks_today}
          icon={CalendarDays}
          color="text-yellow-400"
          hint="PT"
          title="Counts attacks since midnight Pacific Time (America/Los_Angeles)"
        />
      </div>

      <div>
        <div className="flex items-center justify-between mb-2">
          <h3 className="text-sm font-semibold text-gray-300">Attack Timeline</h3>
          <span className="text-[10px] text-gray-500">
            {range.days === 0 ? "last 30d" : `last ${range.label}`} · live
          </span>
        </div>
        <div className="bg-gray-800/50 rounded-lg border border-gray-700/50 p-2">
          <div className="h-44">
            <TimelineChart data={liveTimeline} />
          </div>
        </div>
      </div>

      <div>
        <h3 className="text-sm font-semibold text-gray-300 mb-2">Top Credentials Tried</h3>
        {credsLoading && creds.length === 0 ? (
          <Skeleton rows={6} />
        ) : (
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
                    <td className="p-2 font-mono">
                      <Link
                        to={`/search?q=${encodeURIComponent(c.username)}`}
                        className="text-cyan-400 hover:text-cyan-300 hover:underline"
                        title="Search attempts using this username"
                      >
                        {c.username}
                      </Link>
                    </td>
                    <td className="p-2 font-mono text-orange-400">{c.password}</td>
                    <td className="p-2 text-right text-gray-300">{c.count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <ExportPanel />
    </div>
  );
}
