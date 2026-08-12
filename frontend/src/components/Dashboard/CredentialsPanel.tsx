import { Link } from "react-router-dom";
import { KeyRound, Clock } from "lucide-react";
import {
  useTopUsernames,
  useTopPasswords,
  useCredentials,
  useHourly,
} from "../../hooks/useAttempts";
import { useTimeRange } from "../../context/TimeRangeContext";
import { useSensorScope } from "../../context/SensorContext";
import { formatNumber } from "../../utils/formatters";
import Skeleton from "../common/Skeleton";
import EmptyState from "../common/EmptyState";
import type { CredentialStat } from "../../types";

/** Top values of one credential field, with how widely each is shared.
 *  Breadth is the interesting column: a password tried by many IPs comes from
 *  a circulating wordlist, one tried by a single IP is that operator's guess. */
function FieldTable({
  title,
  rows,
  color,
}: {
  title: string;
  rows: CredentialStat[];
  color: string;
}) {
  const max = rows.length > 0 ? rows[0].count : 1;
  return (
    <div>
      <h3 className="text-xs font-medium text-gray-400 mb-1.5">{title}</h3>
      <div className="bg-gray-800/50 rounded-lg border border-gray-700/50 overflow-hidden">
        {rows.slice(0, 12).map((row) => (
          <div
            key={row.value}
            className="flex items-center gap-2 px-2 py-1.5 border-b border-gray-800/50 last:border-0"
          >
            <Link
              to={`/search?q=${encodeURIComponent(row.value)}`}
              className={`text-[11px] font-mono truncate w-28 shrink-0 hover:underline ${color}`}
              title={`Search attempts using "${row.value}"`}
            >
              {row.value}
            </Link>
            <div className="flex-1 h-1 bg-gray-700 rounded-full overflow-hidden">
              <div
                className="h-full rounded-full bg-gray-500"
                style={{ width: `${(row.count / max) * 100}%` }}
              />
            </div>
            <span className="text-[10px] font-mono text-gray-400 w-12 text-right shrink-0">
              {formatNumber(row.count)}
            </span>
            <span
              className="text-[10px] text-gray-600 w-14 text-right shrink-0"
              title={`${row.ip_count} distinct source IPs tried this`}
            >
              {formatNumber(row.ip_count)} IPs
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function CredentialsPanel() {
  const { range } = useTimeRange();
  const { sensorId, sensors } = useSensorScope();
  const { data: usernames, loading: uLoading } = useTopUsernames(range.days, sensorId);
  const { data: passwords } = useTopPasswords(range.days, sensorId);
  const { data: pairs } = useCredentials(range.days, sensorId);
  const { data: hourly } = useHourly(range.days || 30, sensorId);

  const scopeLabel =
    sensors.find((s) => s.sensor_id === sensorId)?.label ?? "the whole fleet";
  const hourlyMax = hourly.reduce((m, h) => Math.max(m, h.count), 0);
  const hourlyTotal = hourly.reduce((sum, h) => sum + h.count, 0);

  if (uLoading && usernames.length === 0) return <Skeleton rows={10} />;

  if (usernames.length === 0 && passwords.length === 0) {
    return (
      <EmptyState
        icon={KeyRound}
        title="No credentials attempted in this range"
        hint="Widen the time range, or check that login events are being ingested."
      />
    );
  }

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 gap-3">
        <FieldTable title="Top usernames" rows={usernames} color="text-cyan-400" />
        <FieldTable title="Top passwords" rows={passwords} color="text-orange-400" />
      </div>

      {pairs.length > 0 && (
        <div>
          <h3 className="text-xs font-medium text-gray-400 mb-1.5">Top pairs</h3>
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
                {pairs.slice(0, 12).map((pair, i) => (
                  <tr key={i} className="border-b border-gray-800 hover:bg-gray-700/30">
                    <td className="p-2 font-mono text-cyan-400">{pair.username}</td>
                    <td className="p-2 font-mono text-orange-400">{pair.password}</td>
                    <td className="p-2 text-right font-mono text-gray-300">
                      {formatNumber(pair.count)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {hourlyTotal > 0 && (
        <div>
          <h3 className="text-xs font-medium text-gray-400 mb-1.5 flex items-center gap-1.5">
            <Clock className="w-3.5 h-3.5 text-gray-500" aria-hidden />
            Attacks by local hour
            <span className="text-[10px] font-normal text-gray-600">
              {scopeLabel}
            </span>
          </h3>
          <div className="bg-gray-800/50 rounded-lg border border-gray-700/50 p-2">
            <div className="flex items-end gap-px h-20">
              {hourly.map((bucket) => (
                <div
                  key={bucket.hour}
                  className="flex-1 bg-blue-500/60 hover:bg-blue-400/80 rounded-t transition-colors"
                  style={{
                    height: `${hourlyMax > 0 ? Math.max((bucket.count / hourlyMax) * 100, 2) : 2}%`,
                  }}
                  title={`${String(bucket.hour).padStart(2, "0")}:00 — ${formatNumber(bucket.count)} events`}
                />
              ))}
            </div>
            <div className="flex justify-between mt-1 text-[9px] text-gray-600">
              <span>00:00</span>
              <span>12:00</span>
              <span>23:00</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
