import { Link } from "react-router-dom";
import { Radio, ServerCog, HardDrive, Share2 } from "lucide-react";
import { useSensors, useSensorOverlap } from "../../hooks/useAttempts";
import { formatNumber, formatTimestamp } from "../../utils/formatters";
import Skeleton from "../common/Skeleton";
import EmptyState from "../common/EmptyState";
import type { Sensor } from "../../types";

function formatBytes(bytes: number | null): string {
  if (bytes == null) return "—";
  const gb = bytes / 1024 ** 3;
  if (gb >= 1) return `${gb.toFixed(1)} GB`;
  return `${(bytes / 1024 ** 2).toFixed(0)} MB`;
}

function StatusDot({ status }: { status: Sensor["status"] }) {
  const color =
    status === "online" ? "bg-emerald-500" : status === "offline" ? "bg-rose-500" : "bg-gray-600";
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className={`w-2 h-2 rounded-full ${color} ${status === "online" ? "animate-pulse" : ""}`} />
      <span className="text-[10px] uppercase tracking-wider text-gray-400">{status}</span>
    </span>
  );
}

function SensorCard({ sensor }: { sensor: Sensor }) {
  const location =
    [sensor.city, sensor.country_name || sensor.country_code].filter(Boolean).join(", ") ||
    "Location not set";

  return (
    <div className="bg-gray-800/50 border border-gray-700/50 rounded-lg p-3 space-y-2">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-sm font-semibold text-white truncate">{sensor.label}</span>
            {sensor.is_local && (
              <span className="text-[9px] px-1.5 py-0.5 rounded bg-blue-600/20 text-blue-300 uppercase tracking-wider">
                hub
              </span>
            )}
          </div>
          <div className="text-[11px] text-gray-500 font-mono">{sensor.sensor_id}</div>
        </div>
        <StatusDot status={sensor.status} />
      </div>

      <div className="text-xs text-gray-400">
        {location}
        {sensor.location_precision === "country" && (
          <span className="text-gray-600" title="Published at country level only">
            {" "}· approximate
          </span>
        )}
      </div>

      <div className="grid grid-cols-3 gap-2 text-center">
        <div>
          <div className="text-sm font-bold tabular-nums text-red-400">
            {formatNumber(sensor.attempts_24h)}
          </div>
          <div className="text-[9px] text-gray-500 uppercase tracking-wider">24h attacks</div>
        </div>
        <div>
          <div className="text-sm font-bold tabular-nums text-blue-400">
            {formatNumber(sensor.unique_ips_24h)}
          </div>
          <div className="text-[9px] text-gray-500 uppercase tracking-wider">24h IPs</div>
        </div>
        <div>
          <div className="text-sm font-bold tabular-nums text-gray-300">
            {formatNumber(sensor.total_attempts)}
          </div>
          <div className="text-[9px] text-gray-500 uppercase tracking-wider">all time</div>
        </div>
      </div>

      {Object.keys(sensor.protocol_breakdown).length > 0 && (
        <div className="flex flex-wrap gap-1">
          {Object.entries(sensor.protocol_breakdown)
            .sort((a, b) => b[1] - a[1])
            .map(([protocol, count]) => (
              <span
                key={protocol}
                className="text-[10px] px-1.5 py-0.5 rounded bg-gray-700/60 text-gray-300 font-mono"
                title={`${formatNumber(count)} events in the last 24h`}
              >
                {protocol} {formatNumber(count)}
              </span>
            ))}
        </div>
      )}

      <div className="text-[10px] text-gray-500 space-y-0.5 pt-1 border-t border-gray-700/50">
        <div>
          Last event:{" "}
          {sensor.last_event_at ? formatTimestamp(sensor.last_event_at) : "never"}
        </div>
        {!sensor.is_local && (
          <div>
            Heartbeat:{" "}
            {sensor.last_heartbeat_at ? formatTimestamp(sensor.last_heartbeat_at) : "never"}
            {sensor.agent_version && (
              <span className="text-gray-600"> · agent {sensor.agent_version}</span>
            )}
          </div>
        )}
        {sensor.disk_total_bytes != null && (
          <div className={sensor.low_disk ? "text-amber-400" : undefined}>
            <HardDrive className="inline w-3 h-3 mr-1 -mt-0.5" aria-hidden />
            {formatBytes(sensor.disk_free_bytes)} free of{" "}
            {formatBytes(sensor.disk_total_bytes)}
            {sensor.low_disk && " — low"}
          </div>
        )}
      </div>
    </div>
  );
}

export default function FleetPanel() {
  const { data: sensors, loading } = useSensors();
  const { data: overlap } = useSensorOverlap(7);

  if (loading && sensors.length === 0) return <Skeleton rows={6} />;

  if (sensors.length === 0) {
    return (
      <EmptyState
        icon={ServerCog}
        title="No sensors registered"
        hint="The hub registers its own sensor at startup. Remote sensors are provisioned with the admin API."
      />
    );
  }

  return (
    <div className="space-y-4">
      <div className="space-y-2">
        {sensors.map((sensor) => (
          <SensorCard key={sensor.sensor_id} sensor={sensor} />
        ))}
      </div>

      <div>
        <h3 className="text-sm font-semibold text-gray-300 mb-2 flex items-center gap-1.5">
          <Share2 className="w-3.5 h-3.5 text-gray-500" aria-hidden />
          Cross-sensor overlap
          <span className="text-[10px] font-normal text-gray-500">last 7 days</span>
        </h3>

        {overlap.sensors_reporting < 2 ? (
          <div className="bg-gray-800/50 border border-gray-700/50 rounded-lg p-3 text-xs text-gray-400">
            <Radio className="inline w-3.5 h-3.5 mr-1.5 -mt-0.5 text-gray-500" aria-hidden />
            Overlap needs two reporting sensors. With one, every attacker is
            unique to it by definition.
          </div>
        ) : (
          <div className="space-y-2">
            <div className="grid grid-cols-3 gap-2">
              <div className="bg-gray-800/50 border border-gray-700/50 rounded-lg p-2 text-center">
                <div className="text-lg font-bold tabular-nums text-amber-400">
                  {overlap.overlap_rate}%
                </div>
                <div className="text-[9px] text-gray-500 uppercase tracking-wider">
                  seen by 2+
                </div>
              </div>
              <div className="bg-gray-800/50 border border-gray-700/50 rounded-lg p-2 text-center">
                <div className="text-lg font-bold tabular-nums text-white">
                  {formatNumber(overlap.shared_ips)}
                </div>
                <div className="text-[9px] text-gray-500 uppercase tracking-wider">
                  shared IPs
                </div>
              </div>
              <div className="bg-gray-800/50 border border-gray-700/50 rounded-lg p-2 text-center">
                <div className="text-lg font-bold tabular-nums text-gray-300">
                  {formatNumber(overlap.total_ips)}
                </div>
                <div className="text-[9px] text-gray-500 uppercase tracking-wider">
                  total IPs
                </div>
              </div>
            </div>

            <p className="text-[11px] text-gray-500 leading-relaxed">
              An IP hitting several sensors is scanning the internet
              indiscriminately. One hitting a single sensor is comparatively
              targeted — that is the distinction a second sensor buys.
            </p>

            {overlap.top_shared.length > 0 && (
              <div className="bg-gray-800/50 rounded-lg border border-gray-700/50 overflow-hidden">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-gray-700">
                      <th className="text-left p-2 text-gray-400 font-medium">IP</th>
                      <th className="text-left p-2 text-gray-400 font-medium">Sensors</th>
                      <th className="text-right p-2 text-gray-400 font-medium">Events</th>
                    </tr>
                  </thead>
                  <tbody>
                    {overlap.top_shared.slice(0, 10).map((row) => (
                      <tr key={row.src_ip} className="border-b border-gray-800 hover:bg-gray-700/30">
                        <td className="p-2 font-mono">
                          <Link
                            to={`/profile/${encodeURIComponent(row.src_ip)}`}
                            className="text-cyan-400 hover:text-cyan-300 hover:underline"
                          >
                            {row.src_ip}
                          </Link>
                        </td>
                        <td className="p-2 text-gray-400">{row.sensors.join(", ")}</td>
                        <td className="p-2 text-right font-mono text-orange-400">
                          {formatNumber(row.total)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
