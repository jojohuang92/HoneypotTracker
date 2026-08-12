import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { UserSearch } from "lucide-react";
import { fetchJSON } from "../../utils/api";
import { formatTimestamp, intentColor, intentLabel } from "../../utils/formatters";
import type { AttackerProfile } from "../../types";
import Skeleton from "../common/Skeleton";
import EmptyState from "../common/EmptyState";

function StatBox({ label, value, color = "text-white" }: { label: string; value: string | number; color?: string }) {
  return (
    <div className="bg-gray-800/50 rounded-lg p-2 border border-gray-700/50">
      <div className={`text-lg font-bold ${color}`}>{typeof value === "number" ? value.toLocaleString() : value}</div>
      <div className="text-[10px] text-gray-500 uppercase tracking-wider">{label}</div>
    </div>
  );
}

/** The profiled IP lives in the URL (/profile/:ip) so profiles are
 *  shareable and every IP shown elsewhere can link straight here.
 *  The route keys this component by IP, so state resets per profile. */
export default function AttackerProfilePanel() {
  const { ip } = useParams<{ ip: string }>();
  const navigate = useNavigate();
  const [inputValue, setInputValue] = useState(ip ?? "");
  const [profile, setProfile] = useState<AttackerProfile | null>(null);
  const [loading, setLoading] = useState(Boolean(ip));
  const [error, setError] = useState("");

  const lookup = () => {
    const lookupIp = inputValue.trim();
    if (!lookupIp) return;
    navigate(`/profile/${encodeURIComponent(lookupIp)}`);
  };

  useEffect(() => {
    if (!ip) return;
    let cancelled = false;
    fetchJSON<AttackerProfile>(`/profile/${encodeURIComponent(ip)}`)
      .then((nextProfile) => {
        if (cancelled) return;
        setProfile(nextProfile);
        setError("");
      })
      .catch(() => {
        if (cancelled) return;
        setProfile(null);
        setError(`No activity recorded for ${ip}`);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [ip]);

  return (
    <div className="flex flex-col h-full">
      {/* Search bar */}
      <div className="pb-2 border-b border-gray-700">
        <form
          onSubmit={(e) => { e.preventDefault(); lookup(); }}
          className="flex gap-2"
        >
          <input
            type="text"
            value={inputValue}
            onChange={(e) => setInputValue(e.target.value)}
            placeholder="Enter IP address..."
            className="flex-1 px-3 py-2 text-xs bg-gray-800 border border-gray-600 rounded-lg text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500 font-mono"
          />
          <button
            type="submit"
            disabled={loading}
            className="px-3 py-2 text-xs rounded-lg bg-blue-600 text-white hover:bg-blue-500 disabled:opacity-50"
          >
            {loading ? "..." : "Lookup"}
          </button>
        </form>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-auto p-3 space-y-4">
        {!profile && !loading && !error && (
          <EmptyState
            icon={UserSearch}
            title="Profile an attacker IP"
            hint="Enter an IP above, or click any IP anywhere in the dashboard."
          />
        )}

        {error && !loading && (
          <EmptyState icon={UserSearch} title={error} hint="The IP may not have reached this honeypot." />
        )}

        {loading && <Skeleton rows={8} />}

        {profile && !loading && (
          <>
            {/* Header */}
            <div className="bg-gray-800/50 rounded-lg p-3 border border-gray-700/50">
              <div className="flex items-center justify-between">
                <div>
                  <div className="font-mono text-cyan-400 text-sm font-bold">{profile.src_ip}</div>
                  <div className="text-xs text-gray-400 mt-0.5">
                    {[profile.city, profile.country_name].filter(Boolean).join(", ") || "Unknown location"}
                    {profile.as_org && <span className="text-gray-500"> · {profile.as_org}</span>}
                  </div>
                </div>
                {profile.abuse_score !== null && (
                  <div className={`text-lg font-bold ${
                    profile.abuse_score >= 75 ? "text-red-400" :
                    profile.abuse_score >= 50 ? "text-orange-400" :
                    profile.abuse_score >= 25 ? "text-yellow-400" : "text-green-400"
                  }`}>
                    {profile.abuse_score}%
                    <div className="text-[10px] text-gray-500 font-normal text-right">abuse</div>
                  </div>
                )}
              </div>
              {profile.isp && (
                <div className="text-[10px] text-gray-500 mt-1">ISP: {profile.isp}</div>
              )}
              <div className="text-[10px] text-gray-500 mt-0.5">
                First seen: {profile.first_seen ? formatTimestamp(profile.first_seen) : "—"}
                {" · "}
                Last seen: {profile.last_seen ? formatTimestamp(profile.last_seen) : "—"}
              </div>
            </div>

            {/* Composite threat score, with the reasons behind it */}
            <div className="bg-gray-800/50 rounded-lg p-3 border border-gray-700/50">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <div className="text-[10px] text-gray-500 uppercase tracking-wider">
                    Threat score
                  </div>
                  <div className="flex items-baseline gap-2">
                    <span className={`text-2xl font-bold tabular-nums ${
                      profile.threat_level === "critical" ? "text-red-400" :
                      profile.threat_level === "high" ? "text-orange-400" :
                      profile.threat_level === "medium" ? "text-yellow-400" : "text-green-400"
                    }`}>
                      {profile.threat_score}
                    </span>
                    <span className="text-xs text-gray-500">/ 100 · {profile.threat_level}</span>
                  </div>
                </div>
                {profile.sensors_seen.length > 0 && (
                  <div className="text-right">
                    <div className="text-[10px] text-gray-500 uppercase tracking-wider">
                      Seen by
                    </div>
                    <div className="text-xs text-gray-300 font-mono">
                      {profile.sensors_seen.join(", ")}
                    </div>
                  </div>
                )}
              </div>

              {Object.keys(profile.threat_components).length > 0 && (
                <div className="mt-2 space-y-1">
                  {Object.entries(profile.threat_components).map(([name, value]) => (
                    <div key={name} className="flex items-center gap-2">
                      <span className="text-[10px] text-gray-500 w-20 capitalize">{name}</span>
                      <div className="flex-1 h-1 bg-gray-700 rounded-full overflow-hidden">
                        <div
                          className="h-full rounded-full bg-blue-500"
                          style={{ width: `${Math.min(100, value * 4)}%` }}
                        />
                      </div>
                      <span className="text-[10px] font-mono text-gray-400 w-6 text-right">
                        {value}
                      </span>
                    </div>
                  ))}
                </div>
              )}

              {profile.threat_reasons.length > 0 && (
                <ul className="mt-2 space-y-0.5">
                  {profile.threat_reasons.map((reason) => (
                    <li key={reason} className="text-[11px] text-gray-400">
                      · {reason}
                    </li>
                  ))}
                </ul>
              )}
            </div>

            {/* Stats grid */}
            <div className="grid grid-cols-4 gap-2">
              <StatBox label="Attempts" value={profile.total_attempts} color="text-red-400" />
              <StatBox label="Sessions" value={profile.total_sessions} color="text-blue-400" />
              <StatBox label="Commands" value={profile.total_commands} color="text-purple-400" />
              <StatBox label="Files" value={profile.total_files} color="text-orange-400" />
            </div>

            {/* Activity timeline */}
            {profile.timeline.length > 0 && (
              <div>
                <h3 className="text-xs font-medium text-gray-400 mb-2">Activity Timeline</h3>
                <div className="bg-gray-800/50 rounded-lg p-2 border border-gray-700/50">
                  <div className="flex items-end gap-px h-16">
                    {profile.timeline.map((t) => {
                      const max = Math.max(...profile.timeline.map((b) => b.count));
                      const height = max > 0 ? (t.count / max) * 100 : 0;
                      return (
                        <div
                          key={t.bucket}
                          className="flex-1 bg-blue-500/60 hover:bg-blue-400/80 rounded-t transition-colors"
                          style={{ height: `${Math.max(height, 2)}%` }}
                          title={`${t.bucket}: ${t.count} events`}
                        />
                      );
                    })}
                  </div>
                  <div className="flex justify-between mt-1">
                    <span className="text-[9px] text-gray-600">{profile.timeline[0]?.bucket}</span>
                    <span className="text-[9px] text-gray-600">{profile.timeline[profile.timeline.length - 1]?.bucket}</span>
                  </div>
                </div>
              </div>
            )}

            {/* Intents */}
            {profile.intents.length > 0 && (
              <div>
                <h3 className="text-xs font-medium text-gray-400 mb-2">Attack Intents</h3>
                <div className="space-y-1">
                  {profile.intents.map((i) => (
                    <div key={i.intent} className="flex items-center gap-2">
                      <span
                        className="inline-block px-1.5 py-0.5 rounded text-[10px] font-medium min-w-[80px] text-center"
                        style={{
                          backgroundColor: intentColor(i.intent) + "20",
                          color: intentColor(i.intent),
                        }}
                      >
                        {intentLabel(i.intent)}
                      </span>
                      <div className="flex-1 bg-gray-800 rounded-full h-1.5">
                        <div
                          className="h-full rounded-full"
                          style={{
                            width: `${i.percentage}%`,
                            backgroundColor: intentColor(i.intent),
                          }}
                        />
                      </div>
                      <span className="text-[10px] text-gray-500 w-8 text-right">{i.count}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Top commands */}
            {profile.top_commands.length > 0 && (
              <div>
                <h3 className="text-xs font-medium text-gray-400 mb-2">Top Commands</h3>
                <div className="bg-gray-800/50 rounded-lg border border-gray-700/50 overflow-hidden">
                  {profile.top_commands.slice(0, 10).map((c, i) => (
                    <div
                      key={i}
                      className="flex items-center justify-between px-2 py-1.5 border-b border-gray-800/50 last:border-0"
                    >
                      <code className="text-[10px] text-green-400 truncate flex-1 mr-2">
                        $ {c.command}
                      </code>
                      <span className="text-[10px] text-gray-500 shrink-0">{c.count}×</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Top credentials */}
            {profile.top_credentials.length > 0 && (
              <div>
                <h3 className="text-xs font-medium text-gray-400 mb-2">Credentials Tried</h3>
                <div className="bg-gray-800/50 rounded-lg border border-gray-700/50 overflow-hidden">
                  {profile.top_credentials.map((c, i) => (
                    <div
                      key={i}
                      className="flex items-center justify-between px-2 py-1.5 border-b border-gray-800/50 last:border-0"
                    >
                      <span className="text-[10px] font-mono">
                        <span className="text-cyan-400">{c.username}</span>
                        <span className="text-gray-600">:</span>
                        <span className="text-orange-400">{c.password}</span>
                      </span>
                      <span className="text-[10px] text-gray-500">{c.count}×</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Sessions */}
            {profile.sessions.length > 0 && (
              <div>
                <h3 className="text-xs font-medium text-gray-400 mb-2">Sessions</h3>
                <div className="bg-gray-800/50 rounded-lg border border-gray-700/50 overflow-hidden">
                  {profile.sessions.map((s) => (
                    <button
                      key={s.session_id}
                      onClick={() => navigate(`/replay/${encodeURIComponent(s.session_id)}`)}
                      className="w-full flex items-center justify-between px-2 py-1.5 border-b border-gray-800/50 last:border-0 hover:bg-gray-700/30 text-left transition-colors"
                    >
                      <div>
                        <span className="text-[10px] font-mono text-blue-400">{s.session_id.slice(0, 12)}</span>
                        <span className="text-[10px] text-gray-500 ml-2">
                          {s.start_time ? formatTimestamp(s.start_time) : "—"}
                        </span>
                      </div>
                      <div className="flex gap-3 text-[10px] text-gray-500">
                        {s.login_attempts > 0 && <span>{s.login_attempts} logins</span>}
                        {s.commands_run > 0 && <span>{s.commands_run} cmds</span>}
                        {s.files_downloaded > 0 && <span>{s.files_downloaded} files</span>}
                        {s.duration_secs != null && (
                          <span>{Math.round(s.duration_secs)}s</span>
                        )}
                        <span className="text-blue-400">▶</span>
                      </div>
                    </button>
                  ))}
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
