import { useState } from "react";
import { Link } from "react-router-dom";
import { Network, KeyRound, Terminal, FileDigit } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { useCampaigns } from "../../hooks/useAttempts";
import { useSensorScope } from "../../context/SensorContext";
import { formatNumber, formatTimestamp } from "../../utils/formatters";
import Skeleton from "../common/Skeleton";
import EmptyState from "../common/EmptyState";
import type { CampaignGroup } from "../../types";

const KIND_META: Record<CampaignGroup["kind"], { icon: LucideIcon; label: string; color: string }> = {
  credentials: { icon: KeyRound, label: "Credential list", color: "text-cyan-400" },
  payload: { icon: FileDigit, label: "Shared payload", color: "text-rose-400" },
  commands: { icon: Terminal, label: "Command sequence", color: "text-emerald-400" },
};

const WINDOWS = [1, 7, 30] as const;

function CampaignCard({ campaign }: { campaign: CampaignGroup }) {
  const [expanded, setExpanded] = useState(false);
  const meta = KIND_META[campaign.kind];
  const Icon = meta.icon;

  return (
    <div className="bg-gray-800/50 border border-gray-700/50 rounded-lg p-3 space-y-2">
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-start gap-2 min-w-0">
          <Icon className={`w-4 h-4 mt-0.5 shrink-0 ${meta.color}`} aria-hidden />
          <div className="min-w-0">
            <div className="text-xs font-medium text-white">{campaign.summary}</div>
            <div className="text-[10px] text-gray-500">
              {meta.label} · {formatNumber(campaign.event_count)} events
              {campaign.first_seen && ` · from ${formatTimestamp(campaign.first_seen)}`}
            </div>
          </div>
        </div>
        {campaign.sensors.length > 1 && (
          <span
            className="text-[9px] px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 uppercase tracking-wider shrink-0"
            title="Observed at more than one sensor — corroborated across sites"
          >
            {campaign.sensors.length} sensors
          </span>
        )}
      </div>

      <div className="flex flex-wrap gap-1">
        {campaign.countries.slice(0, 5).map((country) => (
          <span key={country} className="text-[10px] px-1.5 py-0.5 rounded bg-gray-700/60 text-gray-300">
            {country}
          </span>
        ))}
        {campaign.asns.slice(0, 3).map((asn) => (
          <span key={asn} className="text-[10px] px-1.5 py-0.5 rounded bg-gray-700/40 text-gray-400 font-mono">
            AS{asn}
          </span>
        ))}
      </div>

      <div className="bg-gray-900/60 rounded p-2 font-mono text-[10px] text-gray-400 space-y-0.5 max-h-24 overflow-auto">
        {campaign.sample.map((line, i) => (
          <div key={i} className="truncate">{line}</div>
        ))}
      </div>

      <button
        onClick={() => setExpanded((e) => !e)}
        className="text-[11px] text-blue-400 hover:text-blue-300"
      >
        {expanded ? "Hide" : "Show"} {formatNumber(campaign.ip_count)} source IPs
      </button>

      {expanded && (
        <div className="flex flex-wrap gap-x-3 gap-y-1">
          {campaign.ips.map((ip) => (
            <Link
              key={ip}
              to={`/profile/${encodeURIComponent(ip)}`}
              className="text-[10px] font-mono text-cyan-400 hover:text-cyan-300 hover:underline"
            >
              {ip}
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}

export default function CampaignsPanel() {
  const { sensorId } = useSensorScope();
  const [days, setDays] = useState<number>(7);
  const { data: campaigns, loading } = useCampaigns(days, sensorId);

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between gap-2">
        <p className="text-[11px] text-gray-500 leading-relaxed max-w-md">
          Groups of IPs running the same operation — identical credential lists,
          payloads, or command sequences. Twenty addresses acting as one.
        </p>
        <div className="flex gap-0.5 bg-gray-800/60 rounded-md p-0.5 shrink-0">
          {WINDOWS.map((w) => (
            <button
              key={w}
              onClick={() => setDays(w)}
              className={`px-2 py-0.5 rounded text-xs font-medium transition-colors ${
                days === w ? "bg-blue-600 text-white" : "text-gray-400 hover:text-white"
              }`}
            >
              {w}d
            </button>
          ))}
        </div>
      </div>

      {loading && campaigns.length === 0 ? (
        <Skeleton rows={6} />
      ) : campaigns.length === 0 ? (
        <EmptyState
          icon={Network}
          title="No campaigns in this window"
          hint="A campaign needs two or more IPs sharing a credential list, payload, or command sequence. Try a longer window."
        />
      ) : (
        <div className="space-y-2">
          {campaigns.map((campaign) => (
            <CampaignCard key={campaign.campaign_id} campaign={campaign} />
          ))}
        </div>
      )}
    </div>
  );
}
