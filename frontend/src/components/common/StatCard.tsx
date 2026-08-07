import { TrendingDown, TrendingUp } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { formatNumber } from "../../utils/formatters";

interface StatCardProps {
  label: string;
  value: number;
  icon: LucideIcon;
  color?: string;
  hint?: string;
  title?: string;
  /** Change vs the previous period, e.g. { value: +312, label: "vs prev 24h" } */
  delta?: { value: number; label: string } | null;
}

export default function StatCard({
  label,
  value,
  icon: Icon,
  color = "text-blue-400",
  hint,
  title,
  delta,
}: StatCardProps) {
  return (
    <div className="bg-gray-800/50 border border-gray-700/50 rounded-lg p-3 flex items-center gap-3" title={title}>
      <Icon className={`w-5 h-5 shrink-0 ${color}`} aria-hidden />
      <div className="min-w-0">
        <div className="text-lg font-bold text-white leading-tight">{formatNumber(value)}</div>
        <div className="text-xs text-gray-400 truncate">
          {label}
          {hint && <span className="text-gray-500"> ({hint})</span>}
        </div>
        {delta && delta.value !== 0 && (
          <div
            className={`flex items-center gap-1 text-[10px] mt-0.5 ${
              delta.value > 0 ? "text-rose-400" : "text-emerald-400"
            }`}
            title={`${formatNumber(Math.abs(delta.value))} ${delta.value > 0 ? "more" : "fewer"} ${delta.label}`}
          >
            {delta.value > 0 ? (
              <TrendingUp className="w-3 h-3" aria-hidden />
            ) : (
              <TrendingDown className="w-3 h-3" aria-hidden />
            )}
            {delta.value > 0 ? "+" : "−"}
            {formatNumber(Math.abs(delta.value))} {delta.label}
          </div>
        )}
      </div>
    </div>
  );
}
