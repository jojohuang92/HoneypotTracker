import { useMemo } from "react";
import { LayoutGrid } from "lucide-react";
import { useMitreMatrix } from "../../hooks/useAttempts";
import { useTimeRange } from "../../context/TimeRangeContext";
import type { MitreTechnique } from "../../types";
import Skeleton from "../common/Skeleton";
import EmptyState from "../common/EmptyState";

/** Heatmap color ramp: light-blue → orange → red, driven by count relative to max. */
function heatStyle(count: number, max: number): { background: string; color: string } {
  if (max === 0) return { background: "rgb(31, 41, 55)", color: "rgb(156, 163, 175)" };
  const t = Math.min(1, Math.log10(count + 1) / Math.log10(max + 1));
  // Stops: (0) gray → (0.25) blue → (0.55) amber → (1.0) red
  const stops = [
    { at: 0.0, rgb: [31, 41, 55] },
    { at: 0.2, rgb: [37, 99, 235] },
    { at: 0.55, rgb: [234, 88, 12] },
    { at: 1.0, rgb: [220, 38, 38] },
  ];
  let lo = stops[0]!;
  let hi = stops[stops.length - 1]!;
  for (let i = 0; i < stops.length - 1; i++) {
    const a = stops[i]!;
    const b = stops[i + 1]!;
    if (t >= a.at && t <= b.at) {
      lo = a;
      hi = b;
      break;
    }
  }
  const span = hi.at - lo.at || 1;
  const f = (t - lo.at) / span;
  const rgb = lo.rgb.map((c, i) => Math.round(c + (hi.rgb[i]! - c) * f));
  // Pick text color based on luminance
  const lum = 0.299 * rgb[0]! + 0.587 * rgb[1]! + 0.114 * rgb[2]!;
  return {
    background: `rgb(${rgb.join(",")})`,
    color: lum > 150 ? "rgb(15,23,42)" : "rgb(248,250,252)",
  };
}

function TechniqueCell({ t, max }: { t: MitreTechnique; max: number }) {
  const style = heatStyle(t.count, max);
  const display = t.technique_name.replace(/:.*$/, ""); // trim sub-technique suffix
  return (
    <div
      className="rounded px-1.5 py-1 border border-gray-800/50 text-[10px] leading-tight hover:ring-2 hover:ring-blue-400 transition-all"
      style={style}
      title={`${t.mitre_id} — ${t.technique_name}: ${t.count.toLocaleString()} events`}
    >
      <div className="font-mono text-[9px] opacity-70">{t.mitre_id}</div>
      <div className="truncate font-medium">{display}</div>
      <div className="text-right font-mono font-bold mt-0.5">
        {t.count.toLocaleString()}
      </div>
    </div>
  );
}

export default function MitreMatrix() {
  const { range } = useTimeRange();
  const { data, loading } = useMitreMatrix(range.days);

  const maxTechniqueCount = useMemo(() => {
    let max = 0;
    for (const tac of data.tactics) {
      for (const t of tac.techniques) {
        if (t.count > max) max = t.count;
      }
    }
    return max;
  }, [data]);

  if (loading && data.tactics.length === 0) {
    return <Skeleton rows={8} />;
  }

  if (data.tactics.length === 0) {
    return (
      <EmptyState
        icon={LayoutGrid}
        title="No MITRE-tagged events in this range"
        hint="Techniques appear as the classifier labels attacker commands — widen the time range to see more."
      />
    );
  }

  return (
    <div className="space-y-2">
      {/* Header */}
      <div className="flex items-baseline justify-between">
        <div>
          <h3 className="text-sm font-semibold text-gray-200">MITRE ATT&CK Coverage</h3>
          <p className="text-[10px] text-gray-500">
            {data.tactics.length} tactics · {data.tactics.reduce((a, t) => a + t.techniques.length, 0)} techniques ·{" "}
            {data.grand_total.toLocaleString()} events
          </p>
        </div>
        <a
          href="https://attack.mitre.org/matrices/enterprise/"
          target="_blank"
          rel="noopener noreferrer"
          className="text-[10px] text-blue-400 hover:underline"
        >
          ATT&CK Navigator ↗
        </a>
      </div>

      {/* Matrix — horizontal scroll on narrow screens, columns for tactics */}
      <div className="overflow-x-auto border border-gray-800 rounded-lg">
        <div
          className="flex gap-px bg-gray-800"
          style={{ minWidth: `${data.tactics.length * 150}px` }}
        >
          {data.tactics.map((tactic) => (
            <div key={tactic.tactic_id} className="flex-1 min-w-[140px] bg-gray-900">
              {/* Tactic header */}
              <div className="px-2 py-1.5 border-b border-gray-700 bg-gray-800/70 sticky top-0">
                <div className="text-[10px] font-semibold text-gray-200 truncate">
                  {tactic.tactic_name}
                </div>
                <div className="text-[9px] text-gray-500 font-mono">
                  {tactic.techniques.length} / {tactic.total.toLocaleString()}
                </div>
              </div>
              {/* Techniques */}
              <div className="p-1 space-y-1">
                {tactic.techniques.map((t) => (
                  <TechniqueCell key={t.mitre_id} t={t} max={maxTechniqueCount} />
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Legend */}
      <div className="flex items-center gap-2 text-[10px] text-gray-500 pt-1">
        <span>Intensity:</span>
        <div className="flex h-2 flex-1 rounded overflow-hidden">
          {Array.from({ length: 40 }, (_, i) => {
            const fakeCount = Math.round(((i + 1) / 40) * maxTechniqueCount);
            return (
              <div
                key={i}
                className="flex-1"
                style={{ background: heatStyle(fakeCount, maxTechniqueCount).background }}
              />
            );
          })}
        </div>
        <span>1</span>
        <span className="font-mono">→</span>
        <span>{maxTechniqueCount.toLocaleString()}</span>
      </div>
    </div>
  );
}
