import { useNavigate } from "react-router-dom";
import { Terminal } from "lucide-react";
import { useCommandRanks } from "../../hooks/useAttempts";
import { useTimeRange } from "../../context/TimeRangeContext";
import { useSensorScope } from "../../context/SensorContext";
import { intentLabel, intentColor, formatNumber } from "../../utils/formatters";
import Skeleton from "../common/Skeleton";
import EmptyState from "../common/EmptyState";

export default function CommandRankings() {
  const { range } = useTimeRange();
  const { sensorId } = useSensorScope();
  const { data, loading } = useCommandRanks(range.days, sensorId);
  const navigate = useNavigate();

  if (loading && data.length === 0) return <Skeleton rows={10} />;

  if (data.length === 0) {
    return (
      <EmptyState
        icon={Terminal}
        title="No commands recorded in this range"
        hint="Commands appear once attackers get past login and start typing."
      />
    );
  }

  const maxCount = data[0].count;

  return (
    <div className="space-y-3">
      <h3 className="text-sm font-semibold text-gray-300">Most Executed Commands</h3>

      <div className="space-y-1.5">
        {data.map((cmd, i) => (
          <button
            key={i}
            onClick={() => navigate(`/search?q=${encodeURIComponent(cmd.command)}`)}
            title="Find sessions that ran this command"
            className="w-full text-left bg-gray-800/50 rounded-lg p-2.5 border border-gray-700/50 hover:border-gray-500 transition-colors"
          >
            <div className="flex items-center justify-between mb-1">
              <code className="text-xs text-green-400 font-mono break-all">
                $ {cmd.command}
              </code>
              <span className="text-xs font-mono text-gray-400 ml-2 shrink-0">
                {formatNumber(cmd.count)}×
              </span>
            </div>
            <div className="flex items-center gap-2">
              <div className="flex-1 h-1 bg-gray-700 rounded-full overflow-hidden">
                <div
                  className="h-full rounded-full transition-all"
                  style={{
                    width: `${(cmd.count / maxCount) * 100}%`,
                    backgroundColor: intentColor(cmd.intent),
                  }}
                />
              </div>
              {cmd.intent && (
                <span
                  className="text-[10px] px-1.5 py-0.5 rounded"
                  style={{
                    backgroundColor: intentColor(cmd.intent) + "20",
                    color: intentColor(cmd.intent),
                  }}
                >
                  {intentLabel(cmd.intent)}
                </span>
              )}
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}
