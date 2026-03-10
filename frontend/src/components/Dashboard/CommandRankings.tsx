import { useCommandRanks } from "../../hooks/useAttempts";
import { intentLabel, intentColor } from "../../utils/formatters";

export default function CommandRankings() {
  const { data, loading } = useCommandRanks();

  if (loading) return <div className="text-gray-500 text-center py-8">Loading...</div>;

  const maxCount = data.length > 0 ? data[0].count : 1;

  return (
    <div className="space-y-3">
      <h3 className="text-sm font-semibold text-gray-300">Most Executed Commands</h3>

      <div className="space-y-1.5">
        {data.map((cmd, i) => (
          <div
            key={i}
            className="bg-gray-800/50 rounded-lg p-2.5 border border-gray-700/50 hover:border-gray-600 transition-colors"
          >
            <div className="flex items-center justify-between mb-1">
              <code className="text-xs text-green-400 font-mono break-all">
                $ {cmd.command}
              </code>
              <span className="text-xs font-mono text-gray-400 ml-2 shrink-0">
                {cmd.count}x
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
          </div>
        ))}
      </div>
    </div>
  );
}
