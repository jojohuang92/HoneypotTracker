import { useIntentBreakdown } from "../../hooks/useAttempts";
import IntentPieChart from "../Charts/PieChart";
import { intentLabel, intentColor } from "../../utils/formatters";

export default function IntentClassification() {
  const { data, loading } = useIntentBreakdown();

  if (loading) return <div className="text-gray-500 text-center py-8">Loading...</div>;

  const chartData = data.map((d) => ({
    name: intentLabel(d.intent),
    value: d.count,
    color: intentColor(d.intent),
  }));

  return (
    <div className="space-y-4">
      <div className="h-64 bg-gray-800/50 rounded-lg p-3 border border-gray-700/50">
        <IntentPieChart data={chartData} />
      </div>

      <div className="bg-gray-800/50 rounded-lg border border-gray-700/50 overflow-hidden">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-gray-700">
              <th className="text-left p-2 text-gray-400 font-medium">Intent</th>
              <th className="text-left p-2 text-gray-400 font-medium">MITRE</th>
              <th className="text-right p-2 text-gray-400 font-medium">Count</th>
              <th className="text-right p-2 text-gray-400 font-medium">%</th>
            </tr>
          </thead>
          <tbody>
            {data.map((d) => (
              <tr key={d.intent} className="border-b border-gray-800 hover:bg-gray-700/30">
                <td className="p-2">
                  <span
                    className="inline-block w-2 h-2 rounded-full mr-2"
                    style={{ backgroundColor: intentColor(d.intent) }}
                  />
                  <span className="text-white">{intentLabel(d.intent)}</span>
                </td>
                <td className="p-2 font-mono text-cyan-400">{d.mitre_id || "—"}</td>
                <td className="p-2 text-right font-mono text-orange-400">
                  {d.count.toLocaleString()}
                </td>
                <td className="p-2 text-right text-gray-400">{d.percentage}%</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {data.some((d) => d.description) && (
        <div className="bg-gray-800/50 rounded-lg p-3 border border-gray-700/50">
          <h4 className="text-xs font-semibold text-gray-400 mb-2">MITRE ATT&CK Reference</h4>
          <div className="space-y-1">
            {data
              .filter((d) => d.description)
              .map((d) => (
                <div key={d.intent} className="text-xs text-gray-400">
                  <span className="font-mono text-cyan-400">{d.mitre_id}</span>
                  {" — "}
                  {d.description}
                </div>
              ))}
          </div>
        </div>
      )}
    </div>
  );
}
