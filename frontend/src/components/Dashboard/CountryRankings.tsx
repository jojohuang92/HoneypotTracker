import { useCountryRanks } from "../../hooks/useAttempts";
import CountryBarChart from "../Charts/BarChart";

export default function CountryRankings() {
  const { data, loading } = useCountryRanks();

  if (loading) return <div className="text-gray-500 text-center py-8">Loading...</div>;

  return (
    <div className="space-y-4">
      <div className="h-64 bg-gray-800/50 rounded-lg p-3 border border-gray-700/50">
        <CountryBarChart
          data={data.slice(0, 10).map((c) => ({
            name: c.country_code,
            value: c.count,
          }))}
        />
      </div>

      <div className="bg-gray-800/50 rounded-lg border border-gray-700/50 overflow-hidden">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-gray-700">
              <th className="text-left p-2 text-gray-400 font-medium">#</th>
              <th className="text-left p-2 text-gray-400 font-medium">Country</th>
              <th className="text-right p-2 text-gray-400 font-medium">Attacks</th>
              <th className="text-right p-2 text-gray-400 font-medium">%</th>
            </tr>
          </thead>
          <tbody>
            {data.map((c, i) => (
              <tr key={c.country_code} className="border-b border-gray-800 hover:bg-gray-700/30">
                <td className="p-2 text-gray-500">{i + 1}</td>
                <td className="p-2">
                  <span className="text-white font-medium">{c.country_name}</span>
                  <span className="ml-1 text-gray-500">({c.country_code})</span>
                </td>
                <td className="p-2 text-right font-mono text-orange-400">
                  {c.count.toLocaleString()}
                </td>
                <td className="p-2 text-right text-gray-400">{c.percentage}%</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
