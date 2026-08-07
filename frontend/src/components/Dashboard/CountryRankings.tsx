import { useNavigate } from "react-router-dom";
import { Globe } from "lucide-react";
import { useCountryRanks } from "../../hooks/useAttempts";
import { useTimeRange } from "../../context/TimeRangeContext";
import { formatNumber } from "../../utils/formatters";
import CountryBarChart from "../Charts/BarChart";
import Skeleton from "../common/Skeleton";
import EmptyState from "../common/EmptyState";

export default function CountryRankings() {
  const { range } = useTimeRange();
  const { data, loading } = useCountryRanks(range.days);
  const navigate = useNavigate();

  if (loading && data.length === 0) return <Skeleton rows={10} />;

  if (data.length === 0) {
    return (
      <EmptyState
        icon={Globe}
        title="No geolocated attacks in this range"
        hint="Widen the time range, or check that the GeoIP database is configured."
      />
    );
  }

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
              <tr
                key={c.country_code}
                onClick={() => navigate(`/attempts?country=${encodeURIComponent(c.country_code)}`)}
                title={`View attempts from ${c.country_name}`}
                className="border-b border-gray-800 hover:bg-gray-700/30 cursor-pointer"
              >
                <td className="p-2 text-gray-500">{i + 1}</td>
                <td className="p-2">
                  <span className="text-white font-medium">{c.country_name}</span>
                  <span className="ml-1 text-gray-500">({c.country_code})</span>
                </td>
                <td className="p-2 text-right font-mono text-orange-400">
                  {formatNumber(c.count)}
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
