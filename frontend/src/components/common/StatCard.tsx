import { formatNumber } from "../../utils/formatters";

interface StatCardProps {
  label: string;
  value: number;
  icon: string;
  color?: string;
}

export default function StatCard({ label, value, icon, color = "text-blue-400" }: StatCardProps) {
  return (
    <div className="bg-gray-800/50 border border-gray-700/50 rounded-lg p-3 flex items-center gap-3">
      <span className={`text-xl ${color}`}>{icon}</span>
      <div>
        <div className="text-lg font-bold text-white">{formatNumber(value)}</div>
        <div className="text-xs text-gray-400">{label}</div>
      </div>
    </div>
  );
}
