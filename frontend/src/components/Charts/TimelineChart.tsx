import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from "recharts";
import type { TimelineBucket } from "../../types";

interface TimelineChartProps {
  data: TimelineBucket[];
}

function formatBucket(bucket: string): { label: string; full: string } {
  // Buckets arrive already in local time from the backend
  const isHourly = bucket.includes(" ");
  if (isHourly) {
    const [date, time] = bucket.split(" ");
    const [, month, day] = date.split("-");
    return { label: time, full: `${month}/${day} ${time}` };
  } else {
    const [, month, day] = bucket.split("-");
    return { label: `${month}/${day}`, full: bucket };
  }
}

export default function TimelineChart({ data }: TimelineChartProps) {
  const formatted = data.map((d) => {
    const { label, full } = formatBucket(d.bucket);
    return { ...d, label, full };
  });

  return (
    <ResponsiveContainer width="100%" height="100%">
      <AreaChart data={formatted} margin={{ top: 5, right: 30, bottom: 0, left: 0 }}>
        <defs>
          <linearGradient id="attackGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
            <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
        <XAxis
          dataKey="label"
          tick={{ fill: "#64748b", fontSize: 10 }}
          axisLine={{ stroke: "#334155" }}
          interval="preserveStartEnd"
          padding={{ right: 10 }}
        />
        <YAxis
          tick={{ fill: "#64748b", fontSize: 10 }}
          axisLine={{ stroke: "#334155" }}
          width={35}
        />
        <Tooltip
          contentStyle={{
            backgroundColor: "#1e293b",
            border: "1px solid #334155",
            borderRadius: "8px",
            fontSize: "12px",
            color: "#e2e8f0",
          }}
          labelFormatter={(_, payload) => payload?.[0]?.payload?.full ?? ""}
        />
        <Area
          type="monotone"
          dataKey="count"
          stroke="#ef4444"
          fill="url(#attackGrad)"
          strokeWidth={2}
          isAnimationActive={false}
          dot={false}
          activeDot={{ r: 4, fill: "#ef4444", stroke: "#fff", strokeWidth: 1.5 }}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}
