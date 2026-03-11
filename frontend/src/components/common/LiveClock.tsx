import { useState, useEffect } from "react";

export default function LiveClock() {
  const [time, setTime] = useState(new Date());

  useEffect(() => {
    const id = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(id);
  }, []);

  const timeStr = time.toLocaleTimeString(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });

  const dateStr = time.toLocaleDateString(undefined, {
    weekday: "short",
    month: "short",
    day: "numeric",
  });

  const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;

  return (
    <div className="text-right">
      <div className="text-sm font-mono font-semibold text-gray-200 tabular-nums">{timeStr}</div>
      <div className="text-[10px] text-gray-500">{dateStr} · {tz}</div>
    </div>
  );
}
