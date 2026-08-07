/* eslint-disable react-refresh/only-export-components -- context module: constants + hook + provider belong together */
import { createContext, useContext, useEffect, useState } from "react";
import type { ReactNode } from "react";

export interface TimeRange {
  label: string;
  days: number; // 0 = all time
}

export const TIME_RANGES: TimeRange[] = [
  { label: "24h", days: 1 },
  { label: "7d", days: 7 },
  { label: "30d", days: 30 },
  { label: "All", days: 0 },
];

interface TimeRangeValue {
  range: TimeRange;
  setRange: (r: TimeRange) => void;
}

const TimeRangeContext = createContext<TimeRangeValue>({
  range: TIME_RANGES[1],
  setRange: () => {},
});

export function TimeRangeProvider({ children }: { children: ReactNode }) {
  const [range, setRange] = useState<TimeRange>(() => {
    const saved = localStorage.getItem("timeRange");
    return TIME_RANGES.find((r) => r.label === saved) ?? TIME_RANGES[1];
  });

  useEffect(() => {
    localStorage.setItem("timeRange", range.label);
  }, [range]);

  return (
    <TimeRangeContext.Provider value={{ range, setRange }}>
      {children}
    </TimeRangeContext.Provider>
  );
}

export function useTimeRange() {
  return useContext(TimeRangeContext);
}
