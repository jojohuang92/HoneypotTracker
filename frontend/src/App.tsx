import { useOverview, useGeoPins } from "./hooks/useAttempts";
import { useSensorScope } from "./context/SensorContext";
import { useSSE } from "./hooks/useSSE";
import AttackMap from "./components/Map/AttackMap";
import { threatLegend } from "./components/Map/threatScale";
import DashboardPanel from "./components/Dashboard/DashboardPanel";
import Sidebar from "./components/layout/Sidebar";
import LiveIndicator from "./components/common/LiveIndicator";
import { useRef, useState, useEffect, useCallback } from "react";
import type { CSSProperties } from "react";
import { formatNumber } from "./utils/formatters";

const OVERLAY_CARD =
  "bg-gray-950/80 backdrop-blur-md rounded-lg border border-gray-800 shadow-lg shadow-black/20";

const MIN_DASH_WIDTH = 320;
const MAX_DASH_WIDTH = 900;
const DEFAULT_DASH_WIDTH = 480;

function App() {
  // All-time headline numbers for the map overlay, independent of the
  // panel's time-range selector.
  const { sensorId, sensors } = useSensorScope();
  const { data: stats } = useOverview(0, sensorId);
  const { data: pins } = useGeoPins(sensorId);

  const { isConnected, lastEvent } = useSSE("/api/stream/live");

  // Record this page view once on mount
  useEffect(() => {
    fetch("/api/stats/view", { method: "POST" }).catch(() => {});
  }, []);

  const [dashWidth, setDashWidth] = useState(DEFAULT_DASH_WIDTH);
  const dragging = useRef(false);

  const onMouseMove = useCallback((e: MouseEvent) => {
    if (!dragging.current) return;
    const newWidth = window.innerWidth - e.clientX;
    setDashWidth(Math.max(MIN_DASH_WIDTH, Math.min(MAX_DASH_WIDTH, newWidth)));
  }, []);

  const onMouseUp = useCallback(() => {
    dragging.current = false;
    document.body.style.cursor = "";
    document.body.style.userSelect = "";
  }, []);

  useEffect(() => {
    window.addEventListener("mousemove", onMouseMove);
    window.addEventListener("mouseup", onMouseUp);
    return () => {
      window.removeEventListener("mousemove", onMouseMove);
      window.removeEventListener("mouseup", onMouseUp);
    };
  }, [onMouseMove, onMouseUp]);

  const startDrag = () => {
    dragging.current = true;
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";
  };

  // Let Leaflet recompute its size whenever the map pane is resized —
  // covers both the drag handle and viewport/breakpoint changes.
  const mapWrapRef = useRef<HTMLDivElement>(null);
  const [mapWidth, setMapWidth] = useState(0);
  useEffect(() => {
    const el = mapWrapRef.current;
    if (!el) return;
    const ro = new ResizeObserver((entries) => {
      setMapWidth(Math.round(entries[0].contentRect.width));
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  return (
    <div className="h-dvh w-screen flex flex-col lg:flex-row overflow-hidden">
      <Sidebar />

      {/* Map */}
      <div ref={mapWrapRef} className="relative min-w-0 h-[38dvh] shrink-0 lg:h-auto lg:flex-1">
        <AttackMap
          pins={pins}
          lastEvent={lastEvent}
          containerWidth={mapWidth}
          sensors={sensors}
        />

        {/* Overlay: Live indicator */}
        <div className={`absolute top-4 left-4 z-[1000] px-3 py-2 ${OVERLAY_CARD}`}>
          <LiveIndicator connected={isConnected} />
        </div>

        {/* Overlay: threat legend */}
        {pins.length > 0 && (
          <div className={`absolute top-4 right-4 z-[1000] hidden md:block px-3 py-2.5 ${OVERLAY_CARD}`}>
            <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-2">
              Attacks per source
            </div>
            <div className="space-y-1.5">
              {threatLegend(pins).map(({ color, label }) => (
                <div key={color} className="flex items-center gap-2">
                  <span
                    className="w-2.5 h-2.5 rounded-full border border-white/40"
                    style={{ background: color, boxShadow: `0 0 6px ${color}99` }}
                  />
                  <span className="text-[11px] font-mono text-gray-400">{label}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Overlay: All-time quick stats */}
        <div className={`absolute bottom-4 left-4 z-[1000] hidden sm:flex px-4 py-2.5 gap-6 ${OVERLAY_CARD}`}>
          <div>
            <div className="text-lg font-bold tabular-nums text-red-400">
              {formatNumber(stats.total_attempts)}
            </div>
            <div className="text-[10px] text-gray-500 uppercase tracking-wider">Total Attacks</div>
          </div>
          <div>
            <div className="text-lg font-bold tabular-nums text-blue-400">
              {formatNumber(stats.unique_ips)}
            </div>
            <div className="text-[10px] text-gray-500 uppercase tracking-wider">Unique IPs</div>
          </div>
          <div>
            <div className="text-lg font-bold tabular-nums text-green-400">
              {stats.unique_countries}
            </div>
            <div className="text-[10px] text-gray-500 uppercase tracking-wider">Countries</div>
          </div>
        </div>
      </div>

      {/* Drag handle (desktop only) */}
      <div
        onMouseDown={startDrag}
        className="hidden lg:block w-1 shrink-0 bg-gray-700 hover:bg-blue-500 active:bg-blue-400 cursor-col-resize transition-colors z-[1000]"
        title="Drag to resize"
      />

      {/* Dashboard panel: fills the rest on mobile, fixed width on desktop */}
      <div
        style={{ "--dash-w": `${dashWidth}px` } as CSSProperties}
        className="flex-1 min-h-0 w-full lg:flex-none lg:w-[var(--dash-w)]"
      >
        <DashboardPanel lastEvent={lastEvent} />
      </div>
    </div>
  );
}

export default App;
