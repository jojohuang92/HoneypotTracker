import { useOverview, useGeoPins, useViewers } from "./hooks/useAttempts";
import { useSSE } from "./hooks/useSSE";
import AttackMap from "./components/Map/AttackMap";
import DashboardPanel from "./components/Dashboard/DashboardPanel";
import LiveIndicator from "./components/common/LiveIndicator";
import { useRef, useState, useEffect, useCallback } from "react";

const MIN_DASH_WIDTH = 320;
const MAX_DASH_WIDTH = 900;
const DEFAULT_DASH_WIDTH = 480;

function App() {
  const { data: stats } = useOverview();
  const { data: pins } = useGeoPins();
  const { data: viewers } = useViewers();
  const { isConnected, lastEvent } = useSSE("/api/stream/events");

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

  return (
    <div className="h-screen w-screen flex overflow-hidden">
      {/* Map - Left Side */}
      <div className="flex-1 relative min-w-0">
        <AttackMap pins={pins} lastEvent={lastEvent} containerWidth={window.innerWidth - dashWidth} />

        {/* Overlay: Live indicator */}
        <div className="absolute top-4 left-4 z-[1000] bg-gray-900/80 backdrop-blur-sm rounded-lg px-3 py-2 border border-gray-700/50">
          <LiveIndicator connected={isConnected} />
        </div>

        {/* Overlay: Quick stats */}
        <div className="absolute bottom-4 left-4 z-[1000] bg-gray-900/80 backdrop-blur-sm rounded-lg px-4 py-2 border border-gray-700/50 flex gap-6">
          <div>
            <div className="text-lg font-bold text-red-400">
              {stats.total_attempts.toLocaleString()}
            </div>
            <div className="text-[10px] text-gray-500 uppercase tracking-wider">Total Attacks</div>
          </div>
          <div>
            <div className="text-lg font-bold text-blue-400">
              {stats.unique_ips.toLocaleString()}
            </div>
            <div className="text-[10px] text-gray-500 uppercase tracking-wider">Unique IPs</div>
          </div>
          <div>
            <div className="text-lg font-bold text-green-400">
              {stats.unique_countries}
            </div>
            <div className="text-[10px] text-gray-500 uppercase tracking-wider">Countries</div>
          </div>
        </div>
      </div>

      {/* Drag handle */}
      <div
        onMouseDown={startDrag}
        className="w-1 shrink-0 bg-gray-700 hover:bg-blue-500 active:bg-blue-400 cursor-col-resize transition-colors z-[1000]"
        title="Drag to resize"
      />

      {/* Dashboard - Right Side */}
      <div style={{ width: dashWidth }} className="shrink-0">
        <DashboardPanel stats={stats} viewers={viewers} />
      </div>
    </div>
  );
}

export default App;
