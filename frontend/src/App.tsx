import { useOverview, useGeoPins } from "./hooks/useAttempts";
import { useSSE } from "./hooks/useSSE";
import AttackMap from "./components/Map/AttackMap";
import DashboardPanel from "./components/Dashboard/DashboardPanel";
import LiveIndicator from "./components/common/LiveIndicator";

function App() {
  const { data: stats } = useOverview();
  const { data: pins } = useGeoPins();
  const { isConnected, lastEvent } = useSSE("/api/stream/events");

  return (
    <div className="h-screen w-screen flex">
      {/* Map - Left Side */}
      <div className="flex-1 relative">
        <AttackMap pins={pins} lastEvent={lastEvent} />

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

      {/* Dashboard - Right Side */}
      <div className="w-[480px] shrink-0">
        <DashboardPanel stats={stats} />
      </div>
    </div>
  );
}

export default App;
