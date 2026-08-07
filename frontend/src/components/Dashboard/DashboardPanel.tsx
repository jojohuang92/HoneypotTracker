import { Routes, Route, Navigate, useLocation, useParams } from "react-router-dom";
import type { LiveAttackEvent } from "../../types";
import { TIME_RANGES, useTimeRange } from "../../context/TimeRangeContext";

import OverviewPanel from "./OverviewPanel";
import AllAttemptsTable from "./AllAttemptsTable";
import CountryRankings from "./CountryRankings";
import IntentClassification from "./IntentClassification";
import MitreMatrix from "./MitreMatrix";
import CommandRankings from "./CommandRankings";
import FilesAccessed from "./FilesAccessed";
import MalwarePanel from "./MalwarePanel";
import IPAddresses from "./IPAddresses";
import SearchPanel from "./SearchPanel";
import AttackerProfilePanel from "./AttackerProfilePanel";
import SessionReplayPanel from "./SessionReplayPanel";
import LiveClock from "../common/LiveClock";

const SECTION_TITLES: [string, string][] = [
  ["/attempts", "Attempts"],
  ["/commands", "Commands"],
  ["/files", "Files Accessed"],
  ["/intents", "Intent Classification"],
  ["/mitre", "MITRE ATT&CK"],
  ["/ips", "Attacker IPs"],
  ["/countries", "Countries"],
  ["/malware", "Captured Malware"],
  ["/profile", "Attacker Profile"],
  ["/replay", "Session Replay"],
  ["/search", "Search"],
];

function sectionTitle(pathname: string): string {
  const match = SECTION_TITLES.find(([prefix]) => pathname.startsWith(prefix));
  return match ? match[1] : "Overview";
}

// Key detail panels by their URL param so all their state (input, playback
// position, fetched data) resets when the subject changes.
function ProfileRoute() {
  const { ip } = useParams();
  return <AttackerProfilePanel key={ip ?? "manual"} />;
}

function ReplayRoute() {
  const { sessionId } = useParams();
  return <SessionReplayPanel key={sessionId} />;
}

// The time-range selector scopes aggregate views; detail views
// (profile, replay, search) always show everything for their subject.
const RANGED_PATHS = ["/", "/attempts", "/commands", "/files", "/intents", "/mitre", "/countries"];

interface DashboardPanelProps {
  lastEvent: LiveAttackEvent | null;
}

export default function DashboardPanel({ lastEvent }: DashboardPanelProps) {
  const { range, setRange } = useTimeRange();
  const { pathname } = useLocation();
  const showRange =
    pathname === "/" || RANGED_PATHS.some((p) => p !== "/" && pathname.startsWith(p));

  return (
    <div className="h-full flex flex-col bg-gray-900 border-l border-gray-800">
      {/* Header */}
      <div className="px-3 py-2 border-b border-gray-800 flex items-center justify-between gap-2 min-h-[46px]">
        <h1 className="text-sm font-semibold text-white tracking-tight truncate">
          {sectionTitle(pathname)}
        </h1>
        <div className="flex items-center gap-3 shrink-0">
          {showRange && (
            <div
              className="flex gap-0.5 bg-gray-800/60 rounded-md p-0.5"
              role="group"
              aria-label="Time range"
            >
              {TIME_RANGES.map((r) => (
                <button
                  key={r.label}
                  onClick={() => setRange(r)}
                  className={`px-2 py-0.5 rounded text-xs font-medium transition-colors ${
                    r.label === range.label
                      ? "bg-blue-600 text-white"
                      : "text-gray-400 hover:text-white hover:bg-gray-700"
                  }`}
                >
                  {r.label}
                </button>
              ))}
            </div>
          )}
          <div className="hidden sm:block">
            <LiveClock />
          </div>
        </div>
      </div>

      {/* Routed content */}
      <div className="flex-1 overflow-auto p-3 min-h-0">
        <Routes>
          <Route path="/" element={<OverviewPanel lastEvent={lastEvent} />} />
          <Route path="/attempts" element={<AllAttemptsTable />} />
          <Route path="/commands" element={<CommandRankings />} />
          <Route path="/files" element={<FilesAccessed />} />
          <Route path="/intents" element={<IntentClassification />} />
          <Route path="/mitre" element={<MitreMatrix />} />
          <Route path="/ips" element={<IPAddresses />} />
          <Route path="/countries" element={<CountryRankings />} />
          <Route path="/malware" element={<MalwarePanel />} />
          <Route path="/profile/:ip?" element={<ProfileRoute />} />
          <Route path="/replay/:sessionId" element={<ReplayRoute />} />
          <Route path="/search" element={<SearchPanel />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </div>
    </div>
  );
}
