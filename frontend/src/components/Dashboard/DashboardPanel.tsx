import { useState } from "react";
import type { Attempt, DashboardTab, OverviewStats } from "../../types";

import TabNavigation from "./TabNavigation";
import OverviewPanel from "./OverviewPanel";
import AllAttemptsTable from "./AllAttemptsTable";
import CountryRankings from "./CountryRankings";
import IntentClassification from "./IntentClassification";
import CommandRankings from "./CommandRankings";
import FilesAccessed from "./FilesAccessed";
import MalwarePanel from "./MalwarePanel";
import IPAddresses from "./IPAddresses";
import SearchPanel from "./SearchPanel";
import AttackerProfilePanel from "./AttackerProfilePanel";
import LiveClock from "../common/LiveClock";

interface DashboardPanelProps {
  stats: OverviewStats;
  lastEvent: Attempt | null;
}

export default function DashboardPanel({ stats, lastEvent }: DashboardPanelProps) {
  const [activeTab, setActiveTab] = useState<DashboardTab>("overview");
  const [profileIp, setProfileIp] = useState<string | undefined>();

  const navigateToProfile = (ip: string) => {
    setProfileIp(ip);
    setActiveTab("profile");
  };

  return (
    <div className="h-full flex flex-col bg-gray-900 border-l border-gray-800 relative">
      {/* Header */}
      <div className="p-3 border-b border-gray-800 flex items-center justify-between">
        <div>
          <h1 className="text-lg font-bold text-white tracking-tight">
            🛡️ Honeypot Tracker
          </h1>
          <p className="text-xs text-gray-500 mt-0.5">
            Real-time attack monitoring & analysis
          </p>
        </div>
        <div className="text-right">
          <LiveClock />
          {/* <div className="flex gap-3 justify-end mt-1">
            <span className="text-[10px] text-gray-500">
              <span className="text-gray-400">{viewers.unique_visitors.toLocaleString()}</span> total visitors
            </span>
            <span className="text-[10px] text-gray-500">
              <span className="text-gray-400">{viewers.views_today.toLocaleString()}</span> today
            </span>
          </div> */}
        </div>
      </div>

      {/* Tabs */}
      <div className="p-2 border-b border-gray-800">
        <TabNavigation activeTab={activeTab} onTabChange={setActiveTab} />
      </div>

      {/* Content */}
      <div className="flex-1 overflow-auto p-3">
        {activeTab === "overview" && <OverviewPanel stats={stats} lastEvent={lastEvent} />}
        {activeTab === "attempts" && <AllAttemptsTable />}
        {activeTab === "countries" && <CountryRankings />}
        {activeTab === "intents" && <IntentClassification />}
        {activeTab === "commands" && <CommandRankings />}
        {activeTab === "files" && <FilesAccessed />}
        {activeTab === "malware" && <MalwarePanel />}
        {activeTab === "search" && <SearchPanel onNavigateToProfile={navigateToProfile} />}
        {activeTab === "profile" && <AttackerProfilePanel initialIp={profileIp} />}
        {activeTab === "ips" && <IPAddresses />}
      </div>
    </div>
  );
}
