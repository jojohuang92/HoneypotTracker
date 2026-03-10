import { useState } from "react";
import type { DashboardTab, OverviewStats } from "../../types";
import TabNavigation from "./TabNavigation";
import OverviewPanel from "./OverviewPanel";
import AllAttemptsTable from "./AllAttemptsTable";
import CountryRankings from "./CountryRankings";
import IntentClassification from "./IntentClassification";
import CommandRankings from "./CommandRankings";
import FilesAccessed from "./FilesAccessed";
import MalwarePanel from "./MalwarePanel";

interface DashboardPanelProps {
  stats: OverviewStats;
}

export default function DashboardPanel({ stats }: DashboardPanelProps) {
  const [activeTab, setActiveTab] = useState<DashboardTab>("overview");

  return (
    <div className="h-full flex flex-col bg-gray-900 border-l border-gray-800">
      {/* Header */}
      <div className="p-3 border-b border-gray-800">
        <h1 className="text-lg font-bold text-white tracking-tight">
          🛡️ Honeypot Tracker
        </h1>
        <p className="text-xs text-gray-500 mt-0.5">
          Real-time attack monitoring & analysis
        </p>
      </div>

      {/* Tabs */}
      <div className="p-2 border-b border-gray-800">
        <TabNavigation activeTab={activeTab} onTabChange={setActiveTab} />
      </div>

      {/* Content */}
      <div className="flex-1 overflow-auto p-3">
        {activeTab === "overview" && <OverviewPanel stats={stats} />}
        {activeTab === "attempts" && <AllAttemptsTable />}
        {activeTab === "countries" && <CountryRankings />}
        {activeTab === "intents" && <IntentClassification />}
        {activeTab === "commands" && <CommandRankings />}
        {activeTab === "files" && <FilesAccessed />}
        {activeTab === "malware" && <MalwarePanel />}
      </div>
    </div>
  );
}
