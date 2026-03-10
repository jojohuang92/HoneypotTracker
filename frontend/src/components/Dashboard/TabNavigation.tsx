import type { DashboardTab } from "../../types";

const TABS: { id: DashboardTab; label: string; icon: string }[] = [
  { id: "overview", label: "Overview", icon: "\u{1F4CA}" },
  { id: "attempts", label: "Attempts", icon: "\u{1F4CB}" },
  { id: "countries", label: "Countries", icon: "\u{1F30D}" },
  { id: "intents", label: "Intents", icon: "\u{1F3AF}" },
  { id: "commands", label: "Commands", icon: "\u{1F4BB}" },
  { id: "files", label: "Files", icon: "\u{1F4C1}" },
  { id: "malware", label: "Malware", icon: "\u{1F41B}" },
];

interface TabNavigationProps {
  activeTab: DashboardTab;
  onTabChange: (tab: DashboardTab) => void;
}

export default function TabNavigation({ activeTab, onTabChange }: TabNavigationProps) {
  return (
    <div className="flex gap-1 p-1 bg-gray-800/50 rounded-lg overflow-x-auto">
      {TABS.map((tab) => (
        <button
          key={tab.id}
          onClick={() => onTabChange(tab.id)}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-all whitespace-nowrap ${
            activeTab === tab.id
              ? "bg-blue-600 text-white shadow-md"
              : "text-gray-400 hover:text-white hover:bg-gray-700/50"
          }`}
        >
          <span>{tab.icon}</span>
          {tab.label}
        </button>
      ))}
    </div>
  );
}
