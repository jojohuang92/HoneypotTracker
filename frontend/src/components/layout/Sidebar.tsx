import { NavLink } from "react-router-dom";
import {
  Activity,
  List,
  Terminal,
  FolderOpen,
  Crosshair,
  LayoutGrid,
  Network,
  Globe,
  Bug,
  UserSearch,
  Search,
  ShieldAlert,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";

interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  end?: boolean;
}

const GROUPS: { label: string; items: NavItem[] }[] = [
  {
    label: "Live",
    items: [{ to: "/", label: "Overview", icon: Activity, end: true }],
  },
  {
    label: "Analyze",
    items: [
      { to: "/attempts", label: "Attempts", icon: List },
      { to: "/commands", label: "Commands", icon: Terminal },
      { to: "/files", label: "Files", icon: FolderOpen },
      { to: "/intents", label: "Intents", icon: Crosshair },
      { to: "/mitre", label: "MITRE", icon: LayoutGrid },
    ],
  },
  {
    label: "Intelligence",
    items: [
      { to: "/ips", label: "IPs", icon: Network },
      { to: "/countries", label: "Countries", icon: Globe },
      { to: "/malware", label: "Malware", icon: Bug },
      { to: "/profile", label: "Profile", icon: UserSearch },
    ],
  },
  {
    label: "Search",
    items: [{ to: "/search", label: "Search", icon: Search }],
  },
];

function linkClasses(isActive: boolean) {
  return `flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-xs font-medium transition-colors whitespace-nowrap ${
    isActive
      ? "bg-blue-600/20 text-blue-300"
      : "text-gray-400 hover:text-white hover:bg-gray-800"
  }`;
}

export default function Sidebar() {
  return (
    <nav className="shrink-0 bg-gray-950 border-gray-800 border-b lg:border-b-0 lg:border-r lg:w-44 lg:flex lg:flex-col">
      {/* Brand (desktop) */}
      <div className="hidden lg:flex items-center gap-2 px-3 pt-4 pb-3">
        <ShieldAlert className="w-5 h-5 text-red-400 shrink-0" />
        <div className="leading-tight">
          <div className="text-sm font-bold text-white tracking-tight">Honeypot</div>
          <div className="text-[10px] text-gray-500 uppercase tracking-widest">Tracker</div>
        </div>
      </div>

      {/* Desktop: grouped vertical nav. Mobile: single horizontal strip. */}
      <div className="flex overflow-x-auto gap-1 p-2 lg:flex-col lg:overflow-x-visible lg:gap-0 lg:p-0 lg:px-2 lg:pb-3 lg:flex-1">
        {GROUPS.map((group) => (
          <div key={group.label} className="flex gap-1 lg:block lg:mt-3 lg:first:mt-0">
            <div className="hidden lg:block px-2.5 pb-1 text-[10px] font-semibold uppercase tracking-wider text-gray-600">
              {group.label}
            </div>
            {group.items.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                className={({ isActive }) => linkClasses(isActive)}
              >
                <item.icon className="w-3.5 h-3.5 shrink-0" aria-hidden />
                {item.label}
              </NavLink>
            ))}
          </div>
        ))}
      </div>
    </nav>
  );
}
