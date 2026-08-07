import { useState } from "react";

const RANGES = [7, 30, 90] as const;

const FORMATS = [
  { label: "Blocklist (.txt)", path: "/api/export/blocklist.txt", desc: "firewall / fail2ban" },
  { label: "CSV", path: "/api/export/iocs.csv", desc: "SIEM / spreadsheet" },
  { label: "STIX 2.1", path: "/api/export/stix.json", desc: "threat-intel platforms" },
] as const;

export default function ExportPanel() {
  const [days, setDays] = useState<number>(30);

  return (
    <div>
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-sm font-semibold text-gray-300">Export IOCs</h3>
        <div className="flex gap-1">
          {RANGES.map((d) => (
            <button
              key={d}
              onClick={() => setDays(d)}
              className={`px-2 py-0.5 text-xs rounded ${
                days === d
                  ? "bg-cyan-600 text-white"
                  : "bg-gray-800 text-gray-400 hover:bg-gray-700"
              }`}
            >
              {d}d
            </button>
          ))}
        </div>
      </div>
      <div className="bg-gray-800/50 rounded-lg border border-gray-700/50 p-2 flex gap-2">
        {FORMATS.map((f) => (
          <a
            key={f.path}
            href={`${f.path}?days=${days}`}
            download
            className="flex-1 text-center px-2 py-2 rounded bg-gray-800 hover:bg-gray-700 border border-gray-700"
          >
            <div className="text-xs font-medium text-cyan-400">{f.label}</div>
            <div className="text-[10px] text-gray-500">{f.desc}</div>
          </a>
        ))}
      </div>
    </div>
  );
}
