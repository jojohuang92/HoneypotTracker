import { useState, useRef, useEffect } from "react";
import type { FilterOptions, AttemptFilters } from "../../hooks/useAttempts";
import { intentLabel, intentColor } from "../../utils/formatters";

type FilterTab = "country" | "event" | "intent";

interface AttemptsFilterProps {
  options: FilterOptions;
  filters: AttemptFilters;
  onChange: (filters: AttemptFilters) => void;
  onClose: () => void;
}

export default function AttemptsFilter({
  options,
  filters,
  onChange,
  onClose,
}: AttemptsFilterProps) {
  const [tab, setTab] = useState<FilterTab>("country");
  const [search, setSearch] = useState("");
  const panelRef = useRef<HTMLDivElement>(null);

  // Close on click outside
  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (panelRef.current && !panelRef.current.contains(e.target as Node)) {
        onClose();
      }
    }
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, [onClose]);

  const activeCount =
    (filters.countries?.length || 0) +
    (filters.events?.length || 0) +
    (filters.intents?.length || 0);

  function toggleValue(
    key: keyof AttemptFilters,
    value: string,
  ) {
    const current = filters[key] || [];
    const next = current.includes(value)
      ? current.filter((v) => v !== value)
      : [...current, value];
    onChange({ ...filters, [key]: next.length ? next : undefined });
  }

  function reset() {
    onChange({});
  }

  const tabs: { key: FilterTab; label: string; count: number }[] = [
    { key: "country", label: "Location", count: filters.countries?.length || 0 },
    { key: "event", label: "Event", count: filters.events?.length || 0 },
    { key: "intent", label: "Intent", count: filters.intents?.length || 0 },
  ];

  const lowerSearch = search.toLowerCase();

  return (
    <div
      ref={panelRef}
      className="absolute top-0 left-0 right-0 bottom-0 z-30 bg-gray-900 border border-gray-700 rounded-lg flex flex-col shadow-2xl"
    >
      {/* Header */}
      <div className="flex items-center justify-between p-2 border-b border-gray-700">
        <div className="flex items-center gap-2">
          <span className="text-sm font-semibold text-gray-200">Filters</span>
          {activeCount > 0 && (
            <span className="text-[10px] bg-blue-600 text-white px-1.5 py-0.5 rounded-full">
              {activeCount}
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          {activeCount > 0 && (
            <button
              onClick={reset}
              className="text-[10px] text-red-400 hover:text-red-300 px-2 py-1 rounded hover:bg-gray-800 transition-colors"
            >
              Reset All
            </button>
          )}
          <button
            onClick={onClose}
            className="text-gray-500 hover:text-gray-300 p-1 rounded hover:bg-gray-800 transition-colors"
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M18 6L6 18M6 6l12 12" />
            </svg>
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-gray-700">
        {tabs.map((t) => (
          <button
            key={t.key}
            onClick={() => { setTab(t.key); setSearch(""); }}
            className={`flex-1 px-2 py-1.5 text-xs font-medium transition-colors ${
              tab === t.key
                ? "text-blue-400 border-b-2 border-blue-400 bg-gray-800/50"
                : "text-gray-500 hover:text-gray-300"
            }`}
          >
            {t.label}
            {t.count > 0 && (
              <span className="ml-1 text-[9px] bg-blue-600/30 text-blue-400 px-1 rounded">
                {t.count}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Search */}
      <div className="p-2 border-b border-gray-800">
        <input
          type="text"
          placeholder="Search..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="w-full px-2 py-1 text-xs bg-gray-800 border border-gray-700 rounded text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500"
        />
      </div>

      {/* Options list */}
      <div className="flex-1 overflow-auto p-1">
        {tab === "country" && (
          <CountryList
            countries={options.countries}
            selected={filters.countries || []}
            search={lowerSearch}
            onToggle={(code) => toggleValue("countries", code)}
          />
        )}
        {tab === "event" && (
          <CheckboxList
            items={options.events
              .filter((e) => e.toLowerCase().includes(lowerSearch))
              .map((e) => ({ value: e, label: e.replace("cowrie.", "") }))}
            selected={filters.events || []}
            onToggle={(val) => toggleValue("events", val)}
          />
        )}
        {tab === "intent" && (
          <IntentList
            intents={options.intents}
            selected={filters.intents || []}
            search={lowerSearch}
            onToggle={(val) => toggleValue("intents", val)}
          />
        )}
      </div>
    </div>
  );
}

function CountryList({
  countries,
  selected,
  search,
  onToggle,
}: {
  countries: { code: string; name: string }[];
  selected: string[];
  search: string;
  onToggle: (code: string) => void;
}) {
  const filtered = countries.filter(
    (c) =>
      c.name.toLowerCase().includes(search) ||
      c.code.toLowerCase().includes(search),
  );

  return (
    <div className="space-y-0.5">
      {filtered.map((c) => (
        <label
          key={c.code}
          className="flex items-center gap-2 px-2 py-1 rounded hover:bg-gray-800/60 cursor-pointer"
        >
          <input
            type="checkbox"
            checked={selected.includes(c.code)}
            onChange={() => onToggle(c.code)}
            className="rounded border-gray-600 bg-gray-800 text-blue-500 focus:ring-0 focus:ring-offset-0 h-3 w-3"
          />
          <span className="text-xs text-gray-300">
            {c.name}
          </span>
          <span className="text-[10px] text-gray-500">{c.code}</span>
        </label>
      ))}
      {filtered.length === 0 && (
        <p className="text-xs text-gray-500 text-center py-4">No matches</p>
      )}
    </div>
  );
}

function IntentList({
  intents,
  selected,
  search,
  onToggle,
}: {
  intents: string[];
  selected: string[];
  search: string;
  onToggle: (val: string) => void;
}) {
  const filtered = intents.filter((i) =>
    intentLabel(i).toLowerCase().includes(search) || i.toLowerCase().includes(search),
  );

  return (
    <div className="space-y-0.5">
      {filtered.map((i) => (
        <label
          key={i}
          className="flex items-center gap-2 px-2 py-1 rounded hover:bg-gray-800/60 cursor-pointer"
        >
          <input
            type="checkbox"
            checked={selected.includes(i)}
            onChange={() => onToggle(i)}
            className="rounded border-gray-600 bg-gray-800 text-blue-500 focus:ring-0 focus:ring-offset-0 h-3 w-3"
          />
          <span
            className="inline-block px-1.5 py-0.5 rounded text-[10px] font-medium"
            style={{
              backgroundColor: intentColor(i) + "20",
              color: intentColor(i),
            }}
          >
            {intentLabel(i)}
          </span>
        </label>
      ))}
      {filtered.length === 0 && (
        <p className="text-xs text-gray-500 text-center py-4">No matches</p>
      )}
    </div>
  );
}

function CheckboxList({
  items,
  selected,
  onToggle,
}: {
  items: { value: string; label: string }[];
  selected: string[];
  onToggle: (val: string) => void;
}) {
  return (
    <div className="space-y-0.5">
      {items.map((item) => (
        <label
          key={item.value}
          className="flex items-center gap-2 px-2 py-1 rounded hover:bg-gray-800/60 cursor-pointer"
        >
          <input
            type="checkbox"
            checked={selected.includes(item.value)}
            onChange={() => onToggle(item.value)}
            className="rounded border-gray-600 bg-gray-800 text-blue-500 focus:ring-0 focus:ring-offset-0 h-3 w-3"
          />
          <span className="text-xs text-gray-300 font-mono">{item.label}</span>
        </label>
      ))}
      {items.length === 0 && (
        <p className="text-xs text-gray-500 text-center py-4">No matches</p>
      )}
    </div>
  );
}
