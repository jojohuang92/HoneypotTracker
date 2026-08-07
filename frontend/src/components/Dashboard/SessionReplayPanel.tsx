import { useState, useEffect, useRef } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { ArrowLeft, Play, Pause, RotateCcw, TerminalSquare } from "lucide-react";
import { useSessionReplay } from "../../hooks/useAttempts";
import { formatTimestamp, intentColor, intentLabel } from "../../utils/formatters";
import Skeleton from "../common/Skeleton";
import EmptyState from "../common/EmptyState";

/** Keystroke-timed replay of one attacker session (/replay/:sessionId).
 *  Delays between lines follow the real event timestamps, asciinema-style. */
export default function SessionReplayPanel() {
  const { sessionId = "" } = useParams<{ sessionId: string }>();
  const navigate = useNavigate();
  const { data: events, loading } = useSessionReplay(sessionId);
  const [visibleCount, setVisibleCount] = useState(0);
  // Starts true so a fresh deep link plays on its own once events arrive
  const [playing, setPlaying] = useState(true);
  const [speed, setSpeed] = useState(1);
  const scrollRef = useRef<HTMLDivElement>(null);
  const timerRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  // Derived: only actually playing while there are more events to show.
  const isPlaying = playing && visibleCount < events.length;

  // Auto-scroll to bottom
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [visibleCount]);

  // Replay timer
  useEffect(() => {
    if (!isPlaying) return;

    const currentEvent = events[visibleCount];
    const nextEvent = events[visibleCount + 1];

    let delay = 800; // default delay
    if (nextEvent && currentEvent) {
      const curr = new Date(currentEvent.timestamp).getTime();
      const next = new Date(nextEvent.timestamp).getTime();
      delay = Math.min(Math.max((next - curr) / speed, 100), 3000);
    }

    timerRef.current = setTimeout(() => {
      setVisibleCount((c) => c + 1);
    }, delay);

    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [isPlaying, visibleCount, events, speed]);

  const play = () => {
    if (visibleCount >= events.length) setVisibleCount(0);
    setPlaying(true);
  };

  const showAll = () => {
    setPlaying(false);
    setVisibleCount(events.length);
  };

  const reset = () => {
    setPlaying(false);
    setVisibleCount(0);
  };

  const visible = events.slice(0, visibleCount);

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="pb-2 border-b border-gray-700 flex items-center gap-2">
        <button
          onClick={() => (window.history.length > 1 ? navigate(-1) : navigate("/"))}
          className="flex items-center gap-1 text-xs text-gray-400 hover:text-white transition-colors"
        >
          <ArrowLeft className="w-3 h-3" aria-hidden />
          Back
        </button>
        <span className="text-xs text-gray-500">|</span>
        <span className="text-xs font-mono text-blue-400">{sessionId.slice(0, 16)}</span>
        <span className="text-xs text-gray-500">{events.length} events</span>
      </div>

      {/* Controls */}
      <div className="py-2 border-b border-gray-700 flex items-center gap-2">
        {!isPlaying ? (
          <button
            onClick={play}
            disabled={loading || events.length === 0}
            className="flex items-center gap-1 px-2 py-1 text-xs rounded bg-green-600 text-white hover:bg-green-500 disabled:opacity-50"
          >
            <Play className="w-3 h-3" aria-hidden /> Play
          </button>
        ) : (
          <button
            onClick={() => setPlaying(false)}
            className="flex items-center gap-1 px-2 py-1 text-xs rounded bg-yellow-600 text-white hover:bg-yellow-500"
          >
            <Pause className="w-3 h-3" aria-hidden /> Pause
          </button>
        )}
        <button
          onClick={reset}
          className="flex items-center gap-1 px-2 py-1 text-xs rounded bg-gray-700 text-gray-300 hover:bg-gray-600"
        >
          <RotateCcw className="w-3 h-3" aria-hidden /> Reset
        </button>
        <button
          onClick={showAll}
          className="px-2 py-1 text-xs rounded bg-gray-700 text-gray-300 hover:bg-gray-600"
        >
          Show All
        </button>
        <select
          value={speed}
          onChange={(e) => setSpeed(Number(e.target.value))}
          aria-label="Playback speed"
          className="text-xs bg-gray-800 border border-gray-600 rounded px-2 py-1 text-gray-300"
        >
          <option value={0.5}>0.5×</option>
          <option value={1}>1×</option>
          <option value={2}>2×</option>
          <option value={5}>5×</option>
          <option value={10}>10×</option>
        </select>
        <span className="text-[10px] text-gray-500 ml-auto font-mono">
          {visibleCount}/{events.length}
        </span>
      </div>

      {/* Terminal window */}
      <div className="flex-1 flex flex-col min-h-0 mt-3 rounded-lg border border-gray-700 overflow-hidden bg-[#0a0e14]">
        {/* Title bar */}
        <div className="flex items-center gap-2 px-3 py-1.5 bg-gray-800/80 border-b border-gray-700 shrink-0">
          <span className="flex gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-red-500/80" />
            <span className="w-2.5 h-2.5 rounded-full bg-yellow-500/80" />
            <span className="w-2.5 h-2.5 rounded-full bg-green-500/80" />
          </span>
          <span className="text-[10px] font-mono text-gray-400 truncate">
            ssh — {sessionId}
          </span>
        </div>

        <div ref={scrollRef} className="flex-1 overflow-auto font-mono text-xs p-3 space-y-0.5">
          {loading && <Skeleton rows={6} />}

          {!loading && events.length === 0 && (
            <EmptyState
              icon={TerminalSquare}
              title="No events in this session"
              hint="The session may have been pruned by retention, or the ID is incomplete."
            />
          )}

          {visible.map((event, i) => {
            const time = formatTimestamp(event.timestamp);
            const eventType = event.event_id.replace("cowrie.", "");

            if (event.event_id.includes("login")) {
              return (
                <div key={i} className="flex gap-2 py-0.5">
                  <span className="text-gray-600 shrink-0">{time}</span>
                  <span className={event.success ? "text-green-400" : "text-red-400"}>
                    {event.success ? "✓" : "✗"} LOGIN
                  </span>
                  <span className="text-cyan-400">{event.username}</span>
                  <span className="text-gray-600">:</span>
                  <span className="text-orange-400">{event.password}</span>
                </div>
              );
            }

            if (event.event_id === "cowrie.command.input") {
              return (
                <div key={i} className="py-0.5">
                  <div className="flex gap-2">
                    <span className="text-gray-600 shrink-0">{time}</span>
                    <span className="text-green-400">$</span>
                    <span className="text-green-300">{event.command}</span>
                  </div>
                  {event.intent && event.intent !== "unknown" && (
                    <div className="ml-[calc(0.5rem+8ch)] mt-0.5">
                      <span
                        className="inline-block px-1 py-0.5 rounded text-[9px] font-medium"
                        style={{
                          backgroundColor: intentColor(event.intent) + "15",
                          color: intentColor(event.intent),
                        }}
                      >
                        {intentLabel(event.intent)} ({event.mitre_id})
                      </span>
                    </div>
                  )}
                </div>
              );
            }

            if (event.event_id.includes("file_download") || event.event_id.includes("file_upload")) {
              return (
                <div key={i} className="flex gap-2 py-0.5">
                  <span className="text-gray-600 shrink-0">{time}</span>
                  <span className="text-yellow-400">⬇ FILE</span>
                  <span className="text-yellow-300 truncate">{event.command}</span>
                </div>
              );
            }

            return (
              <div key={i} className="flex gap-2 py-0.5">
                <span className="text-gray-600 shrink-0">{time}</span>
                <span className="text-gray-400">{eventType}</span>
              </div>
            );
          })}

          {/* Cursor blink when playing */}
          {isPlaying && (
            <div className="flex gap-2 py-0.5">
              <span className="text-green-400 animate-pulse">▊</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
