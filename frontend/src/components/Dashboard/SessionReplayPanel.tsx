import { useState, useEffect, useRef } from "react";
import { useSessionReplay } from "../../hooks/useAttempts";
import { formatTimestamp, intentColor, intentLabel } from "../../utils/formatters";

interface Props {
  sessionId: string;
  onBack: () => void;
}

export default function SessionReplayPanel({ sessionId, onBack }: Props) {
  const { data: events, loading } = useSessionReplay(sessionId);
  const [visibleCount, setVisibleCount] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);
  const scrollRef = useRef<HTMLDivElement>(null);
  const timerRef = useRef<ReturnType<typeof setTimeout>>();

  // Reset when session changes
  useEffect(() => {
    setVisibleCount(0);
    setPlaying(false);
  }, [sessionId]);

  // Auto-scroll to bottom
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [visibleCount]);

  // Replay timer
  useEffect(() => {
    if (!playing || visibleCount >= events.length) {
      setPlaying(false);
      return;
    }

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
  }, [playing, visibleCount, events, speed]);

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
      <div className="p-2 border-b border-gray-700 flex items-center gap-2">
        <button
          onClick={onBack}
          className="text-xs text-gray-400 hover:text-white transition-colors"
        >
          ← Back
        </button>
        <span className="text-xs text-gray-500">|</span>
        <span className="text-xs font-mono text-blue-400">{sessionId.slice(0, 16)}</span>
        <span className="text-xs text-gray-500">
          {events.length} events
        </span>
      </div>

      {/* Controls */}
      <div className="p-2 border-b border-gray-700 flex items-center gap-2">
        {!playing ? (
          <button
            onClick={play}
            disabled={loading || events.length === 0}
            className="px-2 py-1 text-xs rounded bg-green-600 text-white hover:bg-green-500 disabled:opacity-50"
          >
            ▶ Play
          </button>
        ) : (
          <button
            onClick={() => setPlaying(false)}
            className="px-2 py-1 text-xs rounded bg-yellow-600 text-white hover:bg-yellow-500"
          >
            ⏸ Pause
          </button>
        )}
        <button
          onClick={reset}
          className="px-2 py-1 text-xs rounded bg-gray-700 text-gray-300 hover:bg-gray-600"
        >
          ⏮ Reset
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
          className="text-xs bg-gray-800 border border-gray-600 rounded px-2 py-1 text-gray-300"
        >
          <option value={0.5}>0.5×</option>
          <option value={1}>1×</option>
          <option value={2}>2×</option>
          <option value={5}>5×</option>
          <option value={10}>10×</option>
        </select>
        <span className="text-[10px] text-gray-500 ml-auto">
          {visibleCount}/{events.length}
        </span>
      </div>

      {/* Terminal */}
      <div
        ref={scrollRef}
        className="flex-1 overflow-auto bg-black/40 font-mono text-xs p-3 space-y-0.5"
      >
        {loading && (
          <div className="text-gray-500 text-center py-8">Loading session...</div>
        )}

        {!loading && events.length === 0 && (
          <div className="text-gray-500 text-center py-8">No events in this session</div>
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
        {playing && (
          <div className="flex gap-2 py-0.5">
            <span className="text-green-400 animate-pulse">▊</span>
          </div>
        )}
      </div>
    </div>
  );
}
