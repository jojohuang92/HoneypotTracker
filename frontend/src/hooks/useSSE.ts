import { useEffect, useRef, useState } from "react";
import type { LiveAttackEvent } from "../types";

export function useSSE(url: string) {
  const [isConnected, setIsConnected] = useState(false);
  const [lastEvent, setLastEvent] = useState<LiveAttackEvent | null>(null);
  const esRef = useRef<EventSource | null>(null);

  useEffect(() => {
    let disposed = false;
    let retryTimer: number | undefined;
    let attempts = 0;

    const connect = () => {
      if (disposed) return;
      const es = new EventSource(url);
      esRef.current = es;

      es.onopen = () => {
        attempts = 0;
        setIsConnected(true);
      };

      es.addEventListener("new_attack", (e) => {
        try {
          setLastEvent(JSON.parse(e.data));
        } catch {
          // ignore parse errors
        }
      });

      es.onerror = () => {
        setIsConnected(false);
        // The browser only auto-retries transient drops. On a permanent
        // failure (e.g. an HTTP error response) the EventSource closes for
        // good, so reopen it ourselves with exponential backoff.
        if (es.readyState === EventSource.CLOSED) {
          es.close();
          esRef.current = null;
          attempts += 1;
          const delay = Math.min(30_000, 1000 * 2 ** attempts);
          retryTimer = window.setTimeout(connect, delay);
        }
      };
    };

    connect();

    return () => {
      disposed = true;
      window.clearTimeout(retryTimer);
      esRef.current?.close();
      esRef.current = null;
    };
  }, [url]);

  return { isConnected, lastEvent };
}
