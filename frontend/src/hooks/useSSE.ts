import { useEffect, useRef, useState } from "react";
import type { Attempt } from "../types";

export function useSSE(url: string) {
  const [isConnected, setIsConnected] = useState(false);
  const [lastEvent, setLastEvent] = useState<Attempt | null>(null);
  const esRef = useRef<EventSource | null>(null);

  useEffect(() => {
    const es = new EventSource(url);
    esRef.current = es;

    es.onopen = () => setIsConnected(true);

    es.addEventListener("new_attack", (e) => {
      try {
        setLastEvent(JSON.parse(e.data));
      } catch {
        // ignore parse errors
      }
    });

    es.onerror = () => {
      setIsConnected(false);
    };

    return () => {
      es.close();
      esRef.current = null;
    };
  }, [url]);

  return { isConnected, lastEvent };
}
