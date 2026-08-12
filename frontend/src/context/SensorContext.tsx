/* eslint-disable react-refresh/only-export-components -- context module: hook + provider belong together */
import { createContext, useContext, useEffect, useState } from "react";
import type { ReactNode } from "react";
import { useSensors } from "../hooks/useAttempts";
import type { Sensor } from "../types";

interface SensorScopeValue {
  /** Selected sensor id, or null for the whole fleet. */
  sensorId: string | null;
  setSensorId: (id: string | null) => void;
  sensors: Sensor[];
  /** The scope selector is pointless until a second sensor exists. */
  isFleet: boolean;
}

const SensorContext = createContext<SensorScopeValue>({
  sensorId: null,
  setSensorId: () => {},
  sensors: [],
  isFleet: false,
});

export function SensorProvider({ children }: { children: ReactNode }) {
  const { data: sensors } = useSensors();
  const [selected, setSelected] = useState<string | null>(
    () => localStorage.getItem("sensorScope") || null
  );

  useEffect(() => {
    if (selected) localStorage.setItem("sensorScope", selected);
    else localStorage.removeItem("sensorScope");
  }, [selected]);

  // A stored scope naming a sensor that no longer exists would silently filter
  // everything away. Resolve that here rather than writing state in an effect,
  // so the fleet view is never briefly empty.
  const known = sensors.length === 0 || sensors.some((s) => s.sensor_id === selected);
  const sensorId = known ? selected : null;

  return (
    <SensorContext.Provider
      value={{ sensorId, setSensorId: setSelected, sensors, isFleet: sensors.length > 1 }}
    >
      {children}
    </SensorContext.Provider>
  );
}

export function useSensorScope() {
  return useContext(SensorContext);
}
