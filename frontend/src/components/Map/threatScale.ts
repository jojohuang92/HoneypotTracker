import type { GeoPin } from "../../types";

// Threat grading shared by pins, popups, and the map legend. Attack counts
// per source span orders of magnitude and grow without bound, so fixed
// thresholds go stale — grade by quantile of the current pin set instead.
export const GRADE_STYLES = [
  { color: "#3b82f6", size: 11 },
  { color: "#eab308", size: 13 },
  { color: "#f97316", size: 15 },
  { color: "#ef4444", size: 18 },
];

export type ThreatScale = [number, number, number];

export function computeThreatScale(pins: GeoPin[]): ThreatScale {
  const counts = pins.map((p) => p.count).sort((a, b) => a - b);
  const q = (p: number) =>
    counts.length ? counts[Math.min(counts.length - 1, Math.floor(counts.length * p))] : 0;
  return [q(0.5), q(0.75), q(0.9)];
}

export function gradeFor(count: number, scale: ThreatScale) {
  const level = scale.filter((t) => count >= t && t > 0).length;
  return GRADE_STYLES[level];
}

export function compactCount(n: number) {
  return n >= 10000
    ? `${Math.round(n / 1000)}k`
    : n >= 1000
      ? `${(n / 1000).toFixed(1)}k`
      : `${n}`;
}

export function threatLegend(pins: GeoPin[]) {
  const [t0, t1, t2] = computeThreatScale(pins);
  const labels = [
    `< ${compactCount(t0)}`,
    `${compactCount(t0)}–${compactCount(t1)}`,
    `${compactCount(t1)}–${compactCount(t2)}`,
    `≥ ${compactCount(t2)}`,
  ];
  return GRADE_STYLES.map(({ color }, i) => ({ color, label: labels[i] }));
}
