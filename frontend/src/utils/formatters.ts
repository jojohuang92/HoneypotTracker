export function formatTimestamp(ts: string): string {
  // Append Z if no timezone info so the browser treats it as UTC
  const utc = ts.endsWith("Z") || ts.includes("+") ? ts : ts + "Z";
  return new Date(utc).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function maskIP(ip: string): string {
  const parts = ip.split(".");
  if (parts.length === 4) {
    return `${parts[0]}.${parts[1]}.${parts[2]}.***`;
  }
  return ip;
}

export function intentColor(intent: string | null): string {
  const colors: Record<string, string> = {
    brute_force: "#f97316",
    reconnaissance: "#3b82f6",
    malware_deployment: "#ef4444",
    persistence: "#a855f7",
    cryptomining: "#eab308",
    credential_theft: "#ec4899",
    sabotage: "#dc2626",
    lateral_movement: "#8b5cf6",
    scanning: "#06b6d4",
    data_exfiltration: "#f43f5e",
  };
  return colors[intent || ""] || "#6b7280";
}

export function intentLabel(intent: string): string {
  return intent
    .split("_")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}

export function formatNumber(n: number): string {
  return n.toLocaleString("en-US");
}
