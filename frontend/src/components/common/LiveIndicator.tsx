interface LiveIndicatorProps {
  connected: boolean;
}

export default function LiveIndicator({ connected }: LiveIndicatorProps) {
  return (
    <div className="flex items-center gap-2">
      <span
        className={`inline-block w-2 h-2 rounded-full ${
          connected ? "bg-green-500 animate-pulse" : "bg-red-500"
        }`}
      />
      <span className="text-xs font-mono text-gray-400">
        {connected ? "LIVE" : "OFFLINE"}
      </span>
    </div>
  );
}
