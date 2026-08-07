import { Link } from "react-router-dom";
import type { LucideIcon } from "lucide-react";

interface EmptyStateProps {
  icon: LucideIcon;
  title: string;
  hint?: string;
  action?: { label: string; to: string };
}

/** Guidance-first empty state: what's missing and what fills it. */
export default function EmptyState({ icon: Icon, title, hint, action }: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center py-12 px-6 text-center">
      <Icon className="w-8 h-8 text-gray-700 mb-3" aria-hidden />
      <div className="text-sm text-gray-400">{title}</div>
      {hint && <div className="text-xs text-gray-600 mt-1 max-w-xs">{hint}</div>}
      {action && (
        <Link
          to={action.to}
          className="mt-3 text-xs text-blue-400 hover:text-blue-300 transition-colors"
        >
          {action.label}
        </Link>
      )}
    </div>
  );
}
