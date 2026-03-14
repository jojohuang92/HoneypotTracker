import type { Attempt } from "../../types";
import { formatTimestamp, intentLabel, intentColor } from "../../utils/formatters";

interface AttemptDetailProps {
  attempt: Attempt;
  onClose: () => void;
}

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  if (value == null || value === "") return null;
  return (
    <div className="flex justify-between gap-2 py-1.5 border-b border-gray-800/50">
      <span className="text-gray-500 text-xs shrink-0">{label}</span>
      <span className="text-gray-200 text-xs text-right font-mono break-all">{value}</span>
    </div>
  );
}

export default function AttemptDetail({ attempt: a, onClose }: AttemptDetailProps) {
  return (
    <div className="absolute inset-0 z-50 flex items-center justify-center bg-black/60 rounded-lg" onClick={onClose}>
      <div
        className="bg-gray-900 border border-gray-700 rounded-lg shadow-xl w-[90%] max-h-[85%] flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between p-3 border-b border-gray-700">
          <h3 className="text-sm font-semibold text-white">Attempt Detail</h3>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-white text-lg leading-none px-1"
          >
            &times;
          </button>
        </div>

        {/* Body */}
        <div className="p-3 overflow-y-auto space-y-3">
          {/* Connection */}
          <section>
            <h4 className="text-[10px] uppercase tracking-wider text-gray-500 mb-1">Connection</h4>
            <div className="bg-gray-800/50 rounded-lg p-2">
              <Field label="Time" value={formatTimestamp(a.timestamp)} />
              <Field label="Source IP" value={a.src_ip} />
              <Field label="Source Port" value={a.src_port} />
              <Field label="Dest Port" value={a.dst_port} />
              <Field label="Protocol" value={a.protocol} />
              <Field label="Session" value={a.session_id} />
              <Field label="Event" value={a.event_id} />
            </div>
          </section>

          {/* Location */}
          {(a.country_name || a.city) && (
            <section>
              <h4 className="text-[10px] uppercase tracking-wider text-gray-500 mb-1">Location</h4>
              <div className="bg-gray-800/50 rounded-lg p-2">
                <Field label="Country" value={a.country_name ? `${a.country_name} (${a.country_code})` : a.country_code} />
                <Field label="City" value={a.city} />
                <Field label="Coordinates" value={a.latitude != null && a.longitude != null ? `${a.latitude}, ${a.longitude}` : null} />
                <Field label="ASN" value={a.asn} />
                <Field label="AS Org" value={a.as_org} />
              </div>
            </section>
          )}

          {/* Credentials */}
          {(a.username || a.password) && (
            <section>
              <h4 className="text-[10px] uppercase tracking-wider text-gray-500 mb-1">Credentials</h4>
              <div className="bg-gray-800/50 rounded-lg p-2">
                <Field label="Username" value={<span className="text-cyan-400">{a.username}</span>} />
                <Field label="Password" value={<span className="text-orange-400">{a.password}</span>} />
                <Field label="Success" value={a.success ? <span className="text-green-400">Yes</span> : <span className="text-red-400">No</span>} />
              </div>
            </section>
          )}

          {/* Command */}
          {a.command && (
            <section>
              <h4 className="text-[10px] uppercase tracking-wider text-gray-500 mb-1">Command</h4>
              <div className="bg-gray-800/50 rounded-lg p-2">
                <pre className="text-xs text-green-400 font-mono whitespace-pre-wrap break-all">{a.command}</pre>
              </div>
            </section>
          )}

          {/* Classification */}
          {a.intent && (
            <section>
              <h4 className="text-[10px] uppercase tracking-wider text-gray-500 mb-1">Classification</h4>
              <div className="bg-gray-800/50 rounded-lg p-2">
                <Field
                  label="Intent"
                  value={
                    <span
                      className="inline-block px-1.5 py-0.5 rounded text-[10px] font-medium"
                      style={{
                        backgroundColor: intentColor(a.intent) + "20",
                        color: intentColor(a.intent),
                      }}
                    >
                      {intentLabel(a.intent)}
                    </span>
                  }
                />
                <Field label="MITRE ATT&CK" value={a.mitre_id} />
              </div>
            </section>
          )}
        </div>
      </div>
    </div>
  );
}
