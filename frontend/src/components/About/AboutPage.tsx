import { Link } from "react-router-dom";
import { Mail, MapPin, ArrowLeft, ArrowRight, ShieldAlert } from "lucide-react";
import { useOverview } from "../../hooks/useAttempts";
import { useSensorScope } from "../../context/SensorContext";
import { formatNumber } from "../../utils/formatters";

const GITHUB_URL = "https://github.com/jojohuang92";
const LINKEDIN_URL = "https://www.linkedin.com/in/jonathan-huang49/";
const EMAIL = "jonagent49@gmail.com";

const SECURITY_SKILLS = [
  "Splunk / SPL",
  "MITRE ATT&CK",
  "Wireshark",
  "Snort",
  "Linux auditd",
  "Cowrie",
  "nmap",
  "VirusTotal",
  "AbuseIPDB",
  "UFW",
  "Incident response",
  "Network forensics",
];

const ENGINEERING_SKILLS = [
  "Python",
  "FastAPI",
  "TypeScript",
  "React",
  "React Native",
  "Docker",
  "Linux",
  "Nginx",
  "WireGuard",
  "Cloudflare",
  "SQL",
  "scikit-learn",
];

const CERTIFICATIONS: { name: string; note: string; pending?: boolean }[] = [
  { name: "CompTIA Security+", note: "May 2026" },
  { name: "Google Cybersecurity Professional Certificate", note: "Dec 2025" },
  { name: "CodePath CYB102 — Intermediate Cybersecurity", note: "May 2026" },
  { name: "Splunk Certified Power User", note: "in progress", pending: true },
  { name: "CompTIA CySA+", note: "in progress", pending: true },
];

const TIMELINE: { title: string; meta: string; detail?: string }[] = [
  {
    title: "B.S. Computer Science",
    meta: "California State University, Long Beach · Aug 2022 – May 2026",
    detail: "Network security, computer forensics, database systems, cloud computing",
  },
  {
    title: "Undergraduate research assistant",
    meta: "CSULB · Feb – Sep 2025",
    detail: "YOLOv8 and OpenCV perception for vehicle-to-everything (V2X) safety",
  },
];

const PIPELINE = [
  "Cowrie honeypot",
  "Ingest + classify",
  "GeoIP + threat intel",
  "This dashboard",
];

// lucide dropped brand glyphs in v1, and these two are worth recognizing at a
// glance on a page whose whole job is to be clicked through.
function GithubMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="currentColor" className={className} aria-hidden>
      <path d="M12 .5a12 12 0 0 0-3.79 23.4c.6.1.82-.26.82-.58v-2.2c-3.34.72-4.04-1.6-4.04-1.6-.55-1.4-1.34-1.77-1.34-1.77-1.09-.74.08-.73.08-.73 1.2.09 1.84 1.24 1.84 1.24 1.07 1.84 2.8 1.3 3.49 1 .1-.78.42-1.31.76-1.61-2.67-.3-5.47-1.34-5.47-5.96 0-1.32.47-2.39 1.24-3.23-.13-.3-.54-1.53.11-3.18 0 0 1.01-.32 3.3 1.23a11.5 11.5 0 0 1 6.01 0c2.29-1.55 3.3-1.23 3.3-1.23.65 1.65.24 2.88.12 3.18.77.84 1.23 1.91 1.23 3.23 0 4.63-2.8 5.65-5.48 5.95.43.37.81 1.1.81 2.22v3.29c0 .32.22.69.83.58A12 12 0 0 0 12 .5Z" />
    </svg>
  );
}

function LinkedInMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="currentColor" className={className} aria-hidden>
      <path d="M20.45 20.45h-3.56v-5.57c0-1.33-.03-3.04-1.85-3.04-1.86 0-2.14 1.45-2.14 2.94v5.67H9.35V9h3.41v1.56h.05a3.74 3.74 0 0 1 3.37-1.85c3.6 0 4.27 2.37 4.27 5.46v6.28ZM5.34 7.43a2.07 2.07 0 1 1 0-4.13 2.07 2.07 0 0 1 0 4.13Zm1.78 13.02H3.55V9h3.57v11.45ZM22.22 0H1.77C.79 0 0 .77 0 1.73v20.54C0 23.23.79 24 1.77 24h20.45c.98 0 1.78-.77 1.78-1.73V1.73C24 .77 23.2 0 22.22 0Z" />
    </svg>
  );
}

const SECTION_LABEL = "text-[10px] font-semibold uppercase tracking-wider text-gray-600";
const CHIP =
  "text-[11px] text-gray-300 bg-gray-800 rounded px-2 py-1 whitespace-nowrap";

interface StatProps {
  value: string;
  label: string;
  color: string;
}

function Stat({ value, label, color }: StatProps) {
  return (
    <div className="bg-gray-800 rounded-lg px-3.5 py-3">
      <div className={`text-xl font-bold tabular-nums ${color}`}>{value}</div>
      <div className="text-[10px] text-gray-500 uppercase tracking-wider mt-0.5">
        {label}
      </div>
    </div>
  );
}

export default function AboutPage() {
  // All-time totals, fleet-wide — this page is about the project as a whole,
  // so it deliberately ignores the sensor scope and time range selectors.
  const { data: stats } = useOverview(0, null);
  const { sensors } = useSensorScope();
  const online = sensors.filter((s) => s.status === "online").length;

  return (
    <div className="flex-1 min-w-0 min-h-0 overflow-auto bg-gray-900">
      <div className="max-w-3xl mx-auto px-6 py-8">
        <Link
          to="/"
          className="inline-flex items-center gap-1.5 text-xs text-gray-500 hover:text-gray-300 transition-colors mb-6"
        >
          <ArrowLeft className="w-3.5 h-3.5" aria-hidden />
          Back to the live dashboard
        </Link>

        {/* Header */}
        <div className="flex flex-col sm:flex-row gap-5 items-start">
          <div className="w-14 h-14 shrink-0 rounded-full bg-blue-950 text-blue-300 flex items-center justify-center text-lg font-semibold">
            JH
          </div>
          <div className="min-w-0">
            <h1 className="text-2xl font-bold text-white tracking-tight">Jonathan Huang</h1>
            <p className="text-sm text-blue-300 mt-0.5">
              Passionate software engineer focused on cybersecurity
            </p>
            <p className="text-sm text-gray-400 leading-relaxed mt-3">
              B.S. Computer Science, CSULB (May 2026). I built and run this platform end
              to end — a Cowrie SSH/Telnet honeypot on a hardened Raspberry Pi feeding a
              FastAPI backend that classifies attacker intent against MITRE ATT&amp;CK and
              auto-reports confirmed attackers to AbuseIPDB and VirusTotal. Everything on
              this site is live data from my own sensors. Looking for entry-level SOC
              analyst and security engineering roles.
            </p>

            <div className="flex flex-wrap items-center gap-2 mt-4">
              <a
                href={GITHUB_URL}
                target="_blank"
                rel="noreferrer noopener"
                className="inline-flex items-center gap-1.5 text-[11px] text-gray-200 border border-gray-700 rounded-md px-2.5 py-1.5 hover:border-gray-500 hover:text-white transition-colors"
              >
                <GithubMark className="w-3.5 h-3.5" />
                GitHub
              </a>
              <a
                href={LINKEDIN_URL}
                target="_blank"
                rel="noreferrer noopener"
                className="inline-flex items-center gap-1.5 text-[11px] text-gray-200 border border-gray-700 rounded-md px-2.5 py-1.5 hover:border-gray-500 hover:text-white transition-colors"
              >
                <LinkedInMark className="w-3.5 h-3.5" />
                LinkedIn
              </a>
              <a
                href={`mailto:${EMAIL}`}
                className="inline-flex items-center gap-1.5 text-[11px] text-gray-200 border border-gray-700 rounded-md px-2.5 py-1.5 hover:border-gray-500 hover:text-white transition-colors"
              >
                <Mail className="w-3.5 h-3.5" aria-hidden />
                {EMAIL}
              </a>
              <span className="inline-flex items-center gap-1.5 text-[11px] text-gray-500 px-1 py-1.5">
                <MapPin className="w-3.5 h-3.5" aria-hidden />
                Cerritos, CA
              </span>
            </div>
          </div>
        </div>

        {/* Live counters — the whole point of the page is that these move. */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-2.5 mt-7">
          <Stat
            value={formatNumber(stats.total_attempts)}
            label="Attack sessions"
            color="text-red-400"
          />
          <Stat
            value={formatNumber(stats.unique_ips)}
            label="Unique IPs"
            color="text-blue-400"
          />
          <Stat
            value={formatNumber(stats.unique_countries)}
            label="Countries"
            color="text-green-400"
          />
          <Stat
            value={`${online}/${sensors.length}`}
            label="Sensors online"
            color="text-purple-400"
          />
        </div>
        <p className="text-[10px] text-gray-600 mt-2">
          Pulled live from the API — these are real captures, not sample data.
        </p>

        {/* Project */}
        <section className="border-t border-gray-800 mt-7 pt-5">
          <h2 className={SECTION_LABEL}>How it works</h2>
          <div className="flex flex-wrap items-center gap-1.5 mt-3">
            <span className="text-[11px] text-red-300 bg-red-950/40 border border-red-900 rounded px-2 py-1.5">
              Attacker
            </span>
            {PIPELINE.map((step, i) => (
              <span key={step} className="flex items-center gap-1.5">
                <ArrowRight className="w-3.5 h-3.5 text-gray-600" aria-hidden />
                <span
                  className={`text-[11px] rounded px-2 py-1.5 ${
                    i === PIPELINE.length - 1
                      ? "text-blue-300 bg-blue-950/50 border border-blue-800"
                      : "text-gray-200 bg-gray-800"
                  }`}
                >
                  {step}
                </span>
              </span>
            ))}
          </div>
          <p className="text-sm text-gray-400 leading-relaxed mt-3.5">
            Raw honeypot logs are noise. Every command an attacker types is classified
            into an intent and mapped to a MITRE ATT&amp;CK technique, source IPs are
            enriched with GeoIP and reputation data, and captured payloads are hashed and
            submitted to VirusTotal. Confirmed attackers are reported to AbuseIPDB
            automatically, with dedup windows and an audit trail. New sessions stream to
            the browser over Server-Sent Events, so the map moves as attacks land.
          </p>
          <p className="text-sm text-gray-400 leading-relaxed mt-2.5">
            The backend is Python, FastAPI, and SQLAlchemy over SQLite; ingestion, the
            reporting workers, and retention pruning run as async background tasks. The
            dashboard is React 19 and TypeScript with Leaflet and Recharts. The whole
            stack deploys with one <code className="text-gray-300">docker compose up</code>{" "}
            behind nginx, and CI runs the test suite on every push.
          </p>
          <a
            href={`${GITHUB_URL}/HoneypotTracker`}
            target="_blank"
            rel="noreferrer noopener"
            className="inline-flex items-center gap-1.5 text-xs text-blue-400 hover:text-blue-300 transition-colors mt-3.5"
          >
            <GithubMark className="w-3.5 h-3.5" />
            Source on GitHub
          </a>
        </section>

        {/* Skills + credentials */}
        <div className="grid md:grid-cols-2 gap-x-8 gap-y-6 border-t border-gray-800 mt-7 pt-5">
          <div>
            <h2 className={SECTION_LABEL}>Security</h2>
            <div className="flex flex-wrap gap-1.5 mt-2.5">
              {SECURITY_SKILLS.map((s) => (
                <span key={s} className={CHIP}>
                  {s}
                </span>
              ))}
            </div>

            <h2 className={`${SECTION_LABEL} mt-5`}>Engineering</h2>
            <div className="flex flex-wrap gap-1.5 mt-2.5">
              {ENGINEERING_SKILLS.map((s) => (
                <span key={s} className={CHIP}>
                  {s}
                </span>
              ))}
            </div>
          </div>

          <div>
            <h2 className={SECTION_LABEL}>Certifications</h2>
            <ul className="mt-2.5 space-y-1.5">
              {CERTIFICATIONS.map((c) => (
                <li key={c.name} className="flex items-baseline justify-between gap-3">
                  <span
                    className={`text-xs ${c.pending ? "text-gray-400" : "text-gray-200"}`}
                  >
                    {c.name}
                  </span>
                  <span
                    className={`text-[10px] shrink-0 ${
                      c.pending
                        ? "text-amber-500/90 bg-amber-950/40 rounded px-1.5 py-0.5"
                        : "text-gray-500 font-mono"
                    }`}
                  >
                    {c.note}
                  </span>
                </li>
              ))}
            </ul>

            <h2 className={`${SECTION_LABEL} mt-5`}>Education &amp; experience</h2>
            <ul className="mt-2.5 space-y-3">
              {TIMELINE.map((t) => (
                <li key={t.title} className="border-l-2 border-gray-700 pl-3">
                  <div className="text-xs text-gray-200">{t.title}</div>
                  <div className="text-[11px] text-gray-500 mt-0.5">{t.meta}</div>
                  {t.detail && (
                    <div className="text-[11px] text-gray-500 mt-0.5">{t.detail}</div>
                  )}
                </li>
              ))}
            </ul>
          </div>
        </div>

        <div className="flex items-center gap-2 text-[11px] text-gray-600 border-t border-gray-800 mt-7 pt-5">
          <ShieldAlert className="w-3.5 h-3.5 text-red-400/70 shrink-0" aria-hidden />
          Honeypot Tracker is a personal research project. Attacker IPs shown on this site
          are observed hostile traffic against my own sensors.
        </div>
      </div>
    </div>
  );
}
