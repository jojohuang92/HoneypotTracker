import { Link } from "react-router-dom";
import { ArrowLeft, Radio, ShieldAlert, Database, Rss, Scale } from "lucide-react";
import { useSensorScope } from "../../context/SensorContext";

const GITHUB_URL = "https://github.com/jojohuang92/HoneypotTracker";

const SECTION_LABEL = "text-[10px] font-semibold uppercase tracking-wider text-gray-600";
const H2 = "flex items-center gap-2 text-sm font-semibold text-white";
const P = "text-sm text-gray-400 leading-relaxed mt-2.5";
const CODE = "font-mono text-[11px] text-gray-200 bg-gray-800 rounded px-1.5 py-0.5";

function origin(): string {
  return typeof window !== "undefined" ? window.location.origin : "";
}

const FEEDS: { path: string; desc: string; consumers: string }[] = [
  {
    path: "/api/export/blocklist.txt",
    desc: "One attacker IP per line, # comments for provenance. Add ?exclude_tor=true to drop Tor exit nodes.",
    consumers: "pfSense / OPNsense URL aliases, Pi-hole, fail2ban, ipset",
  },
  {
    path: "/api/export/top-attackers.json",
    desc: "Most active sources ranked by attempts, with dominant intent, country and infrastructure tags.",
    consumers: "scripts, dashboards",
  },
  {
    path: "/api/export/iocs.csv",
    desc: "Every indicator type in one flat file: IPs, payload SHA-256 hashes, and download URLs.",
    consumers: "SIEM lookups, spreadsheets",
  },
  {
    path: "/api/export/stix.json",
    desc: "STIX 2.1 bundle with deterministic indicator ids, so repeated pulls dedupe on the consumer side.",
    consumers: "MISP, OpenCTI, TAXII collections",
  },
];

export default function MethodologyPage() {
  const { sensors } = useSensorScope();
  const online = sensors.filter((s) => s.status === "online").length;
  const base = origin();

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

        <h1 className="text-2xl font-bold text-white tracking-tight">Methodology</h1>
        <p className={P}>
          What this site measures, how the numbers are produced, what is done with the data,
          and how to consume it. Everything shown is observed hostile traffic against
          sensors I operate; nothing is sampled or synthetic. The code is open:{" "}
          <a
            href={GITHUB_URL}
            target="_blank"
            rel="noreferrer noopener"
            className="text-blue-400 hover:text-blue-300"
          >
            jojohuang92/HoneypotTracker
          </a>
          .
        </p>

        {/* What is running */}
        <section className="border-t border-gray-800 mt-7 pt-5">
          <h2 className={H2}>
            <ShieldAlert className="w-4 h-4 text-red-400" aria-hidden />
            What the sensors run
          </h2>
          <p className={P}>
            Every sensor runs{" "}
            <a
              href="https://github.com/cowrie/cowrie"
              target="_blank"
              rel="noreferrer noopener"
              className="text-blue-400 hover:text-blue-300"
            >
              Cowrie
            </a>
            , a medium-interaction SSH and Telnet honeypot, inside a Docker container with
            the host's ports 22 and 23 mapped to it. Cowrie accepts logins from a permissive
            credential policy and then <em>emulates</em> a Linux shell: the attacker's
            commands run against a fake filesystem and fake command implementations, never
            against a real kernel. There is no code execution to escape from, so the
            sensor cannot be turned into a relay, proxy or DDoS node. Cowrie's port
            forwarding is left at its default, which logs forwarding requests without
            connecting anywhere.
          </p>
          <p className={P}>
            The one thing Cowrie does reach out for is the payload: when an attacker runs{" "}
            <span className={CODE}>wget</span> or <span className={CODE}>curl</span>, the
            emulation fetches the URL so the dropped file is captured. Those bytes are
            hashed and stored, never executed.
          </p>

          <h3 className={`${SECTION_LABEL} mt-5`}>Sensor footprint</h3>
          <div className="mt-2 grid sm:grid-cols-2 gap-2">
            {sensors.map((s) => (
              <div key={s.sensor_id} className="bg-gray-800/60 rounded-lg px-3 py-2.5 border border-gray-700/50">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs text-gray-200 font-medium truncate">{s.label}</span>
                  <span
                    className={`text-[10px] px-1.5 py-0.5 rounded ${
                      s.status === "online"
                        ? "text-green-300 bg-green-950/60"
                        : "text-gray-400 bg-gray-800"
                    }`}
                  >
                    {s.status}
                  </span>
                </div>
                <div className="text-[11px] text-gray-500 mt-1">
                  {[s.city, s.country_name].filter(Boolean).join(", ") || "Location withheld"}
                  {" · "}
                  {s.protocols.map((p) => p.toUpperCase()).join(" + ")}
                  {" · "}
                  location published at {s.location_precision} precision
                </div>
              </div>
            ))}
            {sensors.length === 0 && (
              <div className="text-xs text-gray-500">Sensor list unavailable.</div>
            )}
          </div>
          <p className="text-[11px] text-gray-500 mt-2">
            {online}/{sensors.length} online now. A single vantage point sees a skewed slice of
            the internet; counts on this site describe what reached these sensors, not the
            internet as a whole. Sensor coordinates are rounded to the precision shown before
            they are published.
          </p>
        </section>

        {/* Pipeline */}
        <section className="border-t border-gray-800 mt-7 pt-5">
          <h2 className={H2}>
            <Radio className="w-4 h-4 text-blue-400" aria-hidden />
            How an event becomes intelligence
          </h2>
          <ol className="mt-3 space-y-2 text-sm text-gray-400 leading-relaxed list-decimal pl-5">
            <li>
              <span className="text-gray-200">Ingest.</span> Cowrie's JSON event log is tailed
              on the hub and pushed from remote sensors over HTTPS with a per-sensor token.
              Nothing a sensor claims about geography or intent is trusted; the hub derives
              both.
            </li>
            <li>
              <span className="text-gray-200">Classify.</span> Every command is matched
              against an ordered set of explicit rules that map it to an intent
              (reconnaissance, malware deployment, cryptomining, credential theft,
              persistence, sabotage) and a MITRE ATT&amp;CK technique. Rules were chosen over
              a model so that every label can be traced to the exact pattern that fired.
              Unmatched commands are labelled <span className={CODE}>unknown</span> rather
              than guessed.
            </li>
            <li>
              <span className="text-gray-200">Enrich.</span> Source IPs get GeoIP
              (MaxMind GeoLite2), an AbuseIPDB confidence score, and infrastructure context
              from Shodan InternetDB and the Tor Project exit list: open ports, product
              versions, known CVEs, and tags such as <span className={CODE}>tor</span>,{" "}
              <span className={CODE}>vpn</span>, <span className={CODE}>proxy</span>,{" "}
              <span className={CODE}>cloud</span>. A Tor exit is a weak indicator (the real
              origin is unknowable); a host running an end-of-life OpenSSH with public CVEs
              is most likely itself compromised. Captured payloads are hashed (SHA-256, SHA-1,
              MD5), dissected locally (ELF architecture, embedded IPs and URLs), and checked
              against VirusTotal.
            </li>
            <li>
              <span className="text-gray-200">Score.</span> Each IP receives a composite
              threat score from its volume, intents, payloads, and how many sensors saw it.
              An IP hitting every sensor is a mass scanner; one hitting a single sensor may be
              targeted. The reasons behind a score are shown on the IP's profile.
            </li>
            <li>
              <span className="text-gray-200">Report.</span> Confirmed attackers are reported
              to AbuseIPDB, captured samples to VirusTotal, and the URLs those samples were
              fetched from to abuse.ch URLhaus. Every outbound report is deduplicated against
              an audit log first, and URLs are only submitted while their capture is fresh
              enough to count as a live distribution site.
            </li>
          </ol>
        </section>

        {/* Data handling */}
        <section className="border-t border-gray-800 mt-7 pt-5">
          <h2 className={H2}>
            <Database className="w-4 h-4 text-green-400" aria-hidden />
            What is stored, and for how long
          </h2>
          <ul className="mt-3 space-y-1.5 text-sm text-gray-400 leading-relaxed list-disc pl-5">
            <li>
              <span className="text-gray-200">Attacker traffic:</span> source IP and port,
              timestamps, credentials tried, commands typed, and files transferred. These are
              the product and are retained; per-day aggregates are kept indefinitely even if
              raw events are ever pruned.
            </li>
            <li>
              <span className="text-gray-200">Captured payloads:</span> stored on the hub as
              bytes named by hash, read-only, never executed, and only ever uploaded to
              VirusTotal. Daily backups that include them are written with owner-only
              permissions and never extracted automatically.
            </li>
            <li>
              <span className="text-gray-200">Private address space</span> is dropped at
              ingestion and never appears in any feed. Only globally routable addresses are
              exported.
            </li>
            <li>
              <span className="text-gray-200">Visitors to this dashboard:</span> a page view
              records the visiting IP and user agent for the visitor counter. The application
              itself sets no cookies; Google Analytics, which does, runs on the site.
            </li>
            <li>
              <span className="text-gray-200">Reporting audit trail:</span> every AbuseIPDB,
              VirusTotal and URLhaus submission is logged and pruned after 90 days.
            </li>
          </ul>
        </section>

        {/* Feeds */}
        <section className="border-t border-gray-800 mt-7 pt-5">
          <h2 className={H2}>
            <Rss className="w-4 h-4 text-orange-400" aria-hidden />
            Open data feeds
          </h2>
          <p className={P}>
            The indicators are free to consume without an account. Feeds accept{" "}
            <span className={CODE}>?days=N</span> (1–365, default 30), are rebuilt at most
            every five minutes, and honour <span className={CODE}>If-None-Match</span> so a
            poller that sends the last <span className={CODE}>ETag</span> costs nothing when
            nothing changed. Requests are rate-limited per client; a five-minute polling
            interval is plenty.
          </p>
          <div className="mt-3 space-y-2">
            {FEEDS.map((f) => (
              <div key={f.path} className="bg-gray-800/60 rounded-lg px-3 py-2.5 border border-gray-700/50">
                <a
                  href={f.path}
                  className="font-mono text-xs text-cyan-400 hover:text-cyan-300 break-all"
                >
                  {base}{f.path}
                </a>
                <div className="text-[11px] text-gray-400 mt-1">{f.desc}</div>
                <div className="text-[10px] text-gray-600 mt-0.5">Works with: {f.consumers}</div>
              </div>
            ))}
          </div>
          <div className="mt-3 bg-gray-950 rounded-lg border border-gray-800 overflow-x-auto">
            <pre className="p-3 text-[11px] leading-relaxed text-gray-300 font-mono">
{`# Refresh an ipset from the blocklist every 5 minutes (cron)
curl -fsS ${base}/api/export/blocklist.txt?days=7 \\
  | grep -v '^#' | xargs -r -n1 ipset add honeypot-attackers -exist`}
            </pre>
          </div>
          <p className="text-[11px] text-gray-500 mt-2">
            Please attribute the data to Honeypot Tracker if you republish it. Indicators
            describe hosts that attacked these sensors; they are not a judgement about the
            host's owner, who is often a victim of the same botnet.
          </p>
        </section>

        {/* Limitations */}
        <section className="border-t border-gray-800 mt-7 pt-5">
          <h2 className={H2}>
            <Scale className="w-4 h-4 text-purple-400" aria-hidden />
            Limitations
          </h2>
          <ul className="mt-3 space-y-1.5 text-sm text-gray-400 leading-relaxed list-disc pl-5">
            <li>
              Cowrie is fingerprintable. Sophisticated actors detect the emulation and leave,
              so the corpus over-represents commodity botnets and credential stuffing.
            </li>
            <li>
              Only SSH and Telnet are exposed. HTTP, SMB, RDP and database scanning are not
              observed at all.
            </li>
            <li>
              GeoIP places an address at its registration, not where the operator sits, and
              a Tor exit or VPN hides the origin entirely. Country rankings describe
              infrastructure, not attackers.
            </li>
            <li>
              Intent labels are rule-based. A novel technique lands in{" "}
              <span className={CODE}>unknown</span> until a rule is written for it; the
              share of unknowns is shown honestly rather than folded into another category.
            </li>
          </ul>
        </section>

        <div className="flex items-center gap-2 text-[11px] text-gray-600 border-t border-gray-800 mt-7 pt-5">
          <ShieldAlert className="w-3.5 h-3.5 text-red-400/70 shrink-0" aria-hidden />
          Questions about the data or a listed address? See the{" "}
          <Link to="/about" className="text-blue-400 hover:text-blue-300">
            About page
          </Link>{" "}
          for contact details.
        </div>
      </div>
    </div>
  );
}
