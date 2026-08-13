import {
  AI_FINDINGS,
  SUMMARY_METRICS,
  TELEMETRY_SOURCES,
  THREAT_ACTIVITY,
} from "@/lib/overview-mock-data";
import { SECURITY_EVENTS } from "@/lib/security-events-mock-data";
import type { Severity, SummaryMetric } from "@/types/security";

const SEVERITY_STYLES: Record<Severity, string> = {
  critical: "border-red-400/20 bg-red-400/10 text-red-300",
  high: "border-orange-400/20 bg-orange-400/10 text-orange-300",
  medium: "border-amber-400/20 bg-amber-400/10 text-amber-300",
  low: "border-sky-400/20 bg-sky-400/10 text-sky-300",
};

const METRIC_STYLES: Record<SummaryMetric["tone"], string> = {
  neutral: "text-foreground",
  critical: "text-red-300",
  warning: "text-amber-300",
  positive: "text-emerald-300",
};

const STATUS_STYLES = {
  Open: "text-red-300",
  Investigating: "text-amber-300",
  Contained: "text-emerald-300",
  Resolved: "text-muted",
} as const;

function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={`inline-flex rounded border px-2 py-0.5 font-mono text-[9px] font-medium uppercase tracking-wider ${SEVERITY_STYLES[severity]}`}
    >
      {severity}
    </span>
  );
}

export default function OverviewPage() {
  const maxActivity = Math.max(
    ...THREAT_ACTIVITY.map((point) => point.critical + point.high + point.medium + point.low),
  );

  return (
    <main className="mx-auto min-h-screen max-w-[1600px] px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
      <header className="mb-6 flex flex-col gap-3 border-b border-border pb-6 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-accent">Security Operations</p>
          <h1 className="mt-2 text-2xl font-semibold tracking-tight text-foreground">Overview</h1>
          <p className="mt-1 text-sm text-muted">Current risk, recent activity, and telemetry coverage.</p>
        </div>
        <div className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-wider text-muted">
          <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" aria-hidden="true" />
          Updated 14:34:02 CDT
        </div>
      </header>

      <section aria-labelledby="summary-heading">
        <h2 id="summary-heading" className="sr-only">Security summary</h2>
        <dl className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
          {SUMMARY_METRICS.map((metric) => (
            <div key={metric.label} className="rounded-lg border border-border bg-surface/25 px-4 py-4">
              <dt className="font-mono text-[10px] uppercase tracking-[0.16em] text-muted">{metric.label}</dt>
              <dd className={`mt-2 text-2xl font-semibold tabular-nums ${METRIC_STYLES[metric.tone]}`}>
                {metric.value}
              </dd>
              <p className="mt-1 text-xs text-muted">{metric.context}</p>
            </div>
          ))}
        </dl>
      </section>

      <div className="mt-5 grid gap-5 xl:grid-cols-[minmax(0,1.65fr)_minmax(300px,0.75fr)]">
        <section aria-labelledby="events-heading" className="min-w-0 rounded-lg border border-border bg-surface/20">
          <div className="flex items-center justify-between border-b border-border px-4 py-3.5">
            <div>
              <h2 id="events-heading" className="text-sm font-semibold text-foreground">Recent Security Events</h2>
              <p className="mt-0.5 text-xs text-muted">Latest prioritized detections across monitored sources</p>
            </div>
            <span className="font-mono text-[9px] uppercase tracking-wider text-muted">Last 2 hours</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[760px] border-collapse text-left text-sm">
              <thead>
                <tr className="border-b border-border font-mono text-[9px] uppercase tracking-[0.14em] text-muted">
                  <th scope="col" className="px-4 py-3 font-medium">Severity</th>
                  <th scope="col" className="px-4 py-3 font-medium">Event</th>
                  <th scope="col" className="px-4 py-3 font-medium">Host / source</th>
                  <th scope="col" className="px-4 py-3 font-medium">Time</th>
                  <th scope="col" className="px-4 py-3 font-medium">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {SECURITY_EVENTS.slice(0, 5).map((event) => (
                  <tr key={event.id} className="transition-colors hover:bg-surface/40">
                    <td className="px-4 py-3"><SeverityBadge severity={event.severity} /></td>
                    <td className="px-4 py-3">
                      <p className="font-medium text-foreground">{event.title}</p>
                      <p className="mt-0.5 font-mono text-[9px] text-muted">{event.id}</p>
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-muted">{event.asset ?? event.sourceIp ?? event.sourceType}</td>
                    <td className="px-4 py-3 font-mono text-xs tabular-nums text-muted">{new Date(event.timestamp).toLocaleTimeString("en-US", { hour12: false })}</td>
                    <td className={`px-4 py-3 text-xs font-medium ${STATUS_STYLES[event.status]}`}>{event.status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <section aria-labelledby="activity-heading" className="rounded-lg border border-border bg-surface/20 p-4">
          <div className="flex items-start justify-between">
            <div>
              <h2 id="activity-heading" className="text-sm font-semibold text-foreground">Threat Activity</h2>
              <p className="mt-0.5 text-xs text-muted">Events by severity · 7 days</p>
            </div>
            <p className="text-right font-mono text-[9px] uppercase tracking-wider text-muted">
              Today<br /><span className="text-sm font-semibold text-foreground">90 events</span>
            </p>
          </div>

          <div className="mt-6 flex h-40 items-end justify-between gap-2 border-b border-border pb-px" role="img" aria-label="Seven-day stacked bar chart. Activity peaks today at 90 events, including 7 critical and 16 high severity events.">
            {THREAT_ACTIVITY.map((point) => {
              const total = point.critical + point.high + point.medium + point.low;
              const height = `${Math.max(20, (total / maxActivity) * 100)}%`;
              return (
                <div key={point.day} className="flex h-full flex-1 items-end justify-center">
                  <div className="flex w-full max-w-7 flex-col-reverse overflow-hidden rounded-t-sm" style={{ height }} title={`${point.day}: ${total} events`}>
                    <span className="bg-sky-400/35" style={{ flex: point.low }} />
                    <span className="bg-amber-400/55" style={{ flex: point.medium }} />
                    <span className="bg-orange-400/75" style={{ flex: point.high }} />
                    <span className="bg-red-400" style={{ flex: point.critical }} />
                  </div>
                </div>
              );
            })}
          </div>
          <div className="mt-2 flex justify-between gap-2 font-mono text-[9px] uppercase text-muted">
            {THREAT_ACTIVITY.map((point) => <span key={point.day} className="flex-1 text-center">{point.day}</span>)}
          </div>
          <ul className="mt-5 grid grid-cols-2 gap-x-4 gap-y-2 text-[10px] text-muted" aria-label="Severity legend">
            {[
              ["Critical", "bg-red-400"],
              ["High", "bg-orange-400"],
              ["Medium", "bg-amber-400/70"],
              ["Low", "bg-sky-400/50"],
            ].map(([label, color]) => (
              <li key={label} className="flex items-center gap-2"><span className={`h-1.5 w-1.5 rounded-full ${color}`} />{label}</li>
            ))}
          </ul>
        </section>
      </div>

      <div className="mt-5 grid gap-5 xl:grid-cols-[minmax(0,1.4fr)_minmax(320px,0.6fr)]">
        <section aria-labelledby="findings-heading" className="rounded-lg border border-border bg-surface/20">
          <div className="border-b border-border px-4 py-3.5">
            <h2 id="findings-heading" className="text-sm font-semibold text-foreground">AI Findings</h2>
            <p className="mt-0.5 text-xs text-muted">Automated correlation and behavioral analysis requiring review</p>
          </div>
          <ul className="divide-y divide-border">
            {AI_FINDINGS.map((finding) => (
              <li key={finding.id} className="p-4">
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityBadge severity={finding.severity} />
                  <h3 className="text-sm font-medium text-foreground">{finding.title}</h3>
                  <span className="ml-auto font-mono text-[10px] text-accent">{finding.confidence}% confidence</span>
                </div>
                <p className="mt-2 text-xs leading-relaxed text-muted">{finding.reasoning}</p>
                <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[9px] uppercase tracking-wider text-muted">
                  <span>{finding.id}</span>
                  <span>Affected: <span className="normal-case text-foreground/80">{finding.affectedEntity}</span></span>
                  {finding.technique && <span>MITRE {finding.technique.id} · <span className="normal-case text-foreground/80">{finding.technique.name}</span></span>}
                </div>
              </li>
            ))}
          </ul>
        </section>

        <section aria-labelledby="telemetry-heading" className="self-start rounded-lg border border-border bg-surface/20">
          <div className="border-b border-border px-4 py-3.5">
            <h2 id="telemetry-heading" className="text-sm font-semibold text-foreground">Telemetry Health</h2>
            <p className="mt-0.5 text-xs text-muted">Data availability and source coverage</p>
          </div>
          <ul className="divide-y divide-border">
            {TELEMETRY_SOURCES.map((source) => (
              <li key={source.name} className="px-4 py-4">
                <div className="flex items-center justify-between gap-3">
                  <div className="flex items-center gap-2">
                    <span className={`h-1.5 w-1.5 rounded-full ${source.status === "Healthy" ? "bg-emerald-400" : source.status === "Delayed" ? "bg-amber-400" : "bg-red-400"}`} aria-hidden="true" />
                    <h3 className="text-xs font-medium text-foreground">{source.name}</h3>
                  </div>
                  <span className={`font-mono text-[9px] uppercase tracking-wider ${source.status === "Healthy" ? "text-emerald-300" : "text-amber-300"}`}>{source.status}</span>
                </div>
                <dl className="mt-2 grid grid-cols-2 gap-3 text-[10px]">
                  <div><dt className="text-muted">Coverage</dt><dd className="mt-0.5 font-mono text-foreground/80">{source.coverage}</dd></div>
                  <div><dt className="text-muted">Last event</dt><dd className="mt-0.5 font-mono text-foreground/80">{source.lastEvent}</dd></div>
                </dl>
              </li>
            ))}
          </ul>
          <div className="border-t border-border bg-background/30 px-4 py-3 text-[10px] leading-relaxed text-muted">
            Network sensor <span className="font-mono text-foreground/80">sensor-dmz-02</span> is reporting delayed events.
          </div>
        </section>
      </div>
    </main>
  );
}
