"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import type { EventCategory, EventStatus, SecurityEvent, Severity } from "@/types/security";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];
const STATUSES: EventStatus[] = ["Open", "Investigating", "Contained", "Resolved"];
const SEVERITY_STYLES: Record<Severity, string> = {
  critical: "border-red-400/20 bg-red-400/10 text-red-300",
  high: "border-orange-400/20 bg-orange-400/10 text-orange-300",
  medium: "border-amber-400/20 bg-amber-400/10 text-amber-300",
  low: "border-sky-400/20 bg-sky-400/10 text-sky-300",
};
const STATUS_STYLES: Record<EventStatus, string> = {
  Open: "text-red-300", Investigating: "text-amber-300", Contained: "text-emerald-300", Resolved: "text-muted",
};
const CONTROL_STYLES = "h-10 rounded-md border border-border bg-background px-3 text-sm text-foreground outline-none transition-colors placeholder:text-muted/70 focus:border-accent/60 focus:ring-2 focus:ring-accent/20";

export function EventExplorer({ events }: { events: SecurityEvent[] }) {
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState<Severity | "all">("all");
  const [status, setStatus] = useState<EventStatus | "all">("all");
  const [category, setCategory] = useState<EventCategory | "all">("all");
  const categories = useMemo(() => [...new Set(events.map((event) => event.category))].sort(), [events]);
  const filteredEvents = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    return events.filter((event) => {
      const searchable = [event.id, event.title, event.description, event.asset, event.sourceIp, event.user, event.detectionRule.name]
        .filter(Boolean).join(" ").toLowerCase();
      return (!normalized || searchable.includes(normalized)) &&
        (severity === "all" || event.severity === severity) &&
        (status === "all" || event.status === status) &&
        (category === "all" || event.category === category);
    });
  }, [category, events, query, severity, status]);

  const hasFilters = query !== "" || severity !== "all" || status !== "all" || category !== "all";
  function resetFilters() { setQuery(""); setSeverity("all"); setStatus("all"); setCategory("all"); }

  return (
    <section aria-labelledby="event-stream-heading" className="rounded-lg border border-border bg-surface/20">
      <h2 id="event-stream-heading" className="sr-only">Security event stream</h2>
      <div className="border-b border-border p-4">
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-[minmax(260px,1fr)_170px_180px_190px_auto]">
          <div>
            <label htmlFor="event-search" className="sr-only">Search security events</label>
            <input id="event-search" type="search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search ID, event, host, IP, user, or rule…" className={`${CONTROL_STYLES} w-full`} />
          </div>
          <label className="sr-only" htmlFor="severity-filter">Severity</label>
          <select id="severity-filter" value={severity} onChange={(event) => setSeverity(event.target.value as Severity | "all")} className={CONTROL_STYLES}>
            <option value="all">All severities</option>{SEVERITIES.map((value) => <option key={value} value={value}>{value[0].toUpperCase() + value.slice(1)}</option>)}
          </select>
          <label className="sr-only" htmlFor="status-filter">Status</label>
          <select id="status-filter" value={status} onChange={(event) => setStatus(event.target.value as EventStatus | "all")} className={CONTROL_STYLES}>
            <option value="all">All statuses</option>{STATUSES.map((value) => <option key={value}>{value}</option>)}
          </select>
          <label className="sr-only" htmlFor="category-filter">Category</label>
          <select id="category-filter" value={category} onChange={(event) => setCategory(event.target.value as EventCategory | "all")} className={CONTROL_STYLES}>
            <option value="all">All categories</option>{categories.map((value) => <option key={value}>{value}</option>)}
          </select>
          <button type="button" onClick={resetFilters} disabled={!hasFilters} className="h-10 rounded-md border border-border px-4 text-sm text-muted transition-colors hover:border-accent/40 hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:cursor-not-allowed disabled:opacity-40">
            Reset
          </button>
        </div>
        <p className="mt-3 text-xs text-muted" aria-live="polite">Showing <span className="font-mono text-foreground">{filteredEvents.length}</span> of {events.length} events</p>
      </div>

      {filteredEvents.length ? (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[980px] border-collapse text-left text-sm">
            <thead><tr className="border-b border-border font-mono text-[10px] uppercase tracking-[0.12em] text-muted">
              {['Severity','Event','Category','Host / source','Time','Risk','Status'].map((label) => <th key={label} scope="col" className="px-4 py-3 font-medium">{label}</th>)}
            </tr></thead>
            <tbody className="divide-y divide-border">
              {filteredEvents.map((event) => (
                <tr key={event.id} className="transition-colors hover:bg-surface/50 focus-within:bg-surface/50">
                  <td className="px-4 py-3.5"><span className={`inline-flex rounded border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider ${SEVERITY_STYLES[event.severity]}`}>{event.severity}</span></td>
                  <td className="px-4 py-3.5"><Link href={`/app/security-events/${event.id}`} className="font-medium text-foreground hover:text-accent focus-visible:rounded-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent">{event.title}</Link><p className="mt-1 font-mono text-[10px] text-muted">{event.id}</p></td>
                  <td className="px-4 py-3.5 text-xs text-muted">{event.category}</td>
                  <td className="px-4 py-3.5 font-mono text-xs text-muted">{event.asset ?? event.sourceIp ?? event.sourceType}</td>
                  <td className="px-4 py-3.5 font-mono text-xs tabular-nums text-muted"><time dateTime={event.timestamp}>{new Intl.DateTimeFormat("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }).format(new Date(event.timestamp))}</time></td>
                  <td className="px-4 py-3.5"><span className={`font-mono text-sm font-semibold tabular-nums ${event.riskScore >= 85 ? "text-red-300" : event.riskScore >= 65 ? "text-amber-300" : "text-muted"}`}>{event.riskScore}</span><span className="text-[10px] text-muted">/100</span></td>
                  <td className={`px-4 py-3.5 text-xs font-medium ${STATUS_STYLES[event.status]}`}>{event.status}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="px-6 py-16 text-center"><p className="text-sm font-medium text-foreground">No events match these filters</p><p className="mt-1 text-sm text-muted">Adjust the search criteria or reset all filters.</p><button type="button" onClick={resetFilters} className="mt-4 rounded-md border border-border px-4 py-2 text-sm text-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent">Reset filters</button></div>
      )}
    </section>
  );
}
