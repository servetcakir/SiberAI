"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import type { ApiSeverity, SecurityEventListItem } from "@/types/siberai-api";

const SEVERITIES: ApiSeverity[] = ["critical", "high", "medium", "low"];
const SEVERITY_STYLES: Record<ApiSeverity, string> = {
  critical: "border-red-400/20 bg-red-400/10 text-red-300",
  high: "border-orange-400/20 bg-orange-400/10 text-orange-300",
  medium: "border-amber-400/20 bg-amber-400/10 text-amber-300",
  low: "border-sky-400/20 bg-sky-400/10 text-sky-300",
};
const CONTROL_STYLES = "h-10 rounded-md border border-border bg-background px-3 text-sm text-foreground outline-none transition-colors placeholder:text-muted/70 focus:border-accent/60 focus:ring-2 focus:ring-accent/20";

export function EventExplorer({ events }: { events: SecurityEventListItem[] }) {
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState<ApiSeverity | "unclassified" | "all">("all");
  const [detectionState, setDetectionState] = useState<"detected" | "observed" | "all">("all");
  const [category, setCategory] = useState("all");
  const categories = useMemo(() => [...new Set(events.map((event) => event.category))].sort(), [events]);
  const filteredEvents = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    return events.filter((event) => {
      const primaryDetection = event.detections[0];
      const searchable = [event.event_id, event.process, event.host, event.user, event.source_ip, event.destination_ip, event.command_line, event.category, primaryDetection?.title, primaryDetection?.rule_id]
        .filter(Boolean).join(" ").toLowerCase();
      const matchesSeverity = severity === "all" || (severity === "unclassified" ? !primaryDetection : primaryDetection?.severity === severity);
      const matchesState = detectionState === "all" || (detectionState === "detected" ? event.detections.length > 0 : event.detections.length === 0);
      return (!normalized || searchable.includes(normalized)) && matchesSeverity && matchesState && (category === "all" || event.category === category);
    });
  }, [category, detectionState, events, query, severity]);
  const hasFilters = query !== "" || severity !== "all" || detectionState !== "all" || category !== "all";
  function resetFilters() { setQuery(""); setSeverity("all"); setDetectionState("all"); setCategory("all"); }

  return <section aria-labelledby="event-stream-heading" className="rounded-lg border border-border bg-surface/20">
    <h2 id="event-stream-heading" className="sr-only">Security event stream</h2>
    <div className="border-b border-border p-4">
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-[minmax(280px,1fr)_170px_170px_190px_auto]">
        <div><label htmlFor="event-search" className="sr-only">Search security events</label><input id="event-search" type="search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search event, process, host, user, IP, or command…" className={`${CONTROL_STYLES} w-full`} /></div>
        <label className="sr-only" htmlFor="severity-filter">Severity</label><select id="severity-filter" value={severity} onChange={(event) => setSeverity(event.target.value as ApiSeverity | "unclassified" | "all")} className={CONTROL_STYLES}><option value="all">All severities</option><option value="unclassified">Unclassified</option>{SEVERITIES.map((value) => <option key={value} value={value}>{value[0].toUpperCase() + value.slice(1)}</option>)}</select>
        <label className="sr-only" htmlFor="state-filter">Detection state</label><select id="state-filter" value={detectionState} onChange={(event) => setDetectionState(event.target.value as "detected" | "observed" | "all")} className={CONTROL_STYLES}><option value="all">All states</option><option value="detected">Detected</option><option value="observed">Observed</option></select>
        <label className="sr-only" htmlFor="category-filter">Category</label><select id="category-filter" value={category} onChange={(event) => setCategory(event.target.value)} className={CONTROL_STYLES}><option value="all">All categories</option>{categories.map((value) => <option key={value}>{value}</option>)}</select>
        <button type="button" onClick={resetFilters} disabled={!hasFilters} className="h-10 rounded-md border border-border px-4 text-sm text-muted transition-colors hover:border-accent/40 hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:cursor-not-allowed disabled:opacity-40">Reset</button>
      </div>
      <p className="mt-3 text-xs text-muted" aria-live="polite">Showing <span className="font-mono text-foreground">{filteredEvents.length}</span> of {events.length} events</p>
    </div>
    {filteredEvents.length ? <div className="overflow-x-auto"><table className="w-full min-w-[980px] border-collapse text-left text-sm">
      <thead><tr className="border-b border-border font-mono text-[10px] uppercase tracking-[0.12em] text-muted">{["Classification", "Process / detection", "Category", "Host", "Time", "Risk", "State"].map((label) => <th key={label} scope="col" className="px-4 py-3 font-medium">{label}</th>)}</tr></thead>
      <tbody className="divide-y divide-border">{filteredEvents.map((event) => { const detection = event.detections[0]; return <tr key={event.event_id} className="transition-colors hover:bg-surface/50 focus-within:bg-surface/50">
        <td className="px-4 py-3.5">{detection ? <span className={`inline-flex rounded border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider ${SEVERITY_STYLES[detection.severity]}`}>{detection.severity}</span> : <span className="inline-flex rounded border border-border bg-background px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider text-muted">Unclassified</span>}</td>
        <td className="px-4 py-3.5"><Link href={`/app/security-events/${encodeURIComponent(event.event_id)}`} className="font-medium text-foreground hover:text-accent focus-visible:rounded-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent">{detection?.title ?? event.process ?? "Process creation"}</Link><p className="mt-1 max-w-xs truncate font-mono text-[10px] text-muted" title={event.event_id}>{event.event_id}</p></td>
        <td className="px-4 py-3.5 text-xs text-muted">{event.category}</td><td className="px-4 py-3.5 font-mono text-xs text-muted">{event.host ?? "Unknown host"}</td>
        <td className="px-4 py-3.5 font-mono text-xs tabular-nums text-muted"><time dateTime={event.timestamp}>{new Intl.DateTimeFormat("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }).format(new Date(event.timestamp))}</time></td>
        <td className="px-4 py-3.5">{detection ? <><span className={`font-mono text-sm font-semibold ${detection.risk_score >= 85 ? "text-red-300" : "text-amber-300"}`}>{detection.risk_score}</span><span className="text-[10px] text-muted">/100</span></> : <span className="text-xs text-muted">—</span>}</td>
        <td className={`px-4 py-3.5 text-xs font-medium ${detection ? "text-amber-300" : "text-muted"}`}>{detection ? "Detected" : "Observed"}</td>
      </tr>; })}</tbody>
    </table></div> : <div className="px-6 py-16 text-center"><p className="text-sm font-medium text-foreground">No events match these filters</p><p className="mt-1 text-sm text-muted">Adjust the search criteria or reset all filters.</p><button type="button" onClick={resetFilters} className="mt-4 rounded-md border border-border px-4 py-2 text-sm text-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent">Reset filters</button></div>}
  </section>;
}
