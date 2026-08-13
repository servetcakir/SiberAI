import type { Metadata } from "next";
import { EventExplorer } from "@/components/app/EventExplorer";
import { SECURITY_EVENTS } from "@/lib/security-events-mock-data";

export const metadata: Metadata = { title: "Security Events | SiberAI", description: "Review and prioritize SiberAI security events." };

export default function SecurityEventsPage() {
  const openCount = SECURITY_EVENTS.filter((event) => event.status === "Open" || event.status === "Investigating").length;
  const criticalCount = SECURITY_EVENTS.filter((event) => event.severity === "critical").length;
  return (
    <main className="mx-auto min-h-screen max-w-[1600px] px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
      <header className="mb-6 flex flex-col gap-4 border-b border-border pb-6 sm:flex-row sm:items-end sm:justify-between">
        <div><p className="font-mono text-[11px] uppercase tracking-[0.18em] text-accent">Event Stream</p><h1 className="mt-2 text-2xl font-semibold tracking-tight text-foreground">Security Events</h1><p className="mt-1 text-sm text-muted">Find and prioritize detections requiring analyst investigation.</p></div>
        <dl className="flex gap-6 text-right"><div><dt className="text-xs text-muted">In current view</dt><dd className="mt-1 font-mono text-lg text-foreground">{SECURITY_EVENTS.length}</dd></div><div><dt className="text-xs text-muted">Open / investigating</dt><dd className="mt-1 font-mono text-lg text-amber-300">{openCount}</dd></div><div><dt className="text-xs text-muted">Critical</dt><dd className="mt-1 font-mono text-lg text-red-300">{criticalCount}</dd></div></dl>
      </header>
      <EventExplorer events={SECURITY_EVENTS} />
    </main>
  );
}
