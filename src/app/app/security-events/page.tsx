import type { Metadata } from "next";
import { EventExplorer } from "@/components/app/EventExplorer";
import { getSecurityEvents, SiberAiApiError } from "@/lib/siberai-api";

export const metadata: Metadata = { title: "Security Events | SiberAI", description: "Review persisted SiberAI security telemetry and detections." };
export const dynamic = "force-dynamic";

function StatePanel({ title, children }: { title: string; children: React.ReactNode }) {
  return <section className="rounded-lg border border-border bg-surface/20 px-6 py-16 text-center"><h2 className="text-base font-semibold text-foreground">{title}</h2><p className="mx-auto mt-2 max-w-md text-sm leading-6 text-muted">{children}</p></section>;
}

export default async function SecurityEventsPage() {
  let events;
  try {
    events = await getSecurityEvents(100);
  } catch (error) {
    if (!(error instanceof SiberAiApiError)) throw error;
    return <main className="mx-auto min-h-screen max-w-[1600px] px-4 py-6 sm:px-6 lg:px-8 lg:py-8"><header className="mb-6 border-b border-border pb-6"><p className="font-mono text-[11px] uppercase tracking-[0.18em] text-accent">Event Stream</p><h1 className="mt-2 text-2xl font-semibold text-foreground">Security Events</h1></header><StatePanel title="Security engine unavailable">The SiberAI engine API could not be reached. Start the local engine API and refresh this page.</StatePanel></main>;
  }
  const detectedCount = events.filter((event) => event.detections.length > 0).length;
  const highPriorityCount = events.filter((event) => event.detections.some((detection) => detection.severity === "critical" || detection.severity === "high")).length;
  return <main className="mx-auto min-h-screen max-w-[1600px] px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
    <header className="mb-6 flex flex-col gap-4 border-b border-border pb-6 sm:flex-row sm:items-end sm:justify-between">
      <div><p className="font-mono text-[11px] uppercase tracking-[0.18em] text-accent">Event Stream</p><h1 className="mt-2 text-2xl font-semibold tracking-tight text-foreground">Security Events</h1><p className="mt-1 text-sm text-muted">Review persisted process telemetry and prioritize generated detections.</p></div>
      <dl className="flex gap-6 text-right"><div><dt className="text-xs text-muted">Recent events</dt><dd className="mt-1 font-mono text-lg text-foreground">{events.length}</dd></div><div><dt className="text-xs text-muted">Detected</dt><dd className="mt-1 font-mono text-lg text-amber-300">{detectedCount}</dd></div><div><dt className="text-xs text-muted">High priority</dt><dd className="mt-1 font-mono text-lg text-red-300">{highPriorityCount}</dd></div></dl>
    </header>
    {events.length ? <EventExplorer events={events} /> : <StatePanel title="No security events recorded yet.">Run the SiberAI engine watch mode to begin collecting local Sysmon process events.</StatePanel>}
  </main>;
}
