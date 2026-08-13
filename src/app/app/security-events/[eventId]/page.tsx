import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { getSecurityEvent, SiberAiApiError } from "@/lib/siberai-api";
import type { ApiSeverity } from "@/types/siberai-api";

const SEVERITY_STYLES: Record<ApiSeverity, string> = { critical: "border-red-400/20 bg-red-400/10 text-red-300", high: "border-orange-400/20 bg-orange-400/10 text-orange-300", medium: "border-amber-400/20 bg-amber-400/10 text-amber-300", low: "border-sky-400/20 bg-sky-400/10 text-sky-300" };
export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "Security Event | SiberAI" };

function Detail({ label, value, mono = true }: { label: string; value: string | number; mono?: boolean }) { return <div className="border-b border-border py-3 last:border-0"><dt className="text-xs text-muted">{label}</dt><dd className={`mt-1 break-words text-sm text-foreground ${mono ? "font-mono" : ""}`}>{value}</dd></div>; }

export default async function EventDetailPage({ params }: { params: Promise<{ eventId: string }> }) {
  const { eventId } = await params;
  let event;
  try { event = await getSecurityEvent(eventId); } catch (error) {
    if (!(error instanceof SiberAiApiError)) throw error;
    return <main className="mx-auto min-h-screen max-w-[1400px] px-4 py-6 sm:px-6 lg:px-8 lg:py-8"><Link href="/app/security-events" className="text-sm text-muted hover:text-accent">← Back to Security Events</Link><section className="mt-6 rounded-lg border border-border bg-surface/20 px-6 py-16 text-center"><h1 className="text-xl font-semibold text-foreground">Security engine unavailable</h1><p className="mt-2 text-sm text-muted">The event could not be loaded because the SiberAI engine API could not be reached.</p></section></main>;
  }
  if (!event) notFound();
  const primaryDetection = event.detections[0];
  const overview: Array<{ label: string; value: string | number }> = [
    { label: "Source type", value: event.source_type },
    { label: "Event category", value: event.category },
  ];
  if (event.record_id !== null) overview.unshift({ label: "Windows record ID", value: event.record_id });
  if (event.host !== null) overview.push({ label: "Host", value: event.host });
  if (event.user !== null) overview.push({ label: "User", value: event.user });
  const processEvidence = [{ label: "Process", value: event.process }, { label: "Parent process", value: event.parent_process }].filter((item): item is { label: string; value: string } => item.value !== null);
  const networkEvidence = [{ label: "Source IP", value: event.source_ip }, { label: "Destination IP", value: event.destination_ip }].filter((item): item is { label: string; value: string } => item.value !== null);
  return <main className="mx-auto min-h-screen max-w-[1400px] px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
    <Link href="/app/security-events" className="inline-flex items-center gap-2 text-sm text-muted hover:text-accent focus-visible:rounded focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"><span aria-hidden="true">←</span> Back to Security Events</Link>
    <header className="mt-5 border-b border-border pb-6"><div className="flex flex-wrap items-center gap-3">{primaryDetection ? <span className={`rounded border px-2.5 py-1 font-mono text-[10px] uppercase tracking-wider ${SEVERITY_STYLES[primaryDetection.severity]}`}>{primaryDetection.severity}</span> : <span className="rounded border border-border bg-background px-2.5 py-1 font-mono text-[10px] uppercase tracking-wider text-muted">Unclassified</span>}<span className="font-mono text-xs text-muted">{event.event_id}</span></div><h1 className="mt-3 max-w-4xl text-2xl font-semibold tracking-tight text-foreground sm:text-3xl">{primaryDetection?.title ?? event.process ?? "Process creation event"}</h1><dl className="mt-5 flex flex-wrap gap-x-8 gap-y-3 text-sm"><div><dt className="text-xs text-muted">Timestamp</dt><dd className="mt-1 font-mono text-foreground"><time dateTime={event.timestamp}>{new Intl.DateTimeFormat("en-US", { dateStyle: "medium", timeStyle: "long" }).format(new Date(event.timestamp))}</time></dd></div><div><dt className="text-xs text-muted">State</dt><dd className="mt-1 text-foreground">{primaryDetection ? "Detected" : "Observed"}</dd></div>{primaryDetection && <div><dt className="text-xs text-muted">Risk score</dt><dd className="mt-1 font-mono text-lg font-semibold text-red-300">{primaryDetection.risk_score}<span className="text-xs font-normal text-muted">/100</span></dd></div>}</dl></header>
    <div className="mt-6 grid gap-5 xl:grid-cols-[minmax(0,1.4fr)_minmax(340px,0.6fr)]"><div className="space-y-5">
      <section className="rounded-lg border border-border bg-surface/20"><div className="border-b border-border px-5 py-4"><h2 className="text-sm font-semibold text-foreground">Event Overview</h2></div><dl className="grid px-5 sm:grid-cols-2 sm:gap-x-8">{overview.map((item) => <Detail key={item.label} {...item} mono={item.label !== "Event category" && item.label !== "Source type"} />)}</dl></section>
      {(processEvidence.length > 0 || event.command_line) && <section className="rounded-lg border border-border bg-surface/20"><div className="border-b border-border px-5 py-4"><h2 className="text-sm font-semibold text-foreground">Process Evidence</h2></div><dl className="grid px-5 sm:grid-cols-2 sm:gap-x-8">{processEvidence.map((item) => <Detail key={item.label} {...item} />)}</dl>{event.command_line && <div className="border-t border-border px-5 py-4"><p className="text-xs text-muted">Command line</p><code className="mt-2 block [overflow-wrap:anywhere] rounded-md border border-border bg-background p-3 font-mono text-xs leading-6 text-foreground/90">{event.command_line}</code></div>}</section>}
      {networkEvidence.length > 0 && <section className="rounded-lg border border-border bg-surface/20"><div className="border-b border-border px-5 py-4"><h2 className="text-sm font-semibold text-foreground">Network Evidence</h2></div><dl className="grid px-5 sm:grid-cols-2 sm:gap-x-8">{networkEvidence.map((item) => <Detail key={item.label} {...item} />)}</dl></section>}
    </div><aside><section className="rounded-lg border border-border bg-surface/20"><div className="border-b border-border px-4 py-3.5"><h2 className="text-sm font-semibold text-foreground">Detection Analysis</h2><p className="mt-1 text-xs text-muted">Deterministic security rule output</p></div>{event.detections.length ? <ul className="divide-y divide-border">{event.detections.map((detection) => <li key={detection.detection_id} className="p-4"><div className="flex items-center justify-between gap-3"><span className={`rounded border px-2 py-0.5 font-mono text-[10px] uppercase ${SEVERITY_STYLES[detection.severity]}`}>{detection.severity}</span><span className="font-mono text-xs text-foreground">{detection.risk_score}/100</span></div><h3 className="mt-3 text-sm font-medium text-foreground">{detection.title}</h3><p className="mt-2 text-xs leading-5 text-muted">{detection.description}</p><dl className="mt-3 space-y-2 text-xs"><div><dt className="text-muted">Rule</dt><dd className="mt-0.5 font-mono text-accent">{detection.rule_id}</dd></div><div><dt className="text-muted">MITRE ATT&amp;CK</dt><dd className="mt-0.5 font-mono text-foreground">{detection.mitre_techniques.join(", ") || "No mapping"}</dd></div></dl></li>)}</ul> : <p className="px-4 py-6 text-sm leading-6 text-muted">No detection generated for this event. This does not establish that the activity is safe.</p>}</section></aside></div>
  </main>;
}
