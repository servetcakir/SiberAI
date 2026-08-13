import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { getSecurityEvent, SECURITY_EVENTS } from "@/lib/security-events-mock-data";
import type { SecurityEvent, Severity } from "@/types/security";

const SEVERITY_STYLES: Record<Severity, string> = {
  critical: "border-red-400/20 bg-red-400/10 text-red-300", high: "border-orange-400/20 bg-orange-400/10 text-orange-300",
  medium: "border-amber-400/20 bg-amber-400/10 text-amber-300", low: "border-sky-400/20 bg-sky-400/10 text-sky-300",
};

export function generateStaticParams() { return SECURITY_EVENTS.map((event) => ({ eventId: event.id })); }

export async function generateMetadata({ params }: { params: Promise<{ eventId: string }> }): Promise<Metadata> {
  const { eventId } = await params; const event = getSecurityEvent(eventId);
  return { title: event ? `${event.id}: ${event.title} | SiberAI` : "Event Not Found | SiberAI" };
}

function Detail({ label, value, mono = true }: { label: string; value: string; mono?: boolean }) {
  return <div className="border-b border-border py-3 last:border-0"><dt className="text-xs text-muted">{label}</dt><dd className={`mt-1 break-words text-sm text-foreground ${mono ? "font-mono" : ""}`}>{value}</dd></div>;
}

export default async function EventDetailPage({ params }: { params: Promise<{ eventId: string }> }) {
  const { eventId } = await params; const event = getSecurityEvent(eventId); if (!event) notFound();
  const details: Array<{ label: string; value?: string; mono?: boolean }> = [
    { label: "Event category", value: event.category, mono: false }, { label: "Source type", value: event.sourceType, mono: false },
    { label: "Host / asset", value: event.asset }, { label: "Source IP", value: event.sourceIp }, { label: "Destination IP", value: event.destinationIp },
    { label: "User", value: event.user }, { label: "Process", value: event.processName }, { label: "Parent process", value: event.parentProcess },
  ];
  const related = (event.relatedEventIds ?? []).map(getSecurityEvent).filter((item): item is SecurityEvent => Boolean(item));
  return (
    <main className="mx-auto min-h-screen max-w-[1400px] px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
      <Link href="/app/security-events" className="inline-flex items-center gap-2 text-sm text-muted hover:text-accent focus-visible:rounded focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"><span aria-hidden="true">←</span> Back to Security Events</Link>
      <header className="mt-5 border-b border-border pb-6">
        <div className="flex flex-wrap items-center gap-3"><span className={`rounded border px-2.5 py-1 font-mono text-[10px] uppercase tracking-wider ${SEVERITY_STYLES[event.severity]}`}>{event.severity}</span><span className="font-mono text-xs text-muted">{event.id}</span></div>
        <h1 className="mt-3 max-w-4xl text-2xl font-semibold tracking-tight text-foreground sm:text-3xl">{event.title}</h1>
        <dl className="mt-5 flex flex-wrap gap-x-8 gap-y-3 text-sm"><div><dt className="text-xs text-muted">Timestamp</dt><dd className="mt-1 font-mono text-foreground"><time dateTime={event.timestamp}>{new Intl.DateTimeFormat("en-US", { dateStyle: "medium", timeStyle: "long" }).format(new Date(event.timestamp))}</time></dd></div><div><dt className="text-xs text-muted">Status</dt><dd className="mt-1 text-foreground">{event.status}</dd></div><div><dt className="text-xs text-muted">Risk score</dt><dd className="mt-1 font-mono text-lg font-semibold text-red-300">{event.riskScore}<span className="text-xs font-normal text-muted">/100</span></dd></div></dl>
      </header>

      <div className="mt-6 grid gap-5 xl:grid-cols-[minmax(0,1.45fr)_minmax(320px,0.55fr)]">
        <div className="space-y-5">
          <section aria-labelledby="summary-title" className="rounded-lg border border-border bg-surface/20 p-5"><h2 id="summary-title" className="text-sm font-semibold text-foreground">Event Summary</h2><p className="mt-3 text-sm leading-7 text-muted">{event.description}</p></section>
          <section aria-labelledby="evidence-title" className="rounded-lg border border-border bg-surface/20"><div className="border-b border-border px-5 py-4"><h2 id="evidence-title" className="text-sm font-semibold text-foreground">Evidence &amp; Event Details</h2><p className="mt-1 text-xs text-muted">Observed fields associated with this detection</p></div><dl className="grid px-5 sm:grid-cols-2 sm:gap-x-8">{details.filter((item) => item.value).map((item) => <Detail key={item.label} label={item.label} value={item.value!} mono={item.mono} />)}</dl>{event.commandLine && <div className="border-t border-border px-5 py-4"><p className="text-xs text-muted">Command line</p><code className="mt-2 block [overflow-wrap:anywhere] rounded-md border border-border bg-background p-3 font-mono text-xs leading-6 text-foreground/90">{event.commandLine}</code></div>}</section>
          <section aria-labelledby="rule-title" className="rounded-lg border border-border bg-surface/20 p-5"><h2 id="rule-title" className="text-sm font-semibold text-foreground">Detection</h2><dl className="mt-3 grid gap-4 sm:grid-cols-2"><div><dt className="text-xs text-muted">Rule ID</dt><dd className="mt-1 font-mono text-sm text-accent">{event.detectionRule.id}</dd></div><div><dt className="text-xs text-muted">Rule name</dt><dd className="mt-1 text-sm text-foreground">{event.detectionRule.name}</dd></div></dl></section>
        </div>
        <aside className="space-y-5">
          <section aria-labelledby="mitre-title" className="rounded-lg border border-border bg-surface/20"><div className="border-b border-border px-4 py-3.5"><h2 id="mitre-title" className="text-sm font-semibold text-foreground">MITRE ATT&amp;CK</h2></div>{event.mitreTechniques?.length ? <ul className="divide-y divide-border">{event.mitreTechniques.map((technique) => <li key={technique.id} className="px-4 py-3"><span className="font-mono text-xs text-accent">{technique.id}</span><p className="mt-1 text-sm text-foreground">{technique.name}</p></li>)}</ul> : <p className="px-4 py-5 text-sm text-muted">No technique mapped to this event.</p>}</section>
          <section aria-labelledby="related-title" className="rounded-lg border border-border bg-surface/20"><div className="border-b border-border px-4 py-3.5"><h2 id="related-title" className="text-sm font-semibold text-foreground">Related Events</h2><p className="mt-1 text-xs text-muted">Mock correlation relationships</p></div>{related.length ? <ul className="divide-y divide-border">{related.map((item) => <li key={item.id}><Link href={`/app/security-events/${item.id}`} className="block px-4 py-3 transition-colors hover:bg-surface/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent"><div className="flex items-center justify-between gap-3"><span className="font-mono text-xs text-accent">{item.id}</span><span className="text-xs capitalize text-muted">{item.severity}</span></div><p className="mt-1.5 text-sm leading-5 text-foreground">{item.title}</p></Link></li>)}</ul> : <p className="px-4 py-5 text-sm text-muted">No related events identified.</p>}</section>
          <section aria-labelledby="analysis-title" className="rounded-lg border border-dashed border-border p-4"><h2 id="analysis-title" className="text-sm font-medium text-foreground">AI Analysis</h2><p className="mt-2 text-xs leading-5 text-muted">Automated event analysis will be available in a future phase.</p></section>
        </aside>
      </div>
    </main>
  );
}
