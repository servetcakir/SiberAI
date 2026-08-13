import Link from "next/link";

export default function EventNotFound() {
  return <main className="flex min-h-screen items-center justify-center px-4"><div className="max-w-md text-center"><p className="font-mono text-xs uppercase tracking-[0.2em] text-accent">Event unavailable</p><h1 className="mt-3 text-2xl font-semibold text-foreground">Security event not found</h1><p className="mt-2 text-sm leading-6 text-muted">The requested event does not exist in the current mock dataset.</p><Link href="/app/security-events" className="mt-6 inline-flex rounded-md border border-border px-4 py-2 text-sm text-foreground hover:border-accent/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent">Return to Security Events</Link></div></main>;
}
