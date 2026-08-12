type DevStatus = "Research" | "In Development" | "Planned";

const DEVELOPMENT_AREAS: { name: string; status: DevStatus }[] = [
  { name: "Network intrusion detection", status: "In Development" },
  { name: "Machine-learning experimentation", status: "In Development" },
  { name: "Security event processing", status: "In Development" },
  { name: "Event correlation", status: "Research" },
  { name: "Risk scoring", status: "Research" },
  { name: "AI-assisted analysis", status: "Planned" },
  { name: "Web-based security dashboard", status: "Planned" },
];

const STATUS_STYLES: Record<DevStatus, string> = {
  Research:
    "border-sky-500/20 bg-sky-500/10 text-sky-300",
  "In Development":
    "border-amber-500/20 bg-amber-500/10 text-amber-300",
  Planned:
    "border-border bg-background/60 text-muted",
};

export function DevelopmentStatus() {
  return (
    <section
      id="about"
      aria-labelledby="development-heading"
      className="border-t border-border/60 px-6 py-24"
    >
      <div className="mx-auto max-w-6xl">
        <div className="grid gap-12 lg:grid-cols-[1fr_1.1fr] lg:items-start">
          <div>
            <p className="mb-3 font-mono text-xs uppercase tracking-[0.2em] text-accent">
              Development
            </p>
            <h2
              id="development-heading"
              className="text-2xl font-semibold tracking-tight text-foreground sm:text-3xl"
            >
              Building SiberAI
            </h2>
            <p className="mt-4 leading-relaxed text-muted">
              SiberAI is currently being developed as an applied cybersecurity
              and machine-learning project. The focus is on building practical
              detection, correlation, and analysis capabilities — not marketing
              demos or simulated threat data.
            </p>
            <p className="mt-4 leading-relaxed text-muted">
              Progress is tracked honestly. Areas below reflect the current
              development focus and roadmap.
            </p>
          </div>

          <ul className="divide-y divide-border rounded-xl border border-border bg-surface/20">
            {DEVELOPMENT_AREAS.map((area) => (
              <li
                key={area.name}
                className="flex flex-col gap-2 px-5 py-4 sm:flex-row sm:items-center sm:justify-between"
              >
                <span className="text-sm text-foreground">{area.name}</span>
                <span
                  className={`inline-flex w-fit shrink-0 rounded-full border px-2.5 py-0.5 font-mono text-[10px] uppercase tracking-wider ${STATUS_STYLES[area.status]}`}
                >
                  {area.status}
                </span>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </section>
  );
}
