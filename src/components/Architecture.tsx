const PIPELINE_STEPS = [
  "Security Telemetry",
  "Data Processing",
  "Rule + ML Detection",
  "Event Correlation",
  "Risk Scoring",
  "AI Analyst",
  "Security Insight",
] as const;

export function Architecture() {
  return (
    <section
      id="architecture"
      aria-labelledby="architecture-heading"
      className="border-t border-border/60 px-6 py-24"
    >
      <div className="mx-auto max-w-6xl">
        <div className="mb-12 max-w-2xl">
          <p className="mb-3 font-mono text-xs uppercase tracking-[0.2em] text-accent">
            Architecture
          </p>
          <h2
            id="architecture-heading"
            className="text-2xl font-semibold tracking-tight text-foreground sm:text-3xl"
          >
            Planned SiberAI pipeline
          </h2>
          <p className="mt-3 text-muted">
            A simplified view of the intended analysis flow. Components are
            under active development and subject to change.
          </p>
        </div>

        <div className="overflow-hidden rounded-xl border border-border bg-surface/20 p-6 sm:p-8">
          {/* Mobile: vertical pipeline */}
          <ol className="flex flex-col md:hidden">
            {PIPELINE_STEPS.map((step, index) => (
              <li key={step} className="flex flex-col items-center">
                <div className="flex w-full max-w-xs items-center gap-4">
                  <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-md border border-border bg-surface font-mono text-xs text-accent">
                    {String(index + 1).padStart(2, "0")}
                  </div>
                  <p className="text-sm font-medium text-foreground">{step}</p>
                </div>
                {index < PIPELINE_STEPS.length - 1 && (
                  <div
                    aria-hidden="true"
                    className="my-2 h-8 w-px bg-gradient-to-b from-border via-accent/30 to-border"
                  />
                )}
              </li>
            ))}
          </ol>

          {/* Desktop: horizontal pipeline */}
          <ol className="hidden md:flex md:items-start md:justify-between">
            {PIPELINE_STEPS.map((step, index) => (
              <li
                key={step}
                className="relative flex flex-1 flex-col items-center px-1"
              >
                <div className="flex h-10 w-10 items-center justify-center rounded-md border border-border bg-surface font-mono text-xs text-accent">
                  {String(index + 1).padStart(2, "0")}
                </div>
                <p className="mt-3 max-w-[6.5rem] text-center text-xs font-medium leading-snug text-foreground lg:max-w-[7.5rem] lg:text-sm">
                  {step}
                </p>
                {index < PIPELINE_STEPS.length - 1 && (
                  <div
                    aria-hidden="true"
                    className="absolute left-[calc(50%+1.25rem)] top-5 h-px w-[calc(100%-2.5rem)] bg-gradient-to-r from-accent/20 via-accent/40 to-accent/20"
                  />
                )}
              </li>
            ))}
          </ol>
        </div>
      </div>
    </section>
  );
}
