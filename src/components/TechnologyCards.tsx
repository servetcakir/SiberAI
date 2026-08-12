const TECHNOLOGIES = [
  {
    title: "Machine Learning",
    description:
      "Identify anomalous patterns and suspicious behavior across security telemetry.",
    icon: (
      <svg
        aria-hidden="true"
        viewBox="0 0 24 24"
        fill="none"
        className="h-6 w-6"
      >
        <path
          d="M4 18V6M4 12H8M8 18V6M8 12H12M12 18V6M12 12H16M16 18V6M16 12H20M20 18V6"
          stroke="currentColor"
          strokeWidth="1.5"
          strokeLinecap="round"
        />
      </svg>
    ),
  },
  {
    title: "Event Correlation",
    description:
      "Connect related security events to reveal patterns that individual alerts may miss.",
    icon: (
      <svg
        aria-hidden="true"
        viewBox="0 0 24 24"
        fill="none"
        className="h-6 w-6"
      >
        <circle cx="6" cy="12" r="2.5" stroke="currentColor" strokeWidth="1.5" />
        <circle cx="18" cy="6" r="2.5" stroke="currentColor" strokeWidth="1.5" />
        <circle cx="18" cy="18" r="2.5" stroke="currentColor" strokeWidth="1.5" />
        <path
          d="M8.5 11L15.5 7M8.5 13L15.5 17"
          stroke="currentColor"
          strokeWidth="1.5"
          strokeLinecap="round"
        />
      </svg>
    ),
  },
  {
    title: "AI Analysis",
    description:
      "Transform complex security findings into clear incident explanations and investigation guidance.",
    icon: (
      <svg
        aria-hidden="true"
        viewBox="0 0 24 24"
        fill="none"
        className="h-6 w-6"
      >
        <path
          d="M12 3L14.5 9.5L21 12L14.5 14.5L12 21L9.5 14.5L3 12L9.5 9.5L12 3Z"
          stroke="currentColor"
          strokeWidth="1.5"
          strokeLinejoin="round"
        />
      </svg>
    ),
  },
] as const;

export function TechnologyCards() {
  return (
    <section
      id="technology"
      aria-labelledby="technology-heading"
      className="border-t border-border/60 px-6 py-24"
    >
      <div className="mx-auto max-w-6xl">
        <div className="mb-12 max-w-2xl">
          <p className="mb-3 font-mono text-xs uppercase tracking-[0.2em] text-accent">
            Core Technology
          </p>
          <h2
            id="technology-heading"
            className="text-2xl font-semibold tracking-tight text-foreground sm:text-3xl"
          >
            Intelligent analysis across the security stack
          </h2>
          <p className="mt-3 text-muted">
            Planned capabilities being developed as part of the SiberAI platform.
          </p>
        </div>

        <ul className="grid gap-4 md:grid-cols-3">
          {TECHNOLOGIES.map((tech) => (
            <li
              key={tech.title}
              className="group rounded-lg border border-border bg-surface/30 p-6 transition-colors hover:border-accent/30 hover:bg-surface/60"
            >
              <div className="mb-4 inline-flex rounded-md border border-border bg-background/60 p-2.5 text-accent transition-colors group-hover:border-accent/30">
                {tech.icon}
              </div>
              <h3 className="text-lg font-medium text-foreground">
                {tech.title}
              </h3>
              <p className="mt-2 text-sm leading-relaxed text-muted">
                {tech.description}
              </p>
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}
