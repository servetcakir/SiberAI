import { SITE } from "@/lib/constants";

export function Hero() {
  return (
    <section
      aria-labelledby="hero-heading"
      className="relative flex min-h-[calc(100svh-4rem)] flex-col justify-center px-6 pb-20 pt-28"
    >
      <div className="mx-auto w-full max-w-4xl">
        <p className="mb-6 inline-flex items-center gap-2 font-mono text-xs uppercase tracking-[0.2em] text-accent">
          <span
            className="h-1.5 w-1.5 rounded-full bg-accent"
            aria-hidden="true"
          />
          Intelligent Security Analysis
        </p>

        <h1
          id="hero-heading"
          className="max-w-3xl text-4xl font-semibold leading-[1.1] tracking-tight text-foreground sm:text-5xl md:text-6xl lg:text-7xl"
        >
          See the signal in the noise.
        </h1>

        <p className="mt-6 max-w-2xl text-base leading-relaxed text-muted sm:text-lg">
          SiberAI is an AI-assisted cybersecurity platform designed to detect
          suspicious behavior, correlate security events, prioritize risk, and
          turn complex telemetry into understandable security insights.
        </p>

        <div className="mt-10 flex flex-col gap-3 sm:flex-row sm:items-center">
          <a
            href={SITE.githubUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex h-11 items-center justify-center rounded-md bg-accent px-6 text-sm font-medium text-background transition-colors hover:bg-accent/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2 focus-visible:ring-offset-background"
          >
            View on GitHub
          </a>
          <a
            href="#technology"
            className="inline-flex h-11 items-center justify-center rounded-md border border-border bg-surface/50 px-6 text-sm font-medium text-foreground transition-colors hover:border-accent/40 hover:bg-surface focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2 focus-visible:ring-offset-background"
          >
            Explore the Project
          </a>
        </div>

        <div
          className="mt-14 inline-flex items-center gap-3 rounded-full border border-border bg-surface/40 px-4 py-2 font-mono text-xs text-muted backdrop-blur-sm"
          role="status"
          aria-label="System status: in development"
        >
          <span className="relative flex h-2 w-2">
            <span className="absolute inline-flex h-full w-full animate-pulse-soft rounded-full bg-amber-400/60" />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-amber-400" />
          </span>
          <span className="uppercase tracking-wider">
            System Status — In Development
          </span>
        </div>
      </div>
    </section>
  );
}
