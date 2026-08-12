import { SITE } from "@/lib/constants";

export function Terminal() {
  return (
    <section
      aria-labelledby="terminal-heading"
      className="border-t border-border/60 px-6 py-24"
    >
      <div className="mx-auto max-w-6xl">
        <h2 id="terminal-heading" className="sr-only">
          Project status terminal
        </h2>

        <div className="mx-auto max-w-xl overflow-hidden rounded-lg border border-border bg-[#0c1018] shadow-2xl shadow-black/20">
          <div className="flex items-center gap-2 border-b border-border px-4 py-3">
            <span className="h-2.5 w-2.5 rounded-full bg-border" aria-hidden="true" />
            <span className="h-2.5 w-2.5 rounded-full bg-border" aria-hidden="true" />
            <span className="h-2.5 w-2.5 rounded-full bg-border" aria-hidden="true" />
            <span className="ml-2 font-mono text-xs text-muted">siberai — status</span>
          </div>

          <pre
            className="overflow-x-auto p-5 font-mono text-sm leading-relaxed text-muted"
            aria-label="SiberAI project status output"
          >
            <code>
              <span className="text-accent">$</span> siberai status{"\n\n"}
              <span className="text-foreground/80">project</span>
              {"      "}
              {SITE.name}
              {"\n"}
              <span className="text-foreground/80">domain</span>
              {"       "}
              {SITE.domain}
              {"\n"}
              <span className="text-foreground/80">version</span>
              {"      "}
              {SITE.version}
              {"\n"}
              <span className="text-foreground/80">status</span>
              {"       "}
              in development
              {"\n\n"}
              <span className="text-accent">&gt;</span> building intelligent
              security analysis
              <span className="animate-blink text-accent">_</span>
            </code>
          </pre>
        </div>
      </div>
    </section>
  );
}
