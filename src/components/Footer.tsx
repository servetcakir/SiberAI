import { LogoMark } from "@/components/LogoMark";
import { SITE } from "@/lib/constants";

export function Footer() {
  return (
    <footer className="border-t border-border/60 px-6 py-12">
      <div className="mx-auto flex max-w-6xl flex-col gap-8 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <div className="flex items-center gap-2.5">
            <LogoMark className="h-4 w-4 text-accent" />
            <span className="text-sm font-semibold text-foreground">
              {SITE.name}
            </span>
          </div>
          <p className="mt-2 text-sm text-muted">
            AI-Powered Cybersecurity Analysis
          </p>
          <p className="mt-4 text-xs text-muted/80">
            Currently in active development.
          </p>
        </div>

        <nav aria-label="Footer navigation">
          <ul className="flex flex-col gap-2 text-sm">
            <li>
              <a
                href={SITE.githubUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="text-muted transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2 focus-visible:ring-offset-background"
              >
                GitHub
              </a>
            </li>
            <li>
              <a
                href={SITE.url}
                className="text-muted transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2 focus-visible:ring-offset-background"
              >
                {SITE.domain}
              </a>
            </li>
          </ul>
        </nav>
      </div>
    </footer>
  );
}
