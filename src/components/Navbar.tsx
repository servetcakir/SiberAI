import { LogoMark } from "@/components/LogoMark";
import { NAV_LINKS, SITE } from "@/lib/constants";

export function Navbar() {
  return (
    <header className="fixed inset-x-0 top-0 z-50 border-b border-border/60 bg-background/70 backdrop-blur-md">
      <nav
        aria-label="Main navigation"
        className="mx-auto flex h-16 max-w-6xl items-center justify-between px-6"
      >
        <a
          href="#"
          className="group flex items-center gap-2.5 text-sm font-semibold tracking-tight text-foreground transition-colors hover:text-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2 focus-visible:ring-offset-background"
        >
          <LogoMark className="h-5 w-5 text-accent transition-transform group-hover:scale-105" />
          <span>{SITE.name}</span>
        </a>

        <div className="flex items-center gap-4 sm:gap-6">
          <ul className="hidden items-center gap-6 sm:flex">
            {NAV_LINKS.map((link) => (
              <li key={link.label}>
                <a
                  href={link.href}
                  {...("external" in link && link.external
                    ? { target: "_blank", rel: "noopener noreferrer" }
                    : {})}
                  className="text-sm text-muted transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2 focus-visible:ring-offset-background"
                >
                  {link.label}
                </a>
              </li>
            ))}
          </ul>

          <span
            className="hidden rounded-full border border-border bg-surface px-2.5 py-1 font-mono text-[10px] font-medium uppercase tracking-wider text-muted sm:inline-block"
            aria-label={`Version ${SITE.version}, currently in development`}
          >
            v{SITE.version} • Development
          </span>

          <details className="relative sm:hidden">
            <summary className="cursor-pointer list-none rounded-md border border-border px-2.5 py-1.5 text-xs text-muted [&::-webkit-details-marker]:hidden">
              Menu
            </summary>
            <ul className="absolute right-0 mt-2 w-40 rounded-lg border border-border bg-surface p-2 shadow-lg">
              {NAV_LINKS.map((link) => (
                <li key={link.label}>
                  <a
                    href={link.href}
                    {...("external" in link && link.external
                      ? { target: "_blank", rel: "noopener noreferrer" }
                      : {})}
                    className="block rounded-md px-3 py-2 text-sm text-muted transition-colors hover:bg-background hover:text-foreground"
                  >
                    {link.label}
                  </a>
                </li>
              ))}
            </ul>
          </details>
        </div>
      </nav>
    </header>
  );
}
