"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { LogoMark } from "@/components/LogoMark";
import { SITE } from "@/lib/constants";

const NAV_ITEMS = [
  { label: "Overview", href: "/app", icon: "overview" },
  { label: "Security Events", href: "/app/security-events", icon: "events" },
  { label: "AI Analysis", icon: "analysis" },
  { label: "Assets", icon: "assets" },
  { label: "AI Analyst", icon: "analyst" },
  { label: "Settings", icon: "settings" },
] as const;

function NavigationIcon({ name }: { name: (typeof NAV_ITEMS)[number]["icon"] }) {
  const common = {
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 1.5,
    strokeLinecap: "round" as const,
    strokeLinejoin: "round" as const,
  };

  return (
    <svg aria-hidden="true" viewBox="0 0 24 24" className="h-4 w-4 shrink-0">
      {name === "overview" && (
        <>
          <rect x="3" y="3" width="7" height="7" rx="1" {...common} />
          <rect x="14" y="3" width="7" height="7" rx="1" {...common} />
          <rect x="3" y="14" width="7" height="7" rx="1" {...common} />
          <rect x="14" y="14" width="7" height="7" rx="1" {...common} />
        </>
      )}
      {name === "events" && (
        <>
          <path d="M12 3 3.5 19h17L12 3Z" {...common} />
          <path d="M12 9v4M12 16.5h.01" {...common} />
        </>
      )}
      {name === "analysis" && (
        <>
          <path d="M4 19V9M10 19V5M16 19v-7M22 19V3" {...common} />
          <path d="M2 19h20" {...common} />
        </>
      )}
      {name === "assets" && (
        <>
          <rect x="3" y="4" width="18" height="13" rx="2" {...common} />
          <path d="M8 21h8M12 17v4" {...common} />
        </>
      )}
      {name === "analyst" && (
        <>
          <path d="M5 18.5 3 21l.7-3.7A8 8 0 1 1 7 20" {...common} />
          <path d="M8.5 12h.01M12 12h.01M15.5 12h.01" {...common} />
        </>
      )}
      {name === "settings" && (
        <>
          <circle cx="12" cy="12" r="3" {...common} />
          <path d="M19 12a7 7 0 0 0-.1-1l2-1.5-2-3.4-2.4 1a8 8 0 0 0-1.8-1L14.4 3h-4.8l-.4 3.1a8 8 0 0 0-1.8 1l-2.4-1-2 3.4L5.1 11a7 7 0 0 0 0 2L3 14.5l2 3.4 2.4-1a8 8 0 0 0 1.8 1l.4 3.1h4.8l.4-3.1a8 8 0 0 0 1.8-1l2.4 1 2-3.4-2.1-1.5a7 7 0 0 0 .1-1Z" {...common} />
        </>
      )}
    </svg>
  );
}

function NavigationItems() {
  const pathname = usePathname();

  return NAV_ITEMS.map((item) => {
    const isActive = "href" in item && (
      item.href === "/app" ? pathname === "/app" : pathname.startsWith(item.href)
    );
    const content = (
      <>
        <NavigationIcon name={item.icon} />
        <span>{item.label}</span>
        {!("href" in item) && (
          <span className="ml-auto rounded border border-border px-1.5 py-0.5 font-mono text-[8px] uppercase tracking-wider text-muted/70">
            Soon
          </span>
        )}
      </>
    );

    return "href" in item ? (
      <Link
        key={item.label}
        href={item.href}
        aria-current={isActive ? "page" : undefined}
        className={`flex h-10 shrink-0 items-center gap-3 rounded-md px-3 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent ${
          isActive
            ? "border border-accent/15 bg-accent/[0.08] font-medium text-accent"
            : "border border-transparent text-muted transition-colors hover:bg-surface/50 hover:text-foreground"
        }`}
      >
        {content}
      </Link>
    ) : (
      <span
        key={item.label}
        aria-disabled="true"
        className="flex h-10 shrink-0 cursor-not-allowed items-center gap-3 rounded-md px-3 text-sm text-muted/60"
      >
        {content}
      </span>
    );
  });
}

export function AppNavigation() {
  return (
    <>
      <aside className="fixed inset-y-0 left-0 z-40 hidden w-64 border-r border-border bg-[#080d15] lg:flex lg:flex-col">
        <div className="flex h-16 items-center border-b border-border px-5">
          <Link
            href="/"
            className="flex items-center gap-2.5 text-sm font-semibold text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          >
            <LogoMark className="h-5 w-5 text-accent" />
            {SITE.name}
            <span className="font-mono text-[9px] uppercase tracking-widest text-muted">Console</span>
          </Link>
        </div>

        <nav aria-label="Application navigation" className="flex-1 px-3 py-5">
          <p className="mb-2 px-3 font-mono text-[9px] uppercase tracking-[0.2em] text-muted/70">
            Workspace
          </p>
          <div className="space-y-1">
            <NavigationItems />
          </div>
        </nav>

        <div className="border-t border-border p-4">
          <div className="rounded-md border border-border bg-surface/30 p-3">
            <div className="flex items-center gap-2 text-xs text-foreground">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" aria-hidden="true" />
              Collection operational
            </div>
            <p className="mt-1.5 font-mono text-[10px] text-muted">3 data sources · 142 assets</p>
          </div>
        </div>
      </aside>

      <header className="sticky top-0 z-40 border-b border-border bg-[#080d15]/95 backdrop-blur lg:hidden">
        <div className="flex h-14 items-center justify-between px-4">
          <Link
            href="/"
            className="flex items-center gap-2 text-sm font-semibold text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          >
            <LogoMark className="h-5 w-5 text-accent" />
            {SITE.name}
          </Link>
          <span className="font-mono text-[9px] uppercase tracking-[0.18em] text-muted">Security Console</span>
        </div>
        <nav aria-label="Application navigation" className="overflow-x-auto border-t border-border px-3 py-2">
          <div className="flex w-max gap-1">
            <NavigationItems />
          </div>
        </nav>
      </header>
    </>
  );
}
