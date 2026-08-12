export const SITE = {
  name: "SiberAI",
  domain: "siberai.dev",
  url: "https://siberai.dev",
  version: "0.1",
  githubUrl: "https://github.com/servetcakir/SiberAI",
} as const;

export const NAV_LINKS = [
  { label: "About", href: "#about" },
  { label: "Technology", href: "#technology" },
  { label: "GitHub", href: SITE.githubUrl, external: true },
] as const;
