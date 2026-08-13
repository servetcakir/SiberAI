import type { Metadata } from "next";
import { AppNavigation } from "@/components/app/AppNavigation";

export const metadata: Metadata = {
  title: "Security Overview | SiberAI",
  description: "SiberAI security operations overview.",
  alternates: {
    canonical: "/app",
  },
  robots: {
    index: false,
    follow: false,
  },
};

export default function ProductLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-[#080d15] text-foreground">
      <AppNavigation />
      <div className="lg:pl-64">{children}</div>
    </div>
  );
}
