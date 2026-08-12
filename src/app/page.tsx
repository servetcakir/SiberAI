import { Architecture } from "@/components/Architecture";
import { DevelopmentStatus } from "@/components/DevelopmentStatus";
import { Footer } from "@/components/Footer";
import { Hero } from "@/components/Hero";
import { Navbar } from "@/components/Navbar";
import { NetworkBackground } from "@/components/NetworkBackground";
import { TechnologyCards } from "@/components/TechnologyCards";
import { Terminal } from "@/components/Terminal";

export default function Home() {
  return (
    <>
      <Navbar />

      <div className="relative isolate overflow-hidden">
        <div aria-hidden="true" className="grid-pattern pointer-events-none absolute inset-0" />
        <NetworkBackground />

        <div className="pointer-events-none absolute inset-x-0 top-0 h-[50vh] bg-gradient-to-b from-accent/[0.03] to-transparent" aria-hidden="true" />

        <main>
          <Hero />
          <TechnologyCards />
          <Architecture />
          <DevelopmentStatus />
          <Terminal />
        </main>
      </div>

      <Footer />
    </>
  );
}
