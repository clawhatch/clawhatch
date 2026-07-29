import { Nav } from "@/components/landing/nav";
import { Hero } from "@/components/landing/hero";
import { Features } from "@/components/landing/features";
import { HowItWorks } from "@/components/landing/how-it-works";
import { Pricing } from "@/components/landing/pricing";
import { Signup } from "@/components/landing/signup";
import { Footer } from "@/components/landing/footer";

export function LandingPage() {
  return (
    <div className="min-h-svh w-full max-w-[100vw] overflow-x-hidden bg-bg">
      <Nav />
      <main className="w-full min-w-0">
        <Hero />
        <Features />
        <HowItWorks />
        <Pricing />
        <Signup />
      </main>
      <Footer />
    </div>
  );
}
