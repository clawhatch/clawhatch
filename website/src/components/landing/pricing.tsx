import { Check } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { PRODUCT } from "@/lib/product";

const tiers = [
  {
    name: "Hatch (Free)",
    price: "Free",
    period: "",
    blurb: "Everything in the open CLI for manual posture.",
    cta: "Run free scan",
    href: "#cta",
    featured: false,
    features: [...PRODUCT.freeTier],
  },
  {
    name: "Nest (Paid)",
    price: "License",
    period: "",
    blurb: "Unlock continuous watch via ~/.clawhatch/license.key",
    cta: "Join waitlist",
    href: "#signup",
    featured: true,
    features: [...PRODUCT.paidTier, "Everything in free tier", "Tasteful upsell in CLI"],
  },
  {
    name: "Secure Hatch",
    price: "Custom",
    period: "",
    blurb: "Human-assisted hatch for teams and agencies.",
    cta: "Contact",
    href: "#signup",
    featured: false,
    features: [
      "Live or async hardening session",
      "Channel allowlist setup",
      "Policy pack for your fleet",
      "Written score report",
      "Design-partner roadmap",
    ],
  },
];

export function Pricing() {
  return (
    <section id="pricing" className="scroll-mt-20 border-t border-border py-20 sm:py-24">
      <div className="mx-auto max-w-6xl px-4 sm:px-6">
        <div className="mx-auto max-w-2xl text-center">
          <p className="text-sm font-medium text-primary">Pricing</p>
          <h2 className="mt-2 text-3xl font-semibold tracking-tight text-fg sm:text-4xl">
            Free to hatch. License to nest.
          </h2>
          <p className="mt-4 text-muted">
            Matches the freemium model in the GitHub README: manual scans free;
            scheduled monitoring and trend reports require a license key.
          </p>
        </div>

        <div className="mt-12 grid gap-4 lg:grid-cols-3">
          {tiers.map((t) => (
            <article
              key={t.name}
              className={cn(
                "relative flex flex-col rounded-xl border p-6 sm:p-8",
                t.featured
                  ? "border-primary/50 bg-surface shadow-lg shadow-primary/5"
                  : "border-border bg-surface",
              )}
            >
              {t.featured && (
                <Badge className="absolute -top-2.5 left-6">Paid tier</Badge>
              )}
              <h3 className="text-lg font-semibold text-fg">{t.name}</h3>
              <p className="mt-1 text-sm text-muted">{t.blurb}</p>
              <div className="mt-6 flex items-baseline gap-1">
                <span className="text-4xl font-semibold tracking-tight text-fg">
                  {t.price}
                </span>
                {t.period && (
                  <span className="text-sm text-muted">{t.period}</span>
                )}
              </div>
              <ul className="mt-6 flex flex-1 flex-col gap-3">
                {t.features.map((f) => (
                  <li
                    key={f}
                    className="flex items-start gap-2.5 text-sm text-muted"
                  >
                    <Check
                      className="mt-0.5 h-4 w-4 shrink-0 text-success"
                      aria-hidden
                    />
                    {f}
                  </li>
                ))}
              </ul>
              <Button
                className="mt-8 w-full"
                variant={t.featured ? "default" : "secondary"}
                asChild
              >
                <a href={t.href}>{t.cta}</a>
              </Button>
            </article>
          ))}
        </div>
        <p className="mt-6 text-center text-xs text-subtle">
          Source of truth:{" "}
          <a
            href={`${PRODUCT.github}#free-vs-paid`}
            className="hover:text-fg"
            target="_blank"
            rel="noreferrer"
          >
            README free vs paid
          </a>
          . npm may still serve v{PRODUCT.npmVersion} until you publish v
          {PRODUCT.version}.
        </p>
      </div>
    </section>
  );
}
