import { Badge } from "@/components/ui/badge";
import { CommandBlock } from "@/components/landing/command-block";
import { PRODUCT } from "@/lib/product";
import { ShieldCheck, Zap, Lock, Github } from "lucide-react";

export function Hero() {
  return (
    <section
      id="top"
      className="relative overflow-hidden pt-28 pb-16 sm:pt-32 sm:pb-24"
    >
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_80%_50%_at_50%_-20%,color-mix(in_oklab,var(--color-primary)_18%,transparent),transparent)]"
      />
      <div
        aria-hidden
        className="pointer-events-none absolute inset-x-0 bottom-0 h-px bg-gradient-to-r from-transparent via-border to-transparent"
      />

      <div className="relative mx-auto grid max-w-6xl items-center gap-12 px-4 sm:px-6 lg:grid-cols-2 lg:gap-16">
        <div className="flex flex-col items-start">
          <div className="mb-5 flex flex-wrap items-center gap-2">
            <Badge>OpenClaw security · local-first</Badge>
            <Badge variant="secondary" className="font-mono text-[10px]">
              v{PRODUCT.version}
            </Badge>
          </div>
          <h1 className="text-balance text-4xl font-semibold tracking-tight text-fg sm:text-5xl lg:text-[3.25rem] lg:leading-[1.08]">
            OpenClaw,{" "}
            <span className="text-primary">born secure.</span>
          </h1>
          <p className="mt-5 max-w-lg text-base leading-relaxed text-muted sm:text-lg">
            Your agent is probably already exposed — keys in config, open DMs,
            no sandbox. Score and fix it in under a second. No account. Nothing
            leaves your machine.
          </p>

          <div className="mt-8 w-full" id="cta">
            <CommandBlock />
            <p className="mt-3 text-xs text-subtle">
              Paste in your terminal. Free forever for manual scans · MIT ·{" "}
              <a
                href={PRODUCT.github}
                className="text-muted underline-offset-2 hover:text-fg hover:underline"
                target="_blank"
                rel="noreferrer"
              >
                source on GitHub
              </a>
            </p>
          </div>

          <ul className="mt-8 flex flex-wrap gap-x-5 gap-y-3 text-sm text-muted">
            <li className="inline-flex items-center gap-2">
              <Zap className="h-4 w-4 text-primary" aria-hidden />
              Under 1 second
            </li>
            <li className="inline-flex items-center gap-2">
              <ShieldCheck className="h-4 w-4 text-primary" aria-hidden />
              {PRODUCT.checks} automated checks
            </li>
            <li className="inline-flex items-center gap-2">
              <Lock className="h-4 w-4 text-primary" aria-hidden />
              100% offline
            </li>
            <li className="inline-flex items-center gap-2">
              <Github className="h-4 w-4 text-primary" aria-hidden />
              <a
                href={PRODUCT.github}
                className="hover:text-fg"
                target="_blank"
                rel="noreferrer"
              >
                {PRODUCT.githubOwner}/{PRODUCT.githubRepo}
              </a>
            </li>
          </ul>
        </div>

        <div className="relative mx-auto w-full max-w-md lg:max-w-none">
          <div className="absolute -inset-4 rounded-2xl bg-primary/10 blur-2xl" aria-hidden />
          <div className="relative overflow-hidden rounded-xl border border-border bg-surface shadow-2xl shadow-black/50">
            <img
              src="/claw-hero.jpeg"
              alt="Red mechanical claw hatching from a cracked egg — ClawHatch brand mark"
              className="aspect-[4/3] w-full object-cover object-center"
              width={800}
              height={600}
            />
            <div className="border-t border-border bg-elevated/90 px-4 py-3">
              <div className="flex items-center justify-between gap-3 font-mono text-xs">
                <span className="text-subtle">
                  Security score · CLI v{PRODUCT.version}
                </span>
                <span className="text-success">
                  93 / {PRODUCT.scoreMax} · A+
                </span>
              </div>
              <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-border">
                <div className="h-full w-[93%] rounded-full bg-success" />
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
