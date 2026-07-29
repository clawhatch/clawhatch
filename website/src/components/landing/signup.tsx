import { Button } from "@/components/ui/button";
import { CommandBlock } from "@/components/landing/command-block";
import { BRAND } from "@/lib/brand";

export function Signup() {
  return (
    <section
      id="signup"
      className="scroll-mt-20 border-t border-border py-20 sm:py-24"
    >
      <div className="mx-auto max-w-6xl px-4 sm:px-6">
        <div className="grid gap-10 overflow-hidden rounded-2xl border border-border bg-surface lg:grid-cols-2">
          <div className="flex flex-col justify-center p-8 sm:p-10 lg:p-12">
            <h2 className="text-2xl font-semibold tracking-tight text-fg sm:text-3xl">
              Hatch now. Nest when you are ready.
            </h2>
            <p className="mt-3 text-muted leading-relaxed">
              Get Nest early access, threat-feed notes, and secure-hatch
              slots. Or skip the form and scan offline in one command.
            </p>

            <div className="mt-8 space-y-3">
              <Button asChild>
                <a href={`mailto:${BRAND.email}?subject=ClawHatch%20early%20access`}>
                  Request early access
                </a>
              </Button>
              <p className="text-xs text-subtle">
                This opens your email app. Contact{" "}
                <a
                  href={`mailto:${BRAND.email}`}
                  className="text-muted underline-offset-2 hover:text-fg hover:underline"
                >
                  {BRAND.email}
                </a>
                {" "}directly if you prefer. Manual scans stay free.
              </p>
            </div>
          </div>

          <div className="flex flex-col justify-center border-t border-border bg-elevated/50 p-8 sm:p-10 lg:border-t-0 lg:border-l lg:p-12">
            <p className="text-sm font-medium text-fg">Prefer zero signup?</p>
            <p className="mt-2 text-sm text-muted">
              The product is the command. Prove posture on your machine first.
            </p>
            <CommandBlock className="mt-6 max-w-none" />
            <a
              id="docs"
              href={BRAND.github}
              target="_blank"
              rel="noreferrer"
              className="mt-6 text-sm text-muted underline-offset-4 hover:text-fg hover:underline"
            >
              Read the docs on GitHub
            </a>
          </div>
        </div>
      </div>
    </section>
  );
}
