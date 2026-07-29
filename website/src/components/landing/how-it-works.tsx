import { PRODUCT } from "@/lib/product";

const steps = [
  {
    n: "01",
    title: "Scan",
    body: `${PRODUCT.commands.scan} — discovers OpenClaw config and runs ${PRODUCT.checks} checks.`,
  },
  {
    n: "02",
    title: "Prove",
    body: "Score 0–100 with critical findings first. Critical findings hard-cap the score at 40.",
  },
  {
    n: "03",
    title: "Fix",
    body: `${PRODUCT.commands.fix} — safe remediations with .bak timestamps; behavioral changes prompt.`,
  },
  {
    n: "04",
    title: "Monitor",
    body: `${PRODUCT.commands.monitor} — compare to last scan. Paid: --start / --report.`,
  },
];

const sample = `$ ${PRODUCT.commands.scan}

  Clawhatch Security Scanner v${PRODUCT.version}

  Security Score: 40/100 (D — Poor)

  CRITICAL  API key(s) found in openclaw.json
  HIGH      Gateway bound to 0.0.0.0
  HIGH      No DM allowlist configured
  MEDIUM    Sandbox mode not enabled

  3 issue(s) can be auto-fixed → run with --fix`;

export function HowItWorks() {
  return (
    <section id="how" className="scroll-mt-20 border-t border-border py-20 sm:py-24">
      <div className="mx-auto max-w-6xl px-4 sm:px-6">
        <div className="max-w-2xl">
          <p className="text-sm font-medium text-primary">How it works</p>
          <h2 className="mt-2 text-3xl font-semibold tracking-tight text-fg sm:text-4xl">
            Same CLI as the GitHub repo
          </h2>
        </div>

        <ol className="mt-12 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {steps.map((s) => (
            <li
              key={s.n}
              className="relative rounded-xl border border-border bg-surface p-6"
            >
              <span className="font-mono text-xs font-medium text-primary">
                {s.n}
              </span>
              <h3 className="mt-3 text-lg font-semibold text-fg">{s.title}</h3>
              <p className="mt-2 text-sm leading-relaxed text-muted">{s.body}</p>
            </li>
          ))}
        </ol>

        <div className="mt-10 overflow-hidden rounded-xl border border-border bg-elevated">
          <div className="flex items-center justify-between border-b border-border px-4 py-2">
            <span className="font-mono text-xs text-subtle">terminal</span>
            <a
              href={PRODUCT.github}
              className="font-mono text-xs text-muted hover:text-fg"
              target="_blank"
              rel="noreferrer"
            >
              github.com/{PRODUCT.githubOwner}/{PRODUCT.githubRepo}
            </a>
          </div>
          <pre className="overflow-x-auto p-4 font-mono text-xs leading-relaxed text-muted sm:text-sm">
            <code>{sample}</code>
          </pre>
        </div>
      </div>
    </section>
  );
}
