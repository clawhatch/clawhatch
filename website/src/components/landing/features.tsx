import {
  ScanSearch,
  Wrench,
  Shield,
  Eye,
  GitBranch,
  KeyRound,
} from "lucide-react";
import { PRODUCT } from "@/lib/product";

const features = [
  {
    icon: ScanSearch,
    title: "Config-aware scanning",
    body: `${PRODUCT.checks} automated checks across identity, network, sandbox, secrets, tools, skills, model, data, and ops — tuned to OpenClaw, not a generic linter.`,
  },
  {
    icon: Wrench,
    title: "Auto-fix with backups",
    body: "`--fix` moves keys to .env, tightens tokens, updates gitignore. Safe fixes apply automatically; behavioral changes prompt first. Timestamped .bak every time.",
  },
  {
    icon: Shield,
    title: "Hardened init",
    body: "`clawhatch init` generates a secure baseline so your claw is born with better defaults — setup and security as one motion.",
  },
  {
    icon: KeyRound,
    title: "Identity first",
    body: "15 identity checks: DM policies, allowlists, pairing, access groups, OAuth — who can trigger before what the model thinks.",
  },
  {
    icon: Eye,
    title: "Monitor + history",
    body: "`clawhatch monitor` compares to last scan. Free: manual + history. Paid license unlocks scheduled monitoring, trends, and alerts.",
  },
  {
    icon: GitBranch,
    title: "CI-ready output",
    body: "`--json`, `--format html`, `--quiet`, exit codes. Drop into GitHub Actions without an account. See the repo README for the workflow.",
  },
];

export function Features() {
  return (
    <section id="features" className="scroll-mt-20 border-t border-border py-20 sm:py-24">
      <div className="mx-auto max-w-6xl px-4 sm:px-6">
        <div className="max-w-2xl">
          <p className="text-sm font-medium text-primary">Features</p>
          <h2 className="mt-2 text-3xl font-semibold tracking-tight text-fg sm:text-4xl">
            What ships in{" "}
            <span className="font-mono text-primary">v{PRODUCT.version}</span>
          </h2>
          <p className="mt-4 text-muted leading-relaxed">
            Tracked to the open-source CLI on{" "}
            <a
              href={PRODUCT.github}
              className="text-fg underline-offset-2 hover:underline"
              target="_blank"
              rel="noreferrer"
            >
              github.com/{PRODUCT.githubOwner}/{PRODUCT.githubRepo}
            </a>
            . Same commands, same freemium split as the README.
          </p>
        </div>

        <div className="mt-12 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {features.map((f) => (
            <article
              key={f.title}
              className="rounded-xl border border-border bg-surface p-6 transition-colors hover:border-border-strong"
            >
              <div className="mb-4 flex h-10 w-10 items-center justify-center rounded-lg border border-border bg-elevated">
                <f.icon className="h-5 w-5 text-primary" aria-hidden />
              </div>
              <h3 className="text-base font-semibold text-fg">{f.title}</h3>
              <p className="mt-2 text-sm leading-relaxed text-muted">{f.body}</p>
            </article>
          ))}
        </div>

        <div className="mt-10 overflow-x-auto rounded-xl border border-border">
          <table className="w-full min-w-[32rem] text-left text-sm">
            <thead className="border-b border-border bg-elevated text-xs uppercase tracking-wide text-subtle">
              <tr>
                <th className="px-4 py-3 font-medium">Category</th>
                <th className="px-4 py-3 font-medium">Checks</th>
                <th className="px-4 py-3 font-medium">Covers</th>
              </tr>
            </thead>
            <tbody>
              {PRODUCT.categories.map((c) => (
                <tr
                  key={c.name}
                  className="border-b border-border last:border-0"
                >
                  <td className="px-4 py-2.5 font-medium text-fg">{c.name}</td>
                  <td className="px-4 py-2.5 font-mono text-primary">
                    {c.count}
                  </td>
                  <td className="px-4 py-2.5 text-muted">{c.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
}
