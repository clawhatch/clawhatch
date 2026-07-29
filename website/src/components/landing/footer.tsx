import { BRAND } from "@/lib/brand";
import { PRODUCT } from "@/lib/product";

export function Footer() {
  return (
    <footer className="border-t border-border py-12">
      <div className="mx-auto flex max-w-6xl flex-col gap-8 px-4 sm:flex-row sm:items-start sm:justify-between sm:px-6">
        <div>
          <div className="flex items-center gap-2.5">
            <span className="flex h-7 w-7 items-center justify-center rounded-md bg-primary text-[10px] font-semibold text-primary-fg">
              CH
            </span>
            <span className="text-sm font-semibold text-fg">{BRAND.name}</span>
            <span className="font-mono text-[10px] text-subtle">
              v{PRODUCT.version}
            </span>
          </div>
          <p className="mt-3 max-w-xs text-sm text-muted">
            Secure hatch for OpenClaw agents. Identity first, action second,
            model last. Open source · {PRODUCT.license}.
          </p>
          <p className="mt-3 text-sm text-muted">
            <a href={BRAND.url} className="text-fg hover:text-primary">
              {BRAND.domain}
            </a>
            {" · "}
            <a href={`mailto:${BRAND.email}`} className="hover:text-fg">
              {BRAND.email}
            </a>
          </p>
        </div>
        <div className="flex flex-wrap gap-x-10 gap-y-6 text-sm">
          <div className="flex flex-col gap-2">
            <span className="font-medium text-fg">Product</span>
            <a href="#features" className="text-muted hover:text-fg">
              Features
            </a>
            <a href="#pricing" className="text-muted hover:text-fg">
              Pricing
            </a>
            <a href="/world" className="text-muted hover:text-fg">
              Scroll world
            </a>
            <a href="#cta" className="text-muted hover:text-fg">
              Scan
            </a>
          </div>
          <div className="flex flex-col gap-2">
            <span className="font-medium text-fg">Source of truth</span>
            <a
              href={PRODUCT.github}
              className="text-muted hover:text-fg"
              target="_blank"
              rel="noreferrer"
            >
              GitHub
            </a>
            <a
              href={PRODUCT.npm}
              className="text-muted hover:text-fg"
              target="_blank"
              rel="noreferrer"
            >
              npm (registry may lag)
            </a>
            <a
              href={`${PRODUCT.github}/blob/main/CHANGELOG.md`}
              className="text-muted hover:text-fg"
              target="_blank"
              rel="noreferrer"
            >
              Changelog
            </a>
            <a
              href={`${PRODUCT.github}/blob/main/SECURITY.md`}
              className="text-muted hover:text-fg"
              target="_blank"
              rel="noreferrer"
            >
              Security
            </a>
          </div>
          <div className="flex flex-col gap-2">
            <span className="font-medium text-fg">Contact</span>
            <a
              href={`mailto:${BRAND.email}`}
              className="text-muted hover:text-fg"
            >
              {BRAND.email}
            </a>
          </div>
        </div>
      </div>
      <div className="mx-auto mt-10 max-w-6xl border-t border-border px-4 pt-6 text-xs text-subtle sm:px-6">
        © {new Date().getFullYear()} {BRAND.name} · {BRAND.domain}. Site tracks{" "}
        <a href={PRODUCT.github} className="hover:text-fg">
          {PRODUCT.githubOwner}/{PRODUCT.githubRepo}
        </a>{" "}
        v{PRODUCT.version} (last repo push {PRODUCT.lastPushed}). MIT-licensed
        scanner.
      </div>
    </footer>
  );
}
