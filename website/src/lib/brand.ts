import { PRODUCT } from "@/lib/product";

/** Public brand host — clawhatch.co.uk is the UK canonical site. */
export const BRAND = {
  name: "ClawHatch",
  domain: "clawhatch.co.uk",
  url: PRODUCT.homepageCanonical,
  www: "https://www.clawhatch.co.uk",
  email: "hello@clawhatch.co.uk",
  github: PRODUCT.github,
  npm: PRODUCT.npm,
  version: PRODUCT.version,
  tagline: "OpenClaw, born secure.",
  description:
    "Security scanner for OpenClaw AI agents — 100 automated checks, score 0–100, auto-fix, local-first. No account.",
} as const;
