/**
 * Single source of truth for ClawHatch product claims.
 * Tracked against https://github.com/clawhatch/clawhatch (repo package.json + README).
 * Last reconciled: 2026-07-29 against main @ 0.2.2 (npm registry may lag — see npmVersion).
 */
export const PRODUCT = {
  /** Version in GitHub package.json / intended release */
  version: "0.2.2",
  /** What npm currently serves (registry.npmjs.org/clawhatch/latest as of reconcile) */
  npmVersion: "0.1.0",
  /** GitHub org repo (canonical) */
  github: "https://github.com/clawhatch/clawhatch",
  githubOwner: "clawhatch",
  githubRepo: "clawhatch",
  npm: "https://www.npmjs.com/package/clawhatch",
  license: "MIT",
  node: ">=18",
  /** Marketing check count used in README / TOTAL_CHECKS */
  checks: 100,
  /** Repo description still says 128 — site uses README number until repo description is fixed */
  checksClaimConflict: 128,
  scoreMax: 100,
  primaryCommand: "npx clawhatch scan",
  commands: {
    scan: "npx clawhatch scan",
    fix: "npx clawhatch scan --fix",
    workspace: "npx clawhatch scan --workspace .",
    deep: "npx clawhatch scan --deep",
    json: "npx clawhatch scan --json",
    html: "npx clawhatch scan --format html",
    quiet: "npx clawhatch scan --quiet",
    init: "npx clawhatch init",
    monitor: "npx clawhatch monitor",
    monitorStatus: "npx clawhatch monitor --status",
    threats: "npx clawhatch threats",
  },
  categories: [
    { name: "Identity & Access", count: 15, detail: "DM policies, allowlists, pairing, access groups, OAuth" },
    { name: "Network", count: 10, detail: "Gateway binding, auth mode, TLS, CORS, port exposure" },
    { name: "Sandbox", count: 8, detail: "Exec policies, workspace access, Docker isolation" },
    { name: "Secrets", count: 30, detail: "API keys in config/logs, .env perms, key rotation" },
    { name: "Tools", count: 20, detail: "Shell access, Docker socket, dangerous combos, timeouts" },
    { name: "Skills", count: 12, detail: "Untrusted sources, eval(), native modules, sandboxing" },
    { name: "Model", count: 7, detail: "Legacy models, injection risk, SOUL.md exposure" },
    { name: "Cloud Sync", count: 1, detail: "iCloud, OneDrive, Dropbox, Google Drive detection" },
    { name: "Data", count: 10, detail: "PII in logs, retention, encryption at rest, backups" },
    { name: "Operational", count: 7, detail: "Logging, monitoring, health checks, git secrets" },
  ],
  freeTier: [
    "Manual scans (`npx clawhatch scan`)",
    "Auto-fix with backups (`--fix`)",
    "Hardened baseline (`clawhatch init`)",
    "JSON / HTML reports",
    "Scan history & change detection",
    "No account required · 100% offline",
  ],
  paidTier: [
    "Scheduled monitoring (`monitor --start`)",
    "Trend reports (`monitor --report`)",
    "Score alerts",
    "License via ~/.clawhatch/license.key",
  ],
  /** Last GitHub push observed at reconcile */
  lastPushed: "2026-02-09",
  homepageCanonical: "https://clawhatch.co.uk",
} as const;
