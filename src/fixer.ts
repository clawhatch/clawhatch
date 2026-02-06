/**
 * Auto-fix system.
 *
 * Rules:
 * 1. ALWAYS back up before modifying any file (.bak.{timestamp})
 * 2. "safe" fixes: permissions, .gitignore, tokens — applied automatically
 * 3. "behavioral" fixes: dmPolicy, sandbox changes — prompt user first
 * 4. Log all changes made
 */

import { readFile, writeFile, copyFile, chmod } from "node:fs/promises";
import { createInterface } from "node:readline";
import { platform } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import JSON5 from "json5";
import chalk from "chalk";
import type { Finding, FixResult, OpenClawConfig } from "./types.js";

function backupPath(filePath: string): string {
  const ts = new Date().toISOString().replace(/[:.]/g, "-");
  return `${filePath}.bak.${ts}`;
}

async function backupFile(filePath: string): Promise<string> {
  const dest = backupPath(filePath);
  await copyFile(filePath, dest);
  return dest;
}

async function promptUser(message: string): Promise<boolean> {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(`${message} [y/N] `, (answer) => {
      rl.close();
      resolve(answer.toLowerCase() === "y" || answer.toLowerCase() === "yes");
    });
  });
}

/**
 * Apply fixes for all auto-fixable findings.
 * Returns a list of what was fixed and what was skipped.
 */
export async function applyFixes(
  findings: Finding[],
  configPath: string | null,
  openclawDir: string
): Promise<FixResult[]> {
  const results: FixResult[] = [];
  const fixable = findings.filter((f) => f.autoFixable);

  if (fixable.length === 0) {
    console.log(chalk.dim("\n  No auto-fixable issues found.\n"));
    return results;
  }

  console.log(
    chalk.cyan(
      `\n  Found ${fixable.length} auto-fixable issue(s). Applying fixes...\n`
    )
  );

  // Group config-related fixes to apply them in a single write
  const configFixes: Finding[] = [];
  const permissionFixes: Finding[] = [];
  const otherFixes: Finding[] = [];

  for (const f of fixable) {
    if (isConfigFix(f)) {
      configFixes.push(f);
    } else if (isPermissionFix(f)) {
      permissionFixes.push(f);
    } else {
      otherFixes.push(f);
    }
  }

  // Apply config fixes (batch — single backup + write)
  if (configFixes.length > 0 && configPath) {
    const configResults = await applyConfigFixes(configFixes, configPath);
    results.push(...configResults);
  }

  // Apply permission fixes
  for (const f of permissionFixes) {
    const r = await applyPermissionFix(f);
    results.push(r);
  }

  // Apply other fixes (e.g., .gitignore)
  for (const f of otherFixes) {
    if (f.id === "SECRET-002") {
      const r = await applyGitignoreFix(openclawDir);
      results.push(r);
    }
  }

  // Summary
  console.log("");
  const applied = results.filter((r) => r.applied).length;
  const skipped = results.filter((r) => !r.applied).length;
  console.log(chalk.green(`  ${applied} fix(es) applied, ${skipped} skipped.`));

  for (const r of results) {
    if (r.applied) {
      console.log(chalk.green(`    + ${r.description}`));
      if (r.backupPath) {
        console.log(chalk.dim(`      Backup: ${r.backupPath}`));
      }
    } else {
      console.log(chalk.dim(`    - Skipped: ${r.description} (${r.skippedReason})`));
    }
  }
  console.log("");

  return results;
}

function isConfigFix(finding: Finding): boolean {
  // FIX: Removed IDENTITY-008 — applyConfigMutation doesn't implement it,
  // so it would silently fail with "Mutation not implemented" message
  return [
    "IDENTITY-001", "IDENTITY-003", "IDENTITY-005", "IDENTITY-007",
    "IDENTITY-009",
    "NETWORK-001", "NETWORK-002", "NETWORK-003", "NETWORK-004",
    "NETWORK-006", "NETWORK-007",
    "SANDBOX-001", "SANDBOX-006", "SANDBOX-007", "SANDBOX-008",
  ].includes(finding.id);
}

function isPermissionFix(finding: Finding): boolean {
  return [
    "IDENTITY-012",
    "SECRET-003", "SECRET-004", "SECRET-005", "SECRET-006",
  ].includes(finding.id);
}

async function applyConfigFixes(
  fixes: Finding[],
  configPath: string
): Promise<FixResult[]> {
  const results: FixResult[] = [];

  // Separate safe vs behavioral
  const safeFixes = fixes.filter((f) => f.fixType === "safe");
  const behavioralFixes = fixes.filter((f) => f.fixType === "behavioral");

  // Prompt for behavioral fixes
  const approvedBehavioral: Finding[] = [];
  for (const f of behavioralFixes) {
    console.log(
      chalk.yellow(
        `  Behavioral change: ${f.title}`
      )
    );
    console.log(chalk.dim(`    ${f.description}`));
    const approved = await promptUser(
      chalk.yellow("    Apply this change?")
    );
    if (approved) {
      approvedBehavioral.push(f);
    } else {
      results.push({
        finding: f,
        applied: false,
        description: f.title,
        skippedReason: "User declined behavioral change",
      });
    }
  }

  const allApproved = [...safeFixes, ...approvedBehavioral];
  if (allApproved.length === 0) return results;

  // Backup config file
  const bak = await backupFile(configPath);
  console.log(chalk.dim(`  Backup created: ${bak}`));

  // Read and parse config
  const raw = await readFile(configPath, "utf-8");
  let config: OpenClawConfig;
  try {
    config = JSON5.parse(raw);
  } catch {
    results.push({
      finding: allApproved[0],
      applied: false,
      description: "Config file fixes",
      skippedReason: "Could not parse openclaw.json",
    });
    return results;
  }

  // Apply each fix
  for (const f of allApproved) {
    const applied = applyConfigMutation(config, f);
    results.push({
      finding: f,
      applied,
      backupPath: bak,
      description: f.title,
      skippedReason: applied ? undefined : "Mutation not implemented for this check",
    });
  }

  // Write updated config
  await writeFile(configPath, JSON.stringify(config, null, 2), "utf-8");

  return results;
}

function applyConfigMutation(config: OpenClawConfig, finding: Finding): boolean {
  switch (finding.id) {
    // Network fixes
    case "NETWORK-001": {
      if (!config.gateway) config.gateway = {};
      config.gateway.bind = "127.0.0.1";
      return true;
    }
    case "NETWORK-002": {
      if (!config.gateway) config.gateway = {};
      if (!config.gateway.auth) config.gateway.auth = {};
      config.gateway.auth.mode = "token";
      config.gateway.auth.token = randomBytes(32).toString("hex");
      return true;
    }
    case "NETWORK-003":
    case "NETWORK-004": {
      if (!config.gateway) config.gateway = {};
      if (!config.gateway.auth) config.gateway.auth = {};
      config.gateway.auth.token = randomBytes(32).toString("hex");
      return true;
    }
    case "NETWORK-006": {
      if (!config.gateway) config.gateway = {};
      config.gateway.allowInsecureAuth = false;
      return true;
    }
    case "NETWORK-007": {
      if (!config.gateway) config.gateway = {};
      config.gateway.dangerouslyDisableDeviceAuth = false;
      return true;
    }

    // Identity fixes (behavioral — already prompted)
    case "IDENTITY-001": {
      // Set dmPolicy to "pairing" for matching channel
      if (config.channels) {
        for (const ch of Object.values(config.channels)) {
          if (ch.dmPolicy === "open") {
            ch.dmPolicy = "pairing";
          }
        }
      }
      return true;
    }
    case "IDENTITY-003": {
      if (config.channels) {
        for (const ch of Object.values(config.channels)) {
          if (ch.groupPolicy === "open") {
            ch.groupPolicy = "allowlist";
          }
        }
      }
      return true;
    }
    case "IDENTITY-005": {
      if (config.channels) {
        for (const ch of Object.values(config.channels)) {
          if (ch.requireMention === false) {
            ch.requireMention = true;
          }
        }
      }
      return true;
    }
    case "IDENTITY-007": {
      if (!config.pairing) (config as Record<string, unknown>).pairing = {};
      config.pairing!.storeTTL = 86400; // 24 hours
      return true;
    }
    case "IDENTITY-009": {
      if (!config.commands) (config as Record<string, unknown>).commands = {};
      config.commands!.useAccessGroups = true;
      return true;
    }

    // Sandbox fixes
    case "SANDBOX-001": {
      if (!config.sandbox) (config as Record<string, unknown>).sandbox = {};
      config.sandbox!.mode = "all";
      return true;
    }
    case "SANDBOX-006": {
      if (config.sandbox?.docker) {
        config.sandbox.docker.network = "none";
      }
      return true;
    }
    case "SANDBOX-007": {
      if (config.sandbox?.docker) {
        config.sandbox.docker.socketMounted = false;
      }
      return true;
    }
    case "SANDBOX-008": {
      if (config.sandbox?.browser) {
        config.sandbox.browser.allowHostControl = false;
      }
      return true;
    }

    default:
      return false;
  }
}

async function applyPermissionFix(finding: Finding): Promise<FixResult> {
  if (platform() === "win32") {
    return {
      finding,
      applied: false,
      description: finding.title,
      skippedReason: "File permission fixes require Unix (use Windows Security settings)",
    };
  }

  if (!finding.file) {
    return {
      finding,
      applied: false,
      description: finding.title,
      skippedReason: "No file path in finding",
    };
  }

  try {
    const mode = finding.id === "SECRET-003" ? 0o700 : 0o600;
    await chmod(finding.file, mode);
    return {
      finding,
      applied: true,
      description: `Set ${finding.file} to ${mode.toString(8)}`,
    };
  } catch (err) {
    return {
      finding,
      applied: false,
      description: finding.title,
      skippedReason: `chmod failed: ${err instanceof Error ? err.message : "unknown error"}`,
    };
  }
}

async function applyGitignoreFix(openclawDir: string): Promise<FixResult> {
  // FIX: Removed redundant dynamic import — join is now imported at top level
  const gitignorePath = join(openclawDir, ".gitignore");

  try {
    let content = "";
    try {
      content = await readFile(gitignorePath, "utf-8");
    } catch {
      // File doesn't exist — create it
    }

    const bak = content ? await backupFile(gitignorePath) : undefined;

    const entries = [".env", ".env.*", "credentials/", "*.key", "*.pem"];
    const missing = entries.filter((e) => !content.includes(e));

    if (missing.length === 0) {
      return {
        finding: { id: "SECRET-002" } as Finding,
        applied: false,
        description: "Update .gitignore",
        skippedReason: "All entries already present",
      };
    }

    const addition = `\n# Added by Clawhatch security scanner\n${missing.join("\n")}\n`;
    await writeFile(gitignorePath, content + addition, "utf-8");

    return {
      finding: { id: "SECRET-002" } as Finding,
      applied: true,
      backupPath: bak,
      description: `Added ${missing.length} entries to .gitignore`,
    };
  } catch (err) {
    return {
      finding: { id: "SECRET-002" } as Finding,
      applied: false,
      description: "Update .gitignore",
      skippedReason: `Failed: ${err instanceof Error ? err.message : "unknown error"}`,
    };
  }
}
