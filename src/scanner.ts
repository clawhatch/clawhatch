/**
 * Main scanner orchestrator.
 *
 * Pipeline:
 * 1. Discover files
 * 2. Parse config, env, markdown
 * 3. Run all check categories
 * 4. Score results
 * 5. Sanitize findings
 * 6. Separate findings from suggestions (by confidence)
 * 7. Return ScanResult
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import chalk from "chalk";
import { findOpenClawDir, discoverFiles } from "./discover.js";
import { parseConfig, readConfigRaw } from "./parsers/config.js";
import { parseEnv } from "./parsers/env.js";
import { runIdentityChecks } from "./checks/identity.js";
import { runNetworkChecks } from "./checks/network.js";
import { runSandboxChecks } from "./checks/sandbox.js";
import { runSecretChecks } from "./checks/secrets.js";
import { runModelChecks } from "./checks/model.js";
import { runCloudSyncCheck } from "./checks/cloud-sync.js";
import { runToolChecks } from "./checks/tools.js";
import { runSkillChecks } from "./checks/skills.js";
import { runDataProtectionChecks } from "./checks/data-protection.js";
import { runOperationalChecks } from "./checks/operational.js";
import { calculateScore } from "./scoring.js";
import { sanitizeFindings } from "./sanitize.js";
import type { Finding, ScanOptions, ScanResult } from "./types.js";
import { join } from "node:path";

const execFileAsync = promisify(execFile);

/**
 * Deduplicate findings by check ID.
 * When the same check fires for multiple files (e.g., SECRET-005 for each credential file),
 * aggregate them into a single finding with updated description showing the count and file list.
 */
function deduplicateFindings(findings: Finding[]): Finding[] {
  const grouped = new Map<string, Finding[]>();

  for (const f of findings) {
    const existing = grouped.get(f.id) || [];
    existing.push(f);
    grouped.set(f.id, existing);
  }

  const deduplicated: Finding[] = [];
  for (const [id, group] of grouped) {
    if (group.length === 1) {
      deduplicated.push(group[0]);
    } else {
      // Aggregate multiple findings with same ID
      const first = group[0];
      const files = group.map((f) => f.file).filter(Boolean) as string[];
      const uniqueFiles = [...new Set(files)];

      // Build aggregated description
      let description = first.description;
      if (uniqueFiles.length > 1) {
        const fileList =
          uniqueFiles.length <= 3
            ? uniqueFiles.map((f) => f.split(/[/\\]/).pop()).join(", ")
            : `${uniqueFiles.slice(0, 3).map((f) => f.split(/[/\\]/).pop()).join(", ")}... and ${uniqueFiles.length - 3} more`;
        description = `${first.title} (${group.length} occurrences in: ${fileList})`;
      }

      deduplicated.push({
        ...first,
        description,
        // Keep the first file for reference, but note there are more
        file: uniqueFiles[0],
      });
    }
  }

  return deduplicated;
}

/**
 * TOTAL_CHECKS: This is the "marketed" number of checks (100-point audit).
 * The actual number of check IDs varies based on config and files found,
 * since some checks only fire conditionally. We track checksRun separately
 * from this constant, which represents the maximum possible checks in a
 * comprehensive scan. The score formula uses actual findings, not this number.
 */
const TOTAL_CHECKS = 100;

/**
 * Detect OpenClaw version by running `openclaw --version`.
 */
async function detectVersion(): Promise<string | null> {
  try {
    const { stdout } = await execFileAsync("openclaw", ["--version"], {
      timeout: 5000,
    });
    return stdout.trim();
  } catch {
    return null;
  }
}

/**
 * Run the full security scan.
 */
export async function scan(options: ScanOptions): Promise<ScanResult> {
  const startTime = Date.now();

  // Use stderr for progress messages when JSON output is requested
  const log = options.json
    ? (...args: unknown[]) => console.error(...args)
    : (...args: unknown[]) => console.log(...args);

  // Step 0: Find OpenClaw installation
  const openclawDir = await findOpenClawDir(options.openclawPath);
  if (!openclawDir) {
    console.error(chalk.red("\n  OpenClaw installation not found."));
    console.error(chalk.dim("  Try: clawhatch scan --path /custom/path"));
    console.error(chalk.dim("  Common locations:"));
    if (process.platform === "win32") {
      console.error(chalk.dim("    Windows: %APPDATA%\\openclaw"));
    }
    console.error(chalk.dim("    macOS/Linux: ~/.openclaw"));
    process.exit(1);
  }

  // Step 0.5: Detect version
  const version = await detectVersion();
  if (version) {
    log(chalk.dim(`  OpenClaw version: ${version}`));
  }

  // Step 1: Discover files
  log(chalk.dim("  Discovering files..."));
  const { files, symlinkWarnings } = await discoverFiles(
    openclawDir,
    options.workspacePath ?? null
  );

  // Report symlink warnings
  for (const warning of symlinkWarnings) {
    log(chalk.yellow(`  Warning: ${warning}`));
  }

  let filesScanned = 0;
  if (files.configPath) filesScanned++;
  if (files.envPath) filesScanned++;
  filesScanned += files.credentialFiles.length;
  filesScanned += files.authProfileFiles.length;
  filesScanned += files.sessionLogFiles.length;
  filesScanned += files.workspaceMarkdownFiles.length;
  filesScanned += files.skillFiles.length;
  filesScanned += files.customCommandFiles.length;
  filesScanned += files.skillPackageFiles.length;
  filesScanned += files.privateKeyFiles.length;
  filesScanned += files.sshKeyFiles.length;

  if (!files.configPath) {
    log(
      chalk.yellow(
        "  Warning: openclaw.json not found — config-based checks will be limited"
      )
    );
  }

  if (!options.workspacePath) {
    log(
      chalk.dim(
        "  Tip: Run with --workspace <path> for full scan including SOUL.md, skills, etc."
      )
    );
  }

  // Step 2: Parse files
  log(chalk.dim("  Parsing configuration..."));
  const config = files.configPath
    ? await parseConfig(files.configPath)
    : null;
  const configRaw = files.configPath
    ? await readConfigRaw(files.configPath)
    : null;

  // FIX: Warn if config file exists but couldn't be parsed (corrupt JSON, encoding issues, etc.)
  if (files.configPath && !config) {
    log(
      chalk.yellow(
        "  Warning: openclaw.json exists but could not be parsed — config-based checks will be skipped"
      )
    );
  }

  // Step 3: Run all checks
  log(chalk.dim("  Running 100 security checks..."));
  const allFindings: Finding[] = [];

  if (config) {
    // Identity & Access (checks 1-15)
    const identityFindings = await runIdentityChecks(config, {
      credentialFiles: files.credentialFiles,
      authProfileFiles: files.authProfileFiles,
    });
    allFindings.push(...identityFindings);

    // Network Exposure (checks 16-25)
    const networkFindings = await runNetworkChecks(config);
    allFindings.push(...networkFindings);

    // Sandbox Configuration (checks 26-33)
    const sandboxFindings = await runSandboxChecks(config);
    allFindings.push(...sandboxFindings);
  }

  // Secret Scanning (checks 34-43)
  if (config || files.workspaceMarkdownFiles.length > 0) {
    const secretFindings = await runSecretChecks(
      config || {},
      configRaw,
      files,
      options.deep
    );
    allFindings.push(...secretFindings);
  }

  // Model Security (checks 44-50)
  if (config) {
    const soulMdPath = files.workspaceMarkdownFiles.find((f) =>
      f.toLowerCase().endsWith("soul.md")
    ) ?? null;
    const modelFindings = await runModelChecks(config, soulMdPath);
    allFindings.push(...modelFindings);
  }

  // Tool Security (checks TOOLS-001 to TOOLS-020)
  if (config) {
    const toolFindings = await runToolChecks(config, files);
    allFindings.push(...toolFindings);
  }

  // Skill Security (checks SKILLS-001 to SKILLS-012)
  if (config || files.skillFiles.length > 0) {
    const skillFindings = await runSkillChecks(config || {}, files);
    allFindings.push(...skillFindings);
  }

  // Data Protection (checks DATA-001 to DATA-010)
  {
    const dataFindings = await runDataProtectionChecks(config || {}, files);
    allFindings.push(...dataFindings);
  }

  // Operational Security (checks OPS-001 to OPS-007)
  {
    const opsFindings = await runOperationalChecks(config || {}, files);
    allFindings.push(...opsFindings);
  }

  // Cloud Sync Detection (check 51)
  const cloudFindings = await runCloudSyncCheck(openclawDir);
  allFindings.push(...cloudFindings);

  // Step 4: Deduplicate findings by check ID
  // When the same issue (e.g., SECRET-005 for loose permissions) appears in multiple files,
  // aggregate them into a single finding with a count, rather than N separate findings.
  const deduplicatedFindings = deduplicateFindings(allFindings);

  // Step 5: Separate findings from suggestions
  const findings = deduplicatedFindings.filter((f) => f.confidence !== "low");
  const suggestions = deduplicatedFindings.filter((f) => f.confidence === "low");

  // Step 6: Sanitize (strip any accidental secret values)
  const sanitizedFindings = sanitizeFindings(findings);
  const sanitizedSuggestions = sanitizeFindings(suggestions);

  // Step 7: Calculate score (only high-confidence findings count)
  const score = calculateScore(sanitizedFindings);

  const duration = Date.now() - startTime;

  return {
    timestamp: new Date().toISOString(),
    openclawVersion: version,
    score,
    findings: sanitizedFindings,
    suggestions: sanitizedSuggestions,
    filesScanned,
    checksRun: TOTAL_CHECKS,
    // FIX: Clamp to 0 — more findings than checks is possible since some checks emit multiple findings
    checksPassed: Math.max(0, TOTAL_CHECKS - sanitizedFindings.length),
    duration,
    platform: process.platform,
  };
}
