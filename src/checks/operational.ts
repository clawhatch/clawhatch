/**
 * Operational Security checks (OPS-001 to OPS-007).
 *
 * Checks for logging, error verbosity, monitoring,
 * dependency staleness, health checks, git secrets, and rollback plans.
 */

import { Severity, type Finding, type OpenClawConfig, type DiscoveredFiles } from "../types.js";
import { readFile, access, constants } from "node:fs/promises";
import { join, basename } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

// FIX: Removed unused API_KEY_PATTERNS constant (was dead code)

export async function runOperationalChecks(
  config: OpenClawConfig,
  files: DiscoveredFiles
): Promise<Finding[]> {
  const findings: Finding[] = [];

  // OPS-001: No structured logging
  if (!config.monitoring?.enabled) {
    findings.push({
      id: "OPS-001",
      severity: Severity.Low,
      confidence: "low",
      category: "Operational Security",
      title: "No structured logging configured",
      description: "No monitoring or structured logging integration detected",
      risk: "Unstructured logs make incident investigation and pattern detection difficult",
      remediation: "Configure monitoring.enabled: true with a structured logging provider",
      autoFixable: false,
    });
  }

  // OPS-002: Error messages too verbose
  if (config.verbose?.enabled === true) {
    findings.push({
      id: "OPS-002",
      severity: Severity.Medium,
      confidence: "medium",
      category: "Operational Security",
      title: "Verbose error output enabled",
      description: "Verbose mode is globally enabled — error messages may expose internal details",
      risk: "Verbose errors can leak file paths, stack traces, or configuration to end users",
      remediation: "Disable verbose mode in production or restrict to admin users",
      autoFixable: false,
    });
  }

  // OPS-003: No monitoring/alerting
  if (!config.monitoring?.enabled) {
    findings.push({
      id: "OPS-003",
      severity: Severity.Low,
      confidence: "low",
      category: "Operational Security",
      title: "No monitoring or alerting",
      description: "No monitoring provider configured for security event alerting",
      risk: "Security incidents may go undetected without active monitoring",
      remediation: "Configure monitoring.enabled: true and set up alerts for anomalous activity",
      autoFixable: false,
    });
  }

  // OPS-004: Stale dependencies in skills
  for (const pkgFile of files.skillPackageFiles.slice(0, 5)) {
    try {
      const content = await readFile(pkgFile, "utf-8");
      const pkg = JSON.parse(content);
      const deps = { ...pkg.dependencies, ...pkg.devDependencies };
      // Check for very old version patterns (major version 0.x or 1.x with known-old packages)
      const stale = Object.entries(deps).filter(([, v]) => {
        const version = String(v);
        return /^[~^]?0\./.test(version); // major version 0 is often pre-release/stale
      });
      if (stale.length > 3) {
        findings.push({
          id: "OPS-004",
          severity: Severity.Low,
          confidence: "low",
          category: "Operational Security",
          title: "Potentially stale dependencies",
          description: `${basename(pkgFile)} has ${stale.length} dependencies at major version 0.x`,
          risk: "Pre-1.0 dependencies may lack security patches and have unstable APIs",
          remediation: "Review and update dependencies to current stable versions",
          autoFixable: false,
          file: pkgFile,
        });
        break;
      }
    } catch {
      // Can't parse
    }
  }

  // OPS-005: No health check endpoint
  // Check if config has any health/readiness settings
  const configStr = JSON.stringify(config).toLowerCase();
  if (!configStr.includes("health") && !configStr.includes("readiness") && !configStr.includes("liveness")) {
    findings.push({
      id: "OPS-005",
      severity: Severity.Low,
      confidence: "low",
      category: "Operational Security",
      title: "No health check endpoint configured",
      description: "No health, readiness, or liveness check configuration found",
      risk: "Cannot monitor agent availability or detect hung/crashed agents",
      remediation: "Configure a health check endpoint for monitoring agent status",
      autoFixable: false,
    });
  }

  // OPS-006: Git repo has secrets in history
  if (files.workspaceDir) {
    try {
      await access(join(files.workspaceDir, ".git"), constants.R_OK);
      // Check last 20 commits for secret patterns
      try {
        const { stdout } = await execFileAsync(
          "git",
          ["log", "--oneline", "-20", "--diff-filter=A", "--name-only"],
          { cwd: files.workspaceDir, timeout: 5000 }
        );
        const hasSecretFiles = /\.env|\.pem|\.key|id_rsa|credentials\.json|service-account/i.test(stdout);
        if (hasSecretFiles) {
          findings.push({
            id: "OPS-006",
            severity: Severity.High,
            confidence: "medium",
            category: "Operational Security",
            title: "Secret files in git history",
            description: "Git history shows .env, .pem, .key, or credential files were committed",
            risk: "Secrets remain in git history even after deletion — anyone with repo access can recover them",
            remediation: "Use git filter-branch or BFG Repo-Cleaner to purge secrets from history, then rotate all affected credentials",
            autoFixable: false,
          });
        }
      } catch {
        // git command failed
      }
    } catch {
      // No .git directory
    }
  }

  // OPS-007: No rollback plan
  // Check if there are any backup/snapshot/rollback references in config
  if (!configStr.includes("backup") && !configStr.includes("rollback") && !configStr.includes("snapshot")) {
    findings.push({
      id: "OPS-007",
      severity: Severity.Low,
      confidence: "low",
      category: "Operational Security",
      title: "No rollback plan configured",
      description: "No backup, rollback, or snapshot configuration found",
      risk: "Misconfigured agents cannot be quickly reverted to a known-good state",
      remediation: "Maintain configuration backups and document a rollback procedure",
      autoFixable: false,
    });
  }

  return findings;
}
