/**
 * Data Protection checks (DATA-001 to DATA-010).
 *
 * Checks for PII in logs, data retention policies, encryption,
 * log rotation, and data access audit trails.
 */

import { Severity, type Finding, type OpenClawConfig, type DiscoveredFiles } from "../types.js";
import { readFile, stat } from "node:fs/promises";
import { basename, join } from "node:path";

// FIX: Tightened PII patterns to reduce false positives.
// Phone/SSN patterns removed — they match timestamps, version numbers, ports, etc.
// with extremely high false-positive rates. Kept email and credit-card (Luhn check
// would be ideal but is out of scope; the 4-group pattern is reasonably specific).
const PII_PATTERNS = [
  /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/,   // email (FIX: [A-Za-z] not [A-Z|a-z])
  /\b\d{4}[\s-]\d{4}[\s-]\d{4}[\s-]\d{4}\b/,               // credit card-like (require separators to avoid matching hex/ids)
];

export async function runDataProtectionChecks(
  config: OpenClawConfig,
  files: DiscoveredFiles
): Promise<Finding[]> {
  const findings: Finding[] = [];

  // DATA-001: Session logs contain PII
  for (const logFile of files.sessionLogFiles.slice(0, 5)) {
    try {
      const content = await readFile(logFile, "utf-8").then((c) => c.slice(0, 512 * 1024));
      const hasPII = PII_PATTERNS.some((p) => p.test(content));
      if (hasPII) {
        findings.push({
          id: "DATA-001",
          severity: Severity.High,
          confidence: "medium",
          category: "Data Protection",
          title: "Session log may contain PII",
          description: `${basename(logFile)} contains patterns resembling personal data (email, phone, etc.)`,
          risk: "PII in logs may violate privacy regulations (GDPR, CCPA) and expose user data",
          remediation: "Enable PII scrubbing in session logs or reduce log verbosity",
          autoFixable: false,
          file: logFile,
        });
        break;
      }
    } catch {
      // Can't read
    }
  }

  // DATA-002: No data retention policy
  if (!config.retention?.sessionLogTTL) {
    findings.push({
      id: "DATA-002",
      severity: Severity.Medium,
      confidence: "medium",
      category: "Data Protection",
      title: "No data retention policy",
      description: "No session log TTL configured — logs accumulate indefinitely",
      risk: "Unbounded log retention increases data breach exposure window",
      remediation: "Set retention.sessionLogTTL to a reasonable period (e.g., 30 days)",
      autoFixable: false,
    });
  }

  // DATA-003: Logs not encrypted at rest
  if (!config.retention?.encryptAtRest) {
    findings.push({
      id: "DATA-003",
      severity: Severity.Low,
      confidence: "low",
      category: "Data Protection",
      title: "Session logs not encrypted at rest",
      description: "retention.encryptAtRest is not enabled for session logs",
      risk: "Logs stored in plaintext can be read if the disk is accessed by unauthorized parties",
      remediation: "Set retention.encryptAtRest: true or use full-disk encryption",
      autoFixable: false,
    });
  }

  // DATA-004: No log rotation
  if (!config.retention?.logRotation) {
    // Also flag if session logs are large
    let hasLargeLog = false;
    for (const logFile of files.sessionLogFiles.slice(0, 5)) {
      try {
        const s = await stat(logFile);
        if (s.size > 50 * 1024 * 1024) {
          hasLargeLog = true;
          break;
        }
      } catch {
        // Can't stat
      }
    }

    findings.push({
      id: "DATA-004",
      severity: hasLargeLog ? Severity.Medium : Severity.Low,
      confidence: hasLargeLog ? "high" : "medium",
      category: "Data Protection",
      title: "No log rotation configured",
      description: hasLargeLog
        ? "Log rotation disabled and session logs exceed 50MB"
        : "retention.logRotation is not enabled",
      risk: "Unrotated logs consume disk space and increase exposure in case of breach",
      remediation: "Set retention.logRotation: true to enable automatic log rotation",
      autoFixable: false,
    });
  }

  // DATA-005: Backups not encrypted
  if (config.retention && !config.retention.encryptAtRest) {
    findings.push({
      id: "DATA-005",
      severity: Severity.Low,
      confidence: "low",
      category: "Data Protection",
      title: "Backups not encrypted",
      description: "Data retention is configured but encryption at rest is not enabled",
      risk: "Backup files containing session data are stored in plaintext",
      remediation: "Enable retention.encryptAtRest: true to encrypt stored data",
      autoFixable: false,
    });
  }

  // DATA-006: No data anonymization
  if (files.sessionLogFiles.length > 0 && !config.retention?.sessionLogTTL) {
    findings.push({
      id: "DATA-006",
      severity: Severity.Low,
      confidence: "low",
      category: "Data Protection",
      title: "No data anonymization",
      description: "Session logs exist with no retention policy or anonymization configured",
      risk: "Historical logs contain identifiable conversation data",
      remediation: "Configure data anonymization or set a retention TTL to limit data lifespan",
      autoFixable: false,
    });
  }

  // DATA-007: Third-party data sharing
  if (config.monitoring?.enabled && config.monitoring?.provider) {
    findings.push({
      id: "DATA-007",
      severity: Severity.Medium,
      confidence: "medium",
      category: "Data Protection",
      title: "Third-party monitoring enabled",
      description: `Monitoring data is sent to third-party provider: ${config.monitoring.provider}`,
      risk: "Session data, tool invocations, or PII may be shared with external services",
      remediation: "Review monitoring configuration to ensure only necessary data is shared",
      autoFixable: false,
    });
  }

  // DATA-008: No right-to-deletion
  if (files.sessionLogFiles.length > 0 && !config.retention?.sessionLogTTL) {
    findings.push({
      id: "DATA-008",
      severity: Severity.Low,
      confidence: "low",
      category: "Data Protection",
      title: "No data deletion mechanism",
      description: "No retention TTL or deletion mechanism for user session data",
      risk: "Cannot fulfil data deletion requests (GDPR Article 17) without manual cleanup",
      remediation: "Configure retention.sessionLogTTL or provide a data deletion workflow",
      autoFixable: false,
    });
  }

  // DATA-009: Logs in public directory
  if (files.workspaceDir) {
    const publicDirs = ["public", "static", "dist", "build", "www"];
    for (const logFile of files.sessionLogFiles) {
      const inPublic = publicDirs.some((d) =>
        logFile.toLowerCase().includes(`${d}/`) || logFile.toLowerCase().includes(`${d}\\`)
      );
      if (inPublic) {
        findings.push({
          id: "DATA-009",
          severity: Severity.High,
          confidence: "high",
          category: "Data Protection",
          title: "Session logs in public directory",
          description: `${basename(logFile)} is inside a public/static directory`,
          risk: "Logs in public directories may be served by web servers and accessible via URL",
          remediation: "Move session logs out of public-facing directories",
          autoFixable: false,
          file: logFile,
        });
        break;
      }
    }
  }

  // DATA-010: No audit trail for data access
  if (!config.tools?.auditLog && files.sessionLogFiles.length > 0) {
    findings.push({
      id: "DATA-010",
      severity: Severity.Low,
      confidence: "low",
      category: "Data Protection",
      title: "No audit trail for data access",
      description: "No audit logging configured to track who accesses session data",
      risk: "Cannot determine who accessed, modified, or exported conversation data",
      remediation: "Enable tools.auditLog: true to track data access operations",
      autoFixable: false,
    });
  }

  return findings;
}
