/**
 * Sanitize findings before JSON serialization or upload.
 * Policy: Finding objects must NEVER contain secret values.
 * Only metadata about secrets (length, entropy score, masked preview).
 */

import type { Finding } from "./types.js";

/**
 * Patterns that might indicate a secret value leaked into a finding field.
 */
const SECRET_INDICATORS = [
  /sk-[a-zA-Z0-9]{20,}/,
  /sk-ant-[a-zA-Z0-9\-]{20,}/,
  /AIza[a-zA-Z0-9_\-]{30,}/,
  /AKIA[A-Z0-9]{16}/,
  /(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{30,}/,
  /xox[bpras]-[a-zA-Z0-9\-]{10,}/,
  /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/,
  /(?:sk|pk)_(?:live|test)_[a-zA-Z0-9]{20,}/,
  /\d{8,10}:[a-zA-Z0-9_-]{35}/,
  // FIX: Additional patterns to match secrets detected by the scanner
  /whsec_[a-zA-Z0-9]{20,}/,                // Stripe webhook secrets
  /rk_live_[a-zA-Z0-9]{20,}/,              // Stripe restricted keys
  /[MN][a-zA-Z0-9]{23,}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27,}/, // Discord tokens
];

function containsSecret(text: string): boolean {
  return SECRET_INDICATORS.some((pattern) => pattern.test(text));
}

function redactSecrets(text: string): string {
  let result = text;
  for (const pattern of SECRET_INDICATORS) {
    result = result.replace(new RegExp(pattern.source, "g"), "[REDACTED]");
  }
  return result;
}

/**
 * Sanitize a single finding — strip any secret values from all string fields.
 */
function sanitizeFinding(finding: Finding): Finding {
  return {
    ...finding,
    title: containsSecret(finding.title)
      ? redactSecrets(finding.title)
      : finding.title,
    description: containsSecret(finding.description)
      ? redactSecrets(finding.description)
      : finding.description,
    risk: containsSecret(finding.risk)
      ? redactSecrets(finding.risk)
      : finding.risk,
    remediation: containsSecret(finding.remediation)
      ? redactSecrets(finding.remediation)
      : finding.remediation,
  };
}

/**
 * Sanitize all findings in an array.
 * Call this before any JSON.stringify() or upload operation.
 */
export function sanitizeFindings(findings: Finding[]): Finding[] {
  return findings.map(sanitizeFinding);
}
