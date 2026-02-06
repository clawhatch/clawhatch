/**
 * Sandbox Configuration checks (26-33).
 *
 * Checks sandbox mode, workspace access, elevated tools,
 * Docker network isolation, and browser host control.
 */

import { Severity, type Finding, type OpenClawConfig } from "../types.js";

export async function runSandboxChecks(
  config: OpenClawConfig
): Promise<Finding[]> {
  const findings: Finding[] = [];

  // Check 26: Sandbox mode enabled
  const sandboxMode = config.sandbox?.mode;
  if (sandboxMode === "off" || sandboxMode === "disabled") {
    findings.push({
      id: "SANDBOX-001",
      severity: Severity.High,
      confidence: "high",
      category: "Sandbox Configuration",
      title: "Sandbox disabled",
      description: `Sandbox mode is "${sandboxMode}" — all tool execution runs on the host`,
      risk: "Malicious or buggy tool calls execute directly on your system with no isolation",
      remediation: 'Set sandbox.mode to "all" or "non-main"',
      autoFixable: true,
      fixType: "behavioral",
    });
  }

  // Check 27: Sandbox scope appropriate
  if (config.sandbox?.scope) {
    const scope = config.sandbox.scope;
    if (scope === "none" || scope === "minimal") {
      findings.push({
        id: "SANDBOX-002",
        severity: Severity.Medium,
        confidence: "high",
        category: "Sandbox Configuration",
        title: "Sandbox scope is minimal",
        description: `Sandbox scope "${scope}" provides limited isolation`,
        risk: "Tool execution may still access sensitive host resources",
        remediation: "Consider increasing sandbox scope for better isolation",
        autoFixable: false,
      });
    }
  }

  // Check 28: workspaceAccess
  const wsAccess = config.sandbox?.workspaceAccess;
  if (wsAccess === "rw") {
    findings.push({
      id: "SANDBOX-003",
      severity: Severity.Medium,
      confidence: "high",
      category: "Sandbox Configuration",
      title: "Sandbox has read-write workspace access",
      description: 'workspace access is "rw" — sandboxed tools can modify workspace files',
      risk: "A compromised tool could alter SOUL.md, skills, or other workspace files",
      remediation: 'Set sandbox.workspaceAccess to "ro" (read-only) unless write access is required',
      autoFixable: false,
    });
  }

  // Check 29: tools.elevated list is minimal
  const elevated = config.tools?.elevated || [];
  if (elevated.length > 5) {
    findings.push({
      id: "SANDBOX-004",
      severity: Severity.Medium,
      confidence: "high",
      category: "Sandbox Configuration",
      title: "Many elevated tools configured",
      description: `${elevated.length} tools have elevated privileges (recommended: <5)`,
      risk: "Each elevated tool bypasses sandbox restrictions",
      remediation: "Review tools.elevated and remove any that don't require elevation",
      autoFixable: false,
    });
  }

  // Check 30: Elevated tools documentation
  if (elevated.length > 0) {
    // We can't easily check if they're documented — flag as suggestion
    findings.push({
      id: "SANDBOX-005",
      severity: Severity.Low,
      confidence: "low",
      category: "Sandbox Configuration",
      title: "Verify elevated tools are documented",
      description: `${elevated.length} elevated tool(s): ${elevated.slice(0, 5).join(", ")}${elevated.length > 5 ? "..." : ""}`,
      risk: "Undocumented elevated tools may be unnecessary or forgotten",
      remediation: "Add comments in openclaw.json explaining why each tool needs elevation",
      autoFixable: false,
    });
  }

  // Check 31: Docker network is "none" (default)
  if (config.sandbox?.docker?.network && config.sandbox.docker.network !== "none") {
    findings.push({
      id: "SANDBOX-006",
      severity: Severity.High,
      confidence: "high",
      category: "Sandbox Configuration",
      title: "Docker sandbox has network access",
      description: `Docker network is "${config.sandbox.docker.network}" (should be "none")`,
      risk: "Sandboxed tools can make network requests — potential data exfiltration",
      remediation: 'Set sandbox.docker.network to "none" unless network access is required',
      autoFixable: true,
      fixType: "behavioral",
    });
  }

  // Check 32: No docker socket mounted
  if (config.sandbox?.docker?.socketMounted === true) {
    findings.push({
      id: "SANDBOX-007",
      severity: Severity.Critical,
      confidence: "high",
      category: "Sandbox Configuration",
      title: "Docker socket mounted in sandbox",
      description: "Docker socket is mounted — sandboxed tools have full Docker API access",
      risk: "Container escape — tools can create privileged containers, access host filesystem",
      remediation: "Remove docker socket mount from sandbox configuration",
      autoFixable: true,
      fixType: "safe",
    });
  }

  // Check 33: Browser host control
  if (config.sandbox?.browser?.allowHostControl === true) {
    findings.push({
      id: "SANDBOX-008",
      severity: Severity.Medium,
      confidence: "medium",
      category: "Sandbox Configuration",
      title: "Browser host control enabled in sandbox",
      description: "sandbox.browser.allowHostControl is true",
      risk: "Sandboxed browser can control host browser — potential for session hijacking",
      remediation: "Set sandbox.browser.allowHostControl to false unless explicitly needed",
      autoFixable: true,
      fixType: "behavioral",
    });
  }

  return findings;
}
