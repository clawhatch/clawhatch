/**
 * Tool Security checks (TOOLS-001 to TOOLS-020).
 *
 * Checks for elevated tool risks, command injection, docker exposure,
 * missing audit trails, and tool configuration hygiene.
 */

import { Severity, type Finding, type OpenClawConfig, type DiscoveredFiles } from "../types.js";
import { readFile } from "node:fs/promises";
import { basename } from "node:path";
import { readFileCapped } from "../utils.js";

const DANGEROUS_TOOLS = ["exec", "shell", "bash", "sh", "cmd", "powershell", "terminal", "run_command"];

const EVAL_PATTERNS = [
  /\beval\s*\(/,
  /\bexec\s*\(/,
  /\bsubprocess\b/,
  /\bchild_process\b/,
  /\bspawn\s*\(/,
  /new\s+Function\s*\(/,
];

const SUDO_PATTERNS = [
  /\bsudo\b/,
  /\bdoas\b/,
  /\brunas\b/,
];

export async function runToolChecks(
  config: OpenClawConfig,
  files: DiscoveredFiles
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const elevated = config.tools?.elevated ?? [];

  // TOOLS-001: Excessive elevated tools (>5)
  if (elevated.length > 5) {
    findings.push({
      id: "TOOLS-001",
      severity: Severity.Medium,
      confidence: "high",
      category: "Tool Security",
      title: "Excessive elevated tools",
      description: `${elevated.length} tools are elevated — large attack surface`,
      risk: "Each elevated tool bypasses sandbox restrictions and increases exposure",
      remediation: "Reduce elevated tools to the minimum needed (ideally ≤5)",
      autoFixable: false,
    });
  }

  // TOOLS-002: Dangerous tools elevated (exec/shell/bash)
  const dangerousElevated = elevated.filter((t) =>
    DANGEROUS_TOOLS.some((d) => t.toLowerCase().includes(d))
  );
  if (dangerousElevated.length > 0) {
    findings.push({
      id: "TOOLS-002",
      severity: Severity.Critical,
      confidence: "high",
      category: "Tool Security",
      title: "Dangerous tools elevated",
      description: `Shell/exec tools elevated: ${dangerousElevated.join(", ")}`,
      risk: "Elevated shell access allows arbitrary command execution without sandbox",
      remediation: "Remove shell/exec from elevated tools and use specific, scoped tools instead",
      autoFixable: false,
    });
  }

  // TOOLS-003: useAccessGroups not enabled
  if (elevated.length > 0 && config.tools?.useAccessGroups !== true) {
    findings.push({
      id: "TOOLS-003",
      severity: Severity.Medium,
      confidence: "high",
      category: "Tool Security",
      title: "Tool access groups not enabled",
      description: "Tools are elevated but useAccessGroups is not enabled",
      risk: "All users/agents get the same tool access — no role-based control",
      remediation: "Set tools.useAccessGroups: true and define access groups per role",
      autoFixable: false,
    });
  }

  // TOOLS-004: No tool allowlist
  if (!config.tools?.allowlist || config.tools.allowlist.length === 0) {
    findings.push({
      id: "TOOLS-004",
      severity: Severity.Medium,
      confidence: "medium",
      category: "Tool Security",
      title: "No tool allowlist configured",
      description: "No explicit allowlist of permitted tools — all tools may be available",
      risk: "Agents can use any available tool without restriction",
      remediation: "Configure tools.allowlist with only the tools your agent needs",
      autoFixable: false,
    });
  }

  // TOOLS-005: Exec tool unrestricted
  const hasExec = elevated.some((t) => t.toLowerCase().includes("exec"));
  if (hasExec && !config.tools?.useAccessGroups) {
    findings.push({
      id: "TOOLS-005",
      severity: Severity.High,
      confidence: "high",
      category: "Tool Security",
      title: "Exec tool elevated without constraints",
      description: "exec/run tool is elevated with no access group restrictions",
      risk: "Any agent or user can execute arbitrary commands via the exec tool",
      remediation: "Add access group constraints or remove exec from elevated tools",
      autoFixable: false,
    });
  }

  // TOOLS-006: Browser relay without constraints
  if (config.sandbox?.browser?.allowHostControl === true) {
    findings.push({
      id: "TOOLS-006",
      severity: Severity.Medium,
      confidence: "medium",
      category: "Tool Security",
      title: "Browser host control enabled",
      description: "Browser relay allows host-level control without documented constraints",
      risk: "Agent can navigate to arbitrary URLs, read cookies, or interact with authenticated sessions",
      remediation: "Restrict browser access to specific domains or disable host control",
      autoFixable: false,
    });
  }

  // TOOLS-007: File write too broad
  if (config.sandbox?.workspaceAccess === "rw" && !config.tools?.allowlist) {
    findings.push({
      id: "TOOLS-007",
      severity: Severity.Medium,
      confidence: "low",
      category: "Tool Security",
      title: "Unrestricted file write access",
      description: "Workspace has read-write access with no tool allowlist to limit write scope",
      risk: "Agent can modify any file in the workspace without restriction",
      remediation: "Use a tool allowlist or restrict workspace access to read-only where possible",
      autoFixable: false,
    });
  }

  // TOOLS-008: Docker socket referenced in command files
  for (const cmdFile of files.customCommandFiles) {
    try {
      const content = await readFile(cmdFile, "utf-8");
      if (/docker\.sock/i.test(content) || /\/var\/run\/docker/i.test(content)) {
        findings.push({
          id: "TOOLS-008",
          severity: Severity.Critical,
          confidence: "high",
          category: "Tool Security",
          title: "Docker socket referenced in custom command",
          description: `${basename(cmdFile)} references docker.sock — full host access`,
          risk: "Docker socket access grants root-equivalent access to the host system",
          remediation: "Remove docker.sock references from custom commands; use rootless Docker instead",
          autoFixable: false,
          file: cmdFile,
        });
        break;
      }
    } catch {
      // Can't read file
    }
  }

  // TOOLS-009: Host network mode in custom commands
  for (const cmdFile of files.customCommandFiles) {
    try {
      const content = await readFile(cmdFile, "utf-8");
      if (/--net[=\s]+host/i.test(content) || /--network[=\s]+host/i.test(content)) {
        findings.push({
          id: "TOOLS-009",
          severity: Severity.High,
          confidence: "high",
          category: "Tool Security",
          title: "Host network mode in custom command",
          description: `${basename(cmdFile)} uses --net=host — container shares host network`,
          risk: "Container can access all host network interfaces and services",
          remediation: "Use bridge or none network mode instead of host",
          autoFixable: false,
          file: cmdFile,
        });
        break;
      }
    } catch {
      // Can't read file
    }
  }

  // TOOLS-010: Sudo/doas/runas in custom commands
  for (const cmdFile of files.customCommandFiles) {
    try {
      const content = await readFile(cmdFile, "utf-8");
      const hasSudo = SUDO_PATTERNS.some((p) => p.test(content));
      if (hasSudo) {
        findings.push({
          id: "TOOLS-010",
          severity: Severity.High,
          confidence: "high",
          category: "Tool Security",
          title: "Privilege escalation in custom command",
          description: `${basename(cmdFile)} contains sudo/doas/runas — escalates privileges`,
          risk: "Custom commands running as root bypass all sandbox protections",
          remediation: "Remove privilege escalation from custom commands; run with least privilege",
          autoFixable: false,
          file: cmdFile,
        });
        break;
      }
    } catch {
      // Can't read file
    }
  }

  // TOOLS-011: Eval/exec in skill files
  for (const skillFile of files.skillFiles) {
    try {
      const content = await readFile(skillFile, "utf-8");
      const hasEval = EVAL_PATTERNS.some((p) => p.test(content));
      if (hasEval) {
        findings.push({
          id: "TOOLS-011",
          severity: Severity.High,
          confidence: "high",
          category: "Tool Security",
          title: "Dynamic code execution in skill",
          description: `${basename(skillFile)} uses eval/exec/subprocess — code injection risk`,
          risk: "Skills with dynamic execution can run arbitrary code",
          remediation: "Replace eval/exec with static, validated alternatives",
          autoFixable: false,
          file: skillFile,
        });
        break;
      }
    } catch {
      // Can't read file
    }
  }

  // TOOLS-012: Custom tool override risk
  if (files.customCommandFiles.length > 0 && files.skillFiles.length > 0) {
    findings.push({
      id: "TOOLS-012",
      severity: Severity.Medium,
      confidence: "medium",
      category: "Tool Security",
      title: "Workspace tools may override managed tools",
      description: `${files.customCommandFiles.length} custom commands alongside ${files.skillFiles.length} skill files`,
      risk: "Custom workspace tools can shadow managed tools, changing behavior unexpectedly",
      remediation: "Review custom commands for naming conflicts with managed tools",
      autoFixable: false,
    });
  }

  // TOOLS-013: Missing tool documentation
  if (elevated.length > 0) {
    const hasClaudeMd = files.workspaceMarkdownFiles.some((f) =>
      basename(f).toUpperCase() === "CLAUDE.MD"
    );
    if (!hasClaudeMd) {
      findings.push({
        id: "TOOLS-013",
        severity: Severity.Low,
        confidence: "low",
        category: "Tool Security",
        title: "Elevated tools lack documentation",
        description: "No CLAUDE.md found to document elevated tool usage and constraints",
        risk: "Undocumented tool access makes security review difficult",
        remediation: "Create a CLAUDE.md that documents which tools are elevated and why",
        autoFixable: false,
      });
    }
  }

  // TOOLS-014: Tool version pinning
  if (files.skillPackageFiles.length > 0) {
    for (const pkgFile of files.skillPackageFiles.slice(0, 5)) {
      try {
        const content = await readFile(pkgFile, "utf-8");
        if (content.includes('"*"') || /"\^/.test(content) || /"~/.test(content)) {
          findings.push({
            id: "TOOLS-014",
            severity: Severity.Low,
            confidence: "low",
            category: "Tool Security",
            title: "Skill dependencies not version-pinned",
            description: `${basename(pkgFile)} uses loose version ranges (^, ~, *)`,
            risk: "Unpinned dependencies can introduce supply-chain vulnerabilities",
            remediation: "Pin exact versions in skill package.json dependencies",
            autoFixable: false,
            file: pkgFile,
          });
          break;
        }
      } catch {
        // Can't read
      }
    }
  }

  // TOOLS-015: Shell command history in session logs
  for (const logFile of files.sessionLogFiles.slice(0, 3)) {
    try {
      // FIX: Use capped read to avoid OOM on large session logs
      const content = await readFileCapped(logFile, 512 * 1024);
      const hasShellSecrets = /(?:password|token|secret|key)\s*[=:]\s*\S+/i.test(content) &&
        /(?:bash|shell|exec|run_command)/i.test(content);
      if (hasShellSecrets) {
        findings.push({
          id: "TOOLS-015",
          severity: Severity.Medium,
          confidence: "medium",
          category: "Tool Security",
          title: "Shell commands may contain secrets in logs",
          description: `Session log ${basename(logFile)} contains shell commands with potential secret values`,
          risk: "Shell command history in logs may expose passwords, tokens, or API keys",
          remediation: "Use environment variables instead of inline secrets in shell commands",
          autoFixable: false,
          file: logFile,
        });
        break;
      }
    } catch {
      // Can't read
    }
  }

  // TOOLS-016: Unrestricted file deletion
  if (config.sandbox?.workspaceAccess === "rw" && !config.tools?.auditLog) {
    findings.push({
      id: "TOOLS-016",
      severity: Severity.Low,
      confidence: "low",
      category: "Tool Security",
      title: "File deletions not audited",
      description: "Workspace is read-write but no audit log is configured for file operations",
      risk: "Deleted files cannot be traced back to the action that removed them",
      remediation: "Enable tools.auditLog to track file modifications and deletions",
      autoFixable: false,
    });
  }

  // TOOLS-017: No command audit trail
  if (!config.tools?.auditLog) {
    findings.push({
      id: "TOOLS-017",
      severity: Severity.Medium,
      confidence: "low",
      category: "Tool Security",
      title: "No command audit trail",
      description: "Tool audit logging is not enabled — tool invocations are not tracked",
      risk: "Cannot trace which tools were called, when, or with what parameters",
      remediation: "Set tools.auditLog: true to enable tool invocation logging",
      autoFixable: false,
    });
  }

  // TOOLS-018: Dynamic tool loading from arbitrary paths
  for (const cmdFile of files.customCommandFiles) {
    try {
      const content = await readFile(cmdFile, "utf-8");
      if (/require\s*\(|import\s*\(|loadModule|dynamicImport/i.test(content)) {
        findings.push({
          id: "TOOLS-018",
          severity: Severity.Medium,
          confidence: "medium",
          category: "Tool Security",
          title: "Dynamic tool loading detected",
          description: `${basename(cmdFile)} dynamically loads modules at runtime`,
          risk: "Dynamically loaded tools can be swapped or injected by modifying the load path",
          remediation: "Use static imports and pin tool sources to known, trusted locations",
          autoFixable: false,
          file: cmdFile,
        });
        break;
      }
    } catch {
      // Can't read
    }
  }

  // TOOLS-019: Tool timeout missing
  if (!config.tools?.timeout) {
    findings.push({
      id: "TOOLS-019",
      severity: Severity.Low,
      confidence: "low",
      category: "Tool Security",
      title: "No tool timeout configured",
      description: "No timeout set for tool execution — tools can run indefinitely",
      risk: "Runaway tool executions can consume resources or hang the agent",
      remediation: "Set tools.timeout to a reasonable value (e.g., 30000ms)",
      autoFixable: false,
    });
  }

  // TOOLS-020: No rate limiting on tools
  if (!config.tools?.rateLimit) {
    findings.push({
      id: "TOOLS-020",
      severity: Severity.Low,
      confidence: "low",
      category: "Tool Security",
      title: "No rate limiting on tools",
      description: "No rate limit configured for tool invocations",
      risk: "Agent can invoke tools at unlimited rate, risking API abuse or resource exhaustion",
      remediation: "Set tools.rateLimit to limit invocations per minute",
      autoFixable: false,
    });
  }

  return findings;
}
