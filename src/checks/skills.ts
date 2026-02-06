/**
 * Skill Security checks (SKILLS-001 to SKILLS-012).
 *
 * Checks for untrusted skill sources, dangerous dependencies,
 * sandboxing, code injection, and configuration hygiene.
 */

import { Severity, type Finding, type OpenClawConfig, type DiscoveredFiles } from "../types.js";
import { readFile } from "node:fs/promises";
import { basename, dirname } from "node:path";

const NETWORK_MODULES = [
  "axios", "node-fetch", "got", "request", "http", "https", "net", "dgram", "ws", "socket.io",
];

const SYSTEM_PATHS = [
  "/etc/", "/usr/", "/var/", "/sys/", "/proc/",
  "C:\\Windows", "C:\\Program Files", "HKEY_",
];

const NATIVE_MODULES = [
  "node-gyp", "ffi-napi", "ref-napi", "bindings", "node-addon-api",
];

// FIX: Tightened credential patterns — previous patterns like /secret/i and /token/i
// had very high false-positive rates on SKILL.md files which discuss these concepts
// in documentation. Now require assignment/access syntax context.
const CREDENTIAL_PATTERNS = [
  /process\.env\.[A-Z_]+/,           // process.env.SOME_VAR (specific env access)
  /(?:api[_-]?key|password|secret|token)\s*[:=]\s*["'][^"']+["']/i,  // key="value" patterns
  /credential[s]?\s*[:=]/i,          // credential assignments
];

export async function runSkillChecks(
  config: OpenClawConfig,
  files: DiscoveredFiles
): Promise<Finding[]> {
  const findings: Finding[] = [];

  // SKILLS-001: Untrusted skill sources
  for (const pkgFile of files.skillPackageFiles.slice(0, 10)) {
    try {
      const content = await readFile(pkgFile, "utf-8");
      const pkg = JSON.parse(content);
      const deps = { ...pkg.dependencies, ...pkg.devDependencies };
      const untrusted = Object.keys(deps).filter((d) =>
        deps[d].startsWith("git+") || deps[d].startsWith("http") || deps[d].includes("github.com")
      );
      if (untrusted.length > 0) {
        findings.push({
          id: "SKILLS-001",
          severity: Severity.High,
          confidence: "high",
          category: "Skill Security",
          title: "Skill uses untrusted dependency sources",
          description: `${basename(dirname(pkgFile))} pulls from git/URL sources: ${untrusted.slice(0, 3).join(", ")}`,
          risk: "Dependencies from URLs or git repos can be modified without notice",
          remediation: "Use npm registry packages with version pinning instead of git/URL sources",
          autoFixable: false,
          file: pkgFile,
        });
      }
    } catch {
      // Can't parse
    }
  }

  // SKILLS-002: Outdated skill dependencies
  for (const pkgFile of files.skillPackageFiles.slice(0, 10)) {
    try {
      const content = await readFile(pkgFile, "utf-8");
      const pkg = JSON.parse(content);
      const deps = { ...pkg.dependencies, ...pkg.devDependencies };
      const wildcard = Object.entries(deps).filter(
        ([, v]) => v === "*" || v === "latest"
      );
      if (wildcard.length > 0) {
        findings.push({
          id: "SKILLS-002",
          severity: Severity.Medium,
          confidence: "medium",
          category: "Skill Security",
          title: "Skill has unpinned dependencies",
          description: `${basename(dirname(pkgFile))} uses "*" or "latest" for ${wildcard.length} dependencies`,
          risk: "Unpinned dependencies can introduce breaking changes or vulnerabilities",
          remediation: "Pin all dependencies to specific versions",
          autoFixable: false,
          file: pkgFile,
        });
      }
    } catch {
      // Can't parse
    }
  }

  // SKILLS-003: Skills with network access
  for (const pkgFile of files.skillPackageFiles.slice(0, 10)) {
    try {
      const content = await readFile(pkgFile, "utf-8");
      const pkg = JSON.parse(content);
      const allDeps = Object.keys({ ...pkg.dependencies, ...pkg.devDependencies });
      const networkDeps = allDeps.filter((d) =>
        NETWORK_MODULES.some((n) => d.includes(n))
      );
      if (networkDeps.length > 0) {
        findings.push({
          id: "SKILLS-003",
          severity: Severity.Medium,
          confidence: "medium",
          category: "Skill Security",
          title: "Skill has network dependencies",
          description: `${basename(dirname(pkgFile))} includes network packages: ${networkDeps.join(", ")}`,
          risk: "Skills with network access can exfiltrate data or contact external services",
          remediation: "Ensure network access is necessary and restrict outbound connections",
          autoFixable: false,
          file: pkgFile,
        });
      }
    } catch {
      // Can't parse
    }
  }

  // SKILLS-004: Skills modify system files
  for (const skillFile of files.skillFiles.slice(0, 10)) {
    try {
      const content = await readFile(skillFile, "utf-8");
      const hasSystemPath = SYSTEM_PATHS.some((p) => content.includes(p));
      if (hasSystemPath) {
        findings.push({
          id: "SKILLS-004",
          severity: Severity.High,
          confidence: "high",
          category: "Skill Security",
          title: "Skill references system paths",
          description: `${basename(skillFile)} references system directories (e.g., /etc/, C:\\Windows)`,
          risk: "Skills that modify system files can compromise host security",
          remediation: "Restrict skill file access to the workspace directory only",
          autoFixable: false,
          file: skillFile,
        });
        break;
      }
    } catch {
      // Can't read
    }
  }

  // SKILLS-005: No skill sandboxing
  if (files.skillFiles.length > 0 && config.skills?.sandboxed !== true) {
    findings.push({
      id: "SKILLS-005",
      severity: Severity.Medium,
      confidence: "medium",
      category: "Skill Security",
      title: "Skills not sandboxed",
      description: `${files.skillFiles.length} skills installed without sandbox isolation`,
      risk: "Unsandboxed skills can access host filesystem, network, and environment",
      remediation: "Set skills.sandboxed: true to isolate skill execution",
      autoFixable: false,
    });
  }

  // SKILLS-006: Skill package-lock missing
  for (const pkgFile of files.skillPackageFiles.slice(0, 10)) {
    const lockFile = pkgFile.replace("package.json", "package-lock.json");
    const yarnLock = pkgFile.replace("package.json", "yarn.lock");
    const pnpmLock = pkgFile.replace("package.json", "pnpm-lock.yaml");
    try {
      await readFile(lockFile, "utf-8");
    } catch {
      try {
        await readFile(yarnLock, "utf-8");
      } catch {
        try {
          await readFile(pnpmLock, "utf-8");
        } catch {
          findings.push({
            id: "SKILLS-006",
            severity: Severity.Medium,
            confidence: "medium",
            category: "Skill Security",
            title: "Skill has no lockfile",
            description: `${basename(dirname(pkgFile))} has no package-lock.json, yarn.lock, or pnpm-lock.yaml`,
            risk: "Without a lockfile, dependency resolution is non-deterministic",
            remediation: "Generate a lockfile by running npm install, yarn, or pnpm install",
            autoFixable: false,
            file: pkgFile,
          });
        }
      }
    }
  }

  // SKILLS-007: Skills use eval/Function
  for (const skillFile of files.skillFiles.slice(0, 10)) {
    try {
      const content = await readFile(skillFile, "utf-8");
      if (/\beval\s*\(/.test(content) || /new\s+Function\s*\(/.test(content)) {
        findings.push({
          id: "SKILLS-007",
          severity: Severity.High,
          confidence: "high",
          category: "Skill Security",
          title: "Skill uses eval() or new Function()",
          description: `${basename(skillFile)} uses dynamic code evaluation`,
          risk: "eval/Function enables arbitrary code execution within the skill",
          remediation: "Replace eval/Function with static code paths",
          autoFixable: false,
          file: skillFile,
        });
        break;
      }
    } catch {
      // Can't read
    }
  }

  // SKILLS-008: Skills load native modules
  for (const pkgFile of files.skillPackageFiles.slice(0, 10)) {
    try {
      const content = await readFile(pkgFile, "utf-8");
      const pkg = JSON.parse(content);
      const allDeps = Object.keys({ ...pkg.dependencies, ...pkg.devDependencies });
      const nativeDeps = allDeps.filter((d) =>
        NATIVE_MODULES.some((n) => d.includes(n))
      );
      if (nativeDeps.length > 0 || pkg.gypfile || pkg.scripts?.install?.includes("node-gyp")) {
        findings.push({
          id: "SKILLS-008",
          severity: Severity.High,
          confidence: "high",
          category: "Skill Security",
          title: "Skill loads native modules",
          description: `${basename(dirname(pkgFile))} uses native addons: ${nativeDeps.join(", ") || "gyp build"}`,
          risk: "Native modules run outside V8 sandbox and can access raw memory",
          remediation: "Use pure JavaScript alternatives where possible",
          autoFixable: false,
          file: pkgFile,
        });
      }
    } catch {
      // Can't parse
    }
  }

  // SKILLS-009: Skills access credentials
  for (const skillFile of files.skillFiles.slice(0, 10)) {
    try {
      const content = await readFile(skillFile, "utf-8");
      const accessesCreds = CREDENTIAL_PATTERNS.some((p) => p.test(content));
      if (accessesCreds) {
        findings.push({
          id: "SKILLS-009",
          severity: Severity.High,
          confidence: "medium",
          category: "Skill Security",
          title: "Skill accesses credentials",
          description: `${basename(skillFile)} references environment variables, tokens, or secrets`,
          risk: "Skills with credential access can exfiltrate API keys or tokens",
          remediation: "Use a secrets manager; don't pass credentials directly to skills",
          autoFixable: false,
          file: skillFile,
        });
        break;
      }
    } catch {
      // Can't read
    }
  }

  // SKILLS-010: No skill signature verification
  if (files.skillFiles.length > 0 && config.skills?.verifySignatures !== true) {
    findings.push({
      id: "SKILLS-010",
      severity: Severity.Low,
      confidence: "low",
      category: "Skill Security",
      title: "No skill signature verification",
      description: "Installed skills are not verified against signatures or checksums",
      risk: "Modified or tampered skills will be loaded without detection",
      remediation: "Enable skills.verifySignatures: true to verify skill integrity",
      autoFixable: false,
    });
  }

  // SKILLS-011: Skills auto-update
  if (config.skills?.autoUpdate === true) {
    findings.push({
      id: "SKILLS-011",
      severity: Severity.Medium,
      confidence: "high",
      category: "Skill Security",
      title: "Skills auto-update enabled",
      description: "Skills are configured to auto-update without manual review",
      risk: "Automatic updates can introduce malicious or broken code without notice",
      remediation: "Disable skills.autoUpdate and review updates manually before applying",
      autoFixable: false,
    });
  }

  // SKILLS-012: Workspace skill override
  if (files.workspaceDir) {
    const managedSkills = files.skillFiles.filter((f) =>
      f.startsWith(files.openclawDir)
    );
    const workspaceSkills = files.skillFiles.filter((f) =>
      files.workspaceDir && f.startsWith(files.workspaceDir)
    );
    if (managedSkills.length > 0 && workspaceSkills.length > 0) {
      findings.push({
        id: "SKILLS-012",
        severity: Severity.Medium,
        confidence: "medium",
        category: "Skill Security",
        title: "Workspace skills may override managed skills",
        description: `${workspaceSkills.length} workspace skills alongside ${managedSkills.length} managed skills`,
        risk: "Workspace skills can shadow managed skills, changing behavior unexpectedly",
        remediation: "Ensure workspace skill names don't conflict with managed skills",
        autoFixable: false,
      });
    }
  }

  return findings;
}
