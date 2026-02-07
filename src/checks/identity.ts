/**
 * Identity & Access checks (1-15).
 *
 * Checks DM policies, allowlists, mention patterns, pairing config,
 * access groups, OAuth permissions, API key rotation, and identity links.
 */

import { Severity, type Confidence, type Finding, type OpenClawConfig } from "../types.js";
import { stat, access, constants } from "node:fs/promises";
import { platform } from "node:os";

type CheckFn = (
  config: OpenClawConfig,
  files: { credentialFiles: string[]; authProfileFiles: string[] }
) => Promise<Finding[]>;

export const runIdentityChecks: CheckFn = async (config, files) => {
  const findings: Finding[] = [];

  // Check 1: DM policy per channel
  if (config.channels) {
    for (const [name, ch] of Object.entries(config.channels)) {
      if (ch.dmPolicy === "open") {
        findings.push({
          id: "IDENTITY-001",
          severity: Severity.Critical,
          confidence: "high",
          category: "Identity & Access",
          title: `DM policy set to "open" for ${name}`,
          description: `Channel "${name}" accepts DMs from anyone without pairing or allowlist`,
          risk: "Any user on this platform can message your agent and potentially exploit it",
          remediation: `Set channels.${name}.dmPolicy to "pairing" or "allowlist"`,
          autoFixable: true,
          fixType: "behavioral",
        });
      }
    }
  }

  // Check 2: allowFrom wildcards
  if (config.channels) {
    for (const [name, ch] of Object.entries(config.channels)) {
      if (ch.allowFrom?.includes("*")) {
        findings.push({
          id: "IDENTITY-002",
          severity: Severity.High,
          confidence: "high",
          category: "Identity & Access",
          title: `Wildcard "*" in allowFrom for ${name}`,
          description: `Channel "${name}" allows messages from everyone via wildcard`,
          risk: "Effectively the same as open DM policy — anyone can interact",
          remediation: `Replace "*" with specific user IDs in channels.${name}.allowFrom`,
          autoFixable: false,
        });
      }
    }
  }

  // Check 3: Group policy per channel
  if (config.channels) {
    for (const [name, ch] of Object.entries(config.channels)) {
      if (ch.groupPolicy === "open") {
        findings.push({
          id: "IDENTITY-003",
          severity: Severity.High,
          confidence: "high",
          category: "Identity & Access",
          title: `Group policy set to "open" for ${name}`,
          description: `Channel "${name}" responds to all group messages without restriction`,
          risk: "Bot can be triggered by anyone in any group it's added to",
          remediation: `Set channels.${name}.groupPolicy to "allowlist"`,
          autoFixable: true,
          fixType: "behavioral",
        });
      }
    }
  }

  // Check 4: groupAllowFrom configured
  if (config.channels) {
    for (const [name, ch] of Object.entries(config.channels)) {
      if (
        ch.groupPolicy === "allowlist" &&
        (!ch.groupAllowFrom || ch.groupAllowFrom.length === 0)
      ) {
        findings.push({
          id: "IDENTITY-004",
          severity: Severity.Medium,
          confidence: "high",
          category: "Identity & Access",
          title: `Empty groupAllowFrom for ${name}`,
          description: `Channel "${name}" has group allowlist policy but no groups configured`,
          risk: "Group policy is effectively blocking all groups — may be unintentional",
          remediation: `Add group IDs to channels.${name}.groupAllowFrom`,
          autoFixable: false,
        });
      }
    }
  }

  // Check 5: requireMention in groups
  if (config.channels) {
    for (const [name, ch] of Object.entries(config.channels)) {
      if (ch.groupPolicy && ch.requireMention === false) {
        findings.push({
          id: "IDENTITY-005",
          severity: Severity.Medium,
          confidence: "high",
          category: "Identity & Access",
          title: `requireMention disabled for ${name}`,
          description: `Channel "${name}" responds to all group messages without requiring @mention`,
          risk: "Agent processes every message in group — higher prompt injection surface",
          remediation: `Set channels.${name}.requireMention to true`,
          autoFixable: true,
          fixType: "behavioral",
        });
      }
    }
  }

  // Check 6: Mention patterns non-trivial (low confidence)
  if (config.channels) {
    for (const [name, ch] of Object.entries(config.channels)) {
      if (ch.mentionPatterns) {
        const trivial = ch.mentionPatterns.every(
          (p) => p === "@bot" || p === "bot" || p.length <= 3
        );
        if (trivial) {
          findings.push({
            id: "IDENTITY-006",
            severity: Severity.Low,
            confidence: "low",
            category: "Identity & Access",
            title: `Trivial mention pattern for ${name}`,
            description: `Channel "${name}" uses generic mention patterns that may trigger on common words`,
            risk: "Agent may respond to unintended messages in group conversations",
            remediation: `Use more specific mention patterns for ${name}`,
            autoFixable: false,
          });
        }
      }
    }
  }

  // Check 7: Pairing store TTL
  if (config.pairing && !config.pairing.storeTTL) {
    findings.push({
      id: "IDENTITY-007",
      severity: Severity.Low,
      confidence: "high",
      category: "Identity & Access",
      title: "No pairing store TTL configured",
      description: "Pairing codes never expire — old codes could be reused",
      risk: "Leaked pairing codes remain valid indefinitely",
      remediation: "Set pairing.storeTTL to a reasonable value (e.g., 86400 for 24h)",
      autoFixable: true,
      fixType: "safe",
    });
  }

  // Check 8: Session dmScope
  if (config.channels) {
    for (const [name, ch] of Object.entries(config.channels)) {
      const accounts = ch.accounts || [];
      if (accounts.length > 1 && ch.dmScope !== "per-channel-peer") {
        findings.push({
          id: "IDENTITY-008",
          severity: Severity.Medium,
          confidence: "high",
          category: "Identity & Access",
          title: `Shared session scope for multi-account ${name}`,
          description: `Channel "${name}" has multiple accounts but doesn't use per-channel-peer session scope`,
          risk: "Conversations from different users may bleed into each other",
          remediation: `Set channels.${name}.dmScope to "per-channel-peer"`,
          autoFixable: true,
          fixType: "behavioral",
        });
      }
    }
  }

  // Check 9: commands.useAccessGroups
  if (config.commands && config.commands.useAccessGroups === false) {
    findings.push({
      id: "IDENTITY-009",
      severity: Severity.Medium,
      confidence: "high",
      category: "Identity & Access",
      title: "Access groups disabled for commands",
      description: "commands.useAccessGroups is false — all users have equal command access",
      risk: "No role-based access control for agent commands",
      remediation: "Set commands.useAccessGroups to true and configure access groups",
      autoFixable: true,
      fixType: "behavioral",
    });
  }

  // Check 10: No wildcards in any allowlist
  if (config.channels) {
    for (const [name, ch] of Object.entries(config.channels)) {
      if (ch.groupAllowFrom?.includes("*")) {
        findings.push({
          id: "IDENTITY-010",
          severity: Severity.High,
          confidence: "high",
          category: "Identity & Access",
          title: `Wildcard in groupAllowFrom for ${name}`,
          description: `Channel "${name}" has wildcard "*" in group allowlist`,
          risk: "Any group can trigger the agent — effectively open policy",
          remediation: `Replace "*" with specific group IDs in channels.${name}.groupAllowFrom`,
          autoFixable: false,
        });
      }
    }
  }

  // Check 11: Multiple accounts have per-account policies
  if (config.channels) {
    for (const [name, ch] of Object.entries(config.channels)) {
      const accounts = ch.accounts || [];
      if (accounts.length > 1 && !ch.dmPolicy) {
        findings.push({
          id: "IDENTITY-011",
          severity: Severity.Medium,
          confidence: "high",
          category: "Identity & Access",
          title: `No DM policy for multi-account ${name}`,
          description: `Channel "${name}" has ${accounts.length} accounts but no explicit DM policy`,
          risk: "Default policy may be too permissive for some accounts",
          remediation: `Set explicit dmPolicy for channels.${name}`,
          autoFixable: false,
        });
      }
    }
  }

  // Check 12: OAuth token file permissions
  for (const credFile of files.credentialFiles) {
    if (platform() === "win32") {
      // On Windows, check basic read access — can't check Unix permissions
      try {
        await access(credFile, constants.R_OK);
        // File exists and is readable — can't check ACLs without icacls
        // We'll flag this as informational on Windows
      } catch {
        // File not readable — different issue, skip
      }
    } else {
      try {
        const s = await stat(credFile);
        const mode = s.mode & 0o777;
        if (mode !== 0o600) {
          findings.push({
            id: "IDENTITY-012",
            severity: Severity.High,
            confidence: "high",
            category: "Identity & Access",
            title: "OAuth token file has loose permissions",
            description: `${credFile} has permissions ${mode.toString(8)} (should be 600)`,
            risk: "Other users on this system can read your OAuth tokens",
            remediation: `Run: chmod 600 "${credFile}"`,
            autoFixable: true,
            fixType: "safe",
            file: credFile,
          });
        }
      } catch {
        // Can't stat — file may not exist
      }
    }
  }

  // Check 13: API key rotation schedule (low confidence)
  // Only fire if we actually found credential files or auth profiles to rotate
  // Also check for rotation evidence: multiple key patterns, recent .env modification, etc.
  if (files.credentialFiles.length > 0 || files.authProfileFiles.length > 0) {
    // Heuristic: check if there are signs of rotation (multiple similar key patterns, _old suffix, etc.)
    let hasRotationEvidence = false;

    // Check credential files for rotation patterns
    for (const credFile of [...files.credentialFiles, ...files.authProfileFiles].slice(0, 5)) {
      try {
        const { readFile } = await import("node:fs/promises");
        const content = await readFile(credFile, "utf-8");
        // Look for rotation-related patterns
        if (/(?:_old|_backup|_previous|rotated|expired)/i.test(content) ||
            /(?:rotation|rotate_at|expires_at|valid_until)/i.test(content)) {
          hasRotationEvidence = true;
          break;
        }
      } catch {
        // Can't read file
      }
    }

    if (!hasRotationEvidence) {
      findings.push({
        id: "IDENTITY-013",
        severity: Severity.Low,
        confidence: "low",
        category: "Identity & Access",
        title: "No API key rotation evidence",
        description: `${files.credentialFiles.length + files.authProfileFiles.length} credential file(s) found with no rotation schedule or documentation`,
        risk: "Long-lived API keys increase exposure window if compromised",
        remediation: "Document your key rotation schedule and set calendar reminders",
        autoFixable: false,
      });
    }
  }

  // Check 14: Channel bot tokens in env, not config
  // We check this in secrets.ts more thoroughly — here we check config structure
  if (config.channels) {
    for (const [name, ch] of Object.entries(config.channels)) {
      const chStr = JSON.stringify(ch);
      // Check if token values are present as literals (not ${VAR} references)
      if (
        chStr.includes("token") &&
        !chStr.includes("${") &&
        chStr.match(/"token"\s*:\s*"[^"]{10,}"/)
      ) {
        findings.push({
          id: "IDENTITY-014",
          severity: Severity.High,
          confidence: "high",
          category: "Identity & Access",
          title: `Bot token hardcoded in config for ${name}`,
          description: `Channel "${name}" appears to have a token value directly in openclaw.json`,
          risk: "Token will be exposed if config file is shared or committed to git",
          remediation: `Move token to .env file and reference as \${${name.toUpperCase()}_TOKEN}`,
          autoFixable: false,
        });
      }
    }
  }

  // Check 15: Identity links reviewed
  if (config.identityLinks && Array.isArray(config.identityLinks) && config.identityLinks.length > 0) {
    findings.push({
      id: "IDENTITY-015",
      severity: Severity.Low,
      confidence: "low",
      category: "Identity & Access",
      title: "Identity links configured — verify they're intentional",
      description: `${config.identityLinks.length} identity link(s) found — these merge sessions across accounts`,
      risk: "Accidental identity links could merge unrelated conversations",
      remediation: "Review identityLinks in openclaw.json and confirm each is intentional",
      autoFixable: false,
    });
  }

  return findings;
};
