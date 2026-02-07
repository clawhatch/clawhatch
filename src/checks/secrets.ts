/**
 * Secret Scanning checks (34-43).
 *
 * Checks for hardcoded API keys, .env handling, file permissions,
 * secrets in markdown files, and session log leakage.
 */

import { Severity, type Finding, type OpenClawConfig, type DiscoveredFiles } from "../types.js";
import { stat, access, constants, readFile } from "node:fs/promises";
import { platform } from "node:os";
import { join, basename } from "node:path";
import { scanMarkdown } from "../parsers/markdown.js";
import { parseJsonl } from "../parsers/jsonl.js";
import { readFileCapped } from "../utils.js";

/** Patterns that suggest an API key value (not a ${VAR} reference) */
const API_KEY_PATTERNS = [
  /sk-[a-zA-Z0-9]{32,}/,
  /sk-ant-[a-zA-Z0-9\-]{32,}/,
  /AIza[a-zA-Z0-9_\-]{35}/,
  /AKIA[A-Z0-9]{16}/,
  /(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,}/,
  /(?:sk|pk)_(?:live|test)_[a-zA-Z0-9]{20,}/,
  /xox[bpras]-[a-zA-Z0-9\-]{10,}/,
];

export async function runSecretChecks(
  config: OpenClawConfig,
  configRaw: string | null,
  files: DiscoveredFiles,
  deep: boolean
): Promise<Finding[]> {
  const findings: Finding[] = [];

  // Check 34: No API keys in openclaw.json (use ${VAR} substitution)
  if (configRaw) {
    let totalKeyCount = 0;
    for (const pattern of API_KEY_PATTERNS) {
      // Use matchAll to count every occurrence, not just the first
      const matches = [...configRaw.matchAll(new RegExp(pattern, "g"))];
      totalKeyCount += matches.length;
    }
    if (totalKeyCount > 0) {
      findings.push({
        id: "SECRET-001",
        severity: Severity.Critical,
        confidence: "high",
        category: "Secret Scanning",
        title: "API key(s) found in openclaw.json",
        description: `${totalKeyCount} hardcoded API key(s) detected — move all to .env`,
        risk: "Keys will be exposed if config is shared, committed, or backed up",
        remediation: "Move keys to .env file and use ${VAR_NAME} substitution in config",
        autoFixable: false,
        file: files.configPath ?? undefined,
      });
    }
  }

  // Check 35: .env files exist and not in git (.gitignore check)
  if (files.envPath) {
    // Check if .gitignore exists and includes .env
    const gitignorePath = join(files.openclawDir, ".gitignore");
    try {
      const gitignore = await readFile(gitignorePath, "utf-8");
      if (!gitignore.includes(".env")) {
        findings.push({
          id: "SECRET-002",
          severity: Severity.High,
          confidence: "high",
          category: "Secret Scanning",
          title: ".env not in .gitignore",
          description: ".env file exists but is not listed in .gitignore",
          risk: "Secrets in .env could be accidentally committed to git",
          remediation: "Add .env to .gitignore",
          autoFixable: true,
          fixType: "safe",
          file: gitignorePath,
        });
      }
    } catch {
      // No .gitignore — flag it
      findings.push({
        id: "SECRET-002",
        severity: Severity.High,
        confidence: "high",
        category: "Secret Scanning",
        title: "No .gitignore found",
        description: "No .gitignore file in OpenClaw directory — .env and credentials may be committed",
        risk: "Secrets could be accidentally committed to git",
        remediation: "Create a .gitignore with: .env, credentials/, *.key",
        autoFixable: true,
        fixType: "safe",
      });
    }
  }

  // Checks 36-39: File permissions (Unix: chmod, Windows: icacls)
  if (platform() === "win32") {
    // FIX: Actually check Windows ACLs using icacls
    try {
      const { execFile: ef } = await import("node:child_process");
      const { promisify: p } = await import("node:util");
      const execAsync = p(ef);

      const { stdout } = await execAsync(
        "icacls",
        [files.openclawDir],
        { timeout: 5000, windowsHide: true }
      );

      // Check for overly permissive ACLs (Everyone, Users, or BUILTIN\Users with access)
      const dangerousGroups = /\b(Everyone|Users|BUILTIN\\Users|Authenticated Users)\s*:\s*\((?!N\))/i;
      if (dangerousGroups.test(stdout)) {
        findings.push({
          id: "SECRET-003",
          severity: Severity.High,
          confidence: "high",
          category: "Secret Scanning",
          title: "OpenClaw directory has permissive Windows ACLs",
          description: "~/.openclaw/ is accessible by other users on this system (Everyone/Users group has access)",
          risk: "Other users on this system can read your OpenClaw configuration and secrets",
          remediation: "Run: icacls \"%USERPROFILE%\\.openclaw\" /inheritance:r /grant:r \"%USERNAME%:F\"",
          autoFixable: false,
          file: files.openclawDir,
        });
      }
    } catch {
      // icacls failed or not available — fall back to informational message
      findings.push({
        id: "SECRET-003",
        severity: Severity.Low,
        confidence: "medium",
        category: "Secret Scanning",
        title: "Windows ACL check inconclusive",
        description: "Could not verify Windows file permissions (icacls unavailable or failed)",
        risk: "Windows ACLs should be reviewed manually to restrict access to OpenClaw files",
        remediation: "Verify that only your user account has access to ~/.openclaw/ via Windows Security settings",
        autoFixable: false,
      });
    }
  } else {
    // Check 36: ~/.openclaw/ directory permissions = 700
    try {
      const s = await stat(files.openclawDir);
      const mode = s.mode & 0o777;
      if (mode !== 0o700) {
        findings.push({
          id: "SECRET-003",
          severity: Severity.High,
          confidence: "high",
          category: "Secret Scanning",
          title: "OpenClaw directory has loose permissions",
          description: `~/.openclaw/ has permissions ${mode.toString(8)} (should be 700)`,
          risk: "Other users on this system can read your OpenClaw configuration and secrets",
          remediation: 'Run: chmod 700 ~/.openclaw/',
          autoFixable: true,
          fixType: "safe",
          file: files.openclawDir,
        });
      }
    } catch {
      // Can't stat
    }

    // Check 37: openclaw.json permissions = 600
    if (files.configPath) {
      try {
        const s = await stat(files.configPath);
        const mode = s.mode & 0o777;
        if (mode !== 0o600) {
          findings.push({
            id: "SECRET-004",
            severity: Severity.High,
            confidence: "high",
            category: "Secret Scanning",
            title: "Config file has loose permissions",
            description: `openclaw.json has permissions ${mode.toString(8)} (should be 600)`,
            risk: "Other users can read your agent configuration",
            remediation: 'Run: chmod 600 ~/.openclaw/openclaw.json',
            autoFixable: true,
            fixType: "safe",
            file: files.configPath,
          });
        }
      } catch {
        // Can't stat
      }
    }

    // Check 38: credentials/*.json permissions = 600
    for (const credFile of files.credentialFiles) {
      try {
        const s = await stat(credFile);
        const mode = s.mode & 0o777;
        if (mode !== 0o600) {
          findings.push({
            id: "SECRET-005",
            severity: Severity.High,
            confidence: "high",
            category: "Secret Scanning",
            title: `Credential file has loose permissions`,
            description: `${basename(credFile)} has permissions ${mode.toString(8)} (should be 600)`,
            risk: "Other users can read your credentials",
            remediation: `Run: chmod 600 "${credFile}"`,
            autoFixable: true,
            fixType: "safe",
            file: credFile,
          });
        }
      } catch {
        // Can't stat
      }
    }

    // Check 39: auth-profiles.json permissions = 600
    for (const authFile of files.authProfileFiles) {
      try {
        const s = await stat(authFile);
        const mode = s.mode & 0o777;
        if (mode !== 0o600) {
          findings.push({
            id: "SECRET-006",
            severity: Severity.High,
            confidence: "high",
            category: "Secret Scanning",
            title: "Auth profile has loose permissions",
            description: `${basename(authFile)} has permissions ${mode.toString(8)} (should be 600)`,
            risk: "Other users can read your API keys",
            remediation: `Run: chmod 600 "${authFile}"`,
            autoFixable: true,
            fixType: "safe",
            file: authFile,
          });
        }
      } catch {
        // Can't stat
      }
    }
  }

  // Checks 40-42: Secrets in markdown files
  const mdFilesToScan: Array<{ path: string; name: string; checkId: string }> = [];

  for (const mdFile of files.workspaceMarkdownFiles) {
    const name = basename(mdFile).toUpperCase();
    let checkId = "SECRET-010";
    if (name === "SOUL.MD") checkId = "SECRET-007";
    else if (name === "AGENTS.MD") checkId = "SECRET-008";
    else if (name === "TOOLS.MD") checkId = "SECRET-009";
    mdFilesToScan.push({ path: mdFile, name, checkId });
  }

  for (const { path, name, checkId } of mdFilesToScan) {
    try {
      const result = await scanMarkdown(path);
      if (result.secretMatches.length > 0) {
        const firstMatch = result.secretMatches[0];
        findings.push({
          id: checkId,
          severity: name === "TOOLS.MD" ? Severity.Critical : Severity.High,
          confidence: "high",
          category: "Secret Scanning",
          title: `Secret found in ${name}`,
          description: `${result.secretMatches.length} potential secret(s) detected — first: ${firstMatch.pattern} at line ${firstMatch.line}`,
          risk: `Secrets in ${name} may be exposed via git, cloud sync, or agent output`,
          remediation: `Move secrets from ${name} to .env file and use environment variable references`,
          autoFixable: false,
          file: path,
          line: firstMatch.line,
        });
      }
    } catch {
      // Can't read file
    }
  }

  // Check 43: Session logs don't contain leaked keys (sample scan)
  for (const logFile of files.sessionLogFiles.slice(0, 5)) {
    // Only scan first 5 log files
    try {
      const result = await parseJsonl(logFile, deep);
      if (result.truncated) {
        const sizeMB = (result.totalSizeBytes / (1024 * 1024)).toFixed(1);
        findings.push({
          id: "SECRET-011",
          severity: Severity.Low,
          confidence: "medium",
          category: "Secret Scanning",
          title: `Large session log (${sizeMB}MB) — sampled`,
          description: `${basename(logFile)} is ${sizeMB}MB — only first 1MB was scanned`,
          risk: "Secrets in later portions of the log may be missed",
          remediation: "Run with --deep for full session log scanning",
          autoFixable: false,
          file: logFile,
        });
      }

      // Scan entries for API key patterns
      for (const entry of result.entries) {
        const content = entry.content || "";
        for (const pattern of API_KEY_PATTERNS) {
          if (pattern.test(content)) {
            findings.push({
              id: "SECRET-012",
              severity: Severity.High,
              confidence: "high",
              category: "Secret Scanning",
              title: "API key leaked in session log",
              description: `Potential API key found in session log ${basename(logFile)}`,
              risk: "Session logs with leaked keys may be backed up or synced to cloud",
              remediation: "Rotate the exposed key immediately and clear session logs",
              autoFixable: false,
              file: logFile,
            });
            break; // One finding per file
          }
        }
      }
    } catch {
      // Can't read file
    }
  }

  // SECRET-013: Private keys in workspace
  if (files.privateKeyFiles.length > 0) {
    findings.push({
      id: "SECRET-013",
      severity: Severity.High,
      confidence: "high",
      category: "Secret Scanning",
      title: "Private key files in workspace",
      description: `${files.privateKeyFiles.length} private key file(s) found: ${files.privateKeyFiles.slice(0, 3).map((f) => basename(f)).join(", ")}`,
      risk: "Private keys in the workspace can be read by agents, committed to git, or synced to cloud",
      remediation: "Move private keys to a secure location outside the workspace (e.g., ~/.ssh/)",
      autoFixable: false,
      file: files.privateKeyFiles[0],
    });
  }

  // SECRET-014: Certificates in workspace
  if (files.workspaceDir) {
    const certExtensions = [".cer", ".crt"];
    const certFiles = files.privateKeyFiles.filter((f) =>
      certExtensions.some((ext) => f.toLowerCase().endsWith(ext))
    );
    // Also check for .cer/.crt alongside .pem/.key files
    if (files.privateKeyFiles.length > 0 || certFiles.length > 0) {
      // Only flag if there's a .git directory (suggesting they could be committed)
      const gitDir = join(files.workspaceDir, ".git");
      try {
        await access(gitDir, constants.R_OK);
        findings.push({
          id: "SECRET-014",
          severity: Severity.Medium,
          confidence: "medium",
          category: "Secret Scanning",
          title: "Certificate/key files may be committed to git",
          description: "Private key or certificate files exist in a git-tracked workspace",
          risk: "Certificates and private keys committed to git are exposed in repository history",
          remediation: "Add *.pem, *.key, *.p12, *.cer, *.crt to .gitignore",
          autoFixable: false,
        });
      } catch {
        // No .git
      }
    }
  }

  // SECRET-015: Database URLs in config
  if (configRaw) {
    const dbUrlPatterns = [
      /postgres(?:ql)?:\/\/[^\s"']+/i,
      /mysql:\/\/[^\s"']+/i,
      /mongodb(\+srv)?:\/\/[^\s"']+/i,
      /redis:\/\/[^\s"']+/i,
    ];
    for (const pattern of dbUrlPatterns) {
      if (pattern.test(configRaw)) {
        findings.push({
          id: "SECRET-015",
          severity: Severity.High,
          confidence: "high",
          category: "Secret Scanning",
          title: "Database connection string in config",
          description: "Database URL found in openclaw.json — may contain credentials",
          risk: "Database URLs often include username/password in the connection string",
          remediation: "Move database URLs to .env and use ${VAR} substitution",
          autoFixable: false,
          file: files.configPath ?? undefined,
        });
        break;
      }
    }
  }

  // SECRET-016: OAuth tokens in session logs
  const oauthPatterns = [
    /Bearer\s+[a-zA-Z0-9\-_.~+/]+=*/,
    /access_token[=:]\s*[a-zA-Z0-9\-_.~+/]{20,}/,
  ];
  for (const logFile of files.sessionLogFiles.slice(0, 5)) {
    try {
      // FIX: Read only the first 512KB via stream instead of reading entire file then slicing
      const content = await readFileCapped(logFile, 512 * 1024);
      const hasOAuth = oauthPatterns.some((p) => p.test(content));
      if (hasOAuth) {
        findings.push({
          id: "SECRET-016",
          severity: Severity.High,
          confidence: "medium",
          category: "Secret Scanning",
          title: "OAuth/access token in session log",
          description: `${basename(logFile)} contains Bearer token or access_token values`,
          risk: "OAuth tokens in logs can be used to impersonate users or access protected resources",
          remediation: "Enable session log scrubbing to redact Bearer tokens and access tokens",
          autoFixable: false,
          file: logFile,
        });
        break;
      }
    } catch {
      // Can't read
    }
  }

  // SECRET-017: Webhook secrets in plaintext config
  if (configRaw) {
    const webhookPatterns = [
      /whsec_[a-zA-Z0-9]{20,}/,          // Stripe webhook secret
      /webhook[_-]?secret\s*[=:]\s*"[^$]/i, // Generic webhook secret not using env ref
    ];
    for (const pattern of webhookPatterns) {
      if (pattern.test(configRaw)) {
        findings.push({
          id: "SECRET-017",
          severity: Severity.High,
          confidence: "high",
          category: "Secret Scanning",
          title: "Webhook secret in plaintext config",
          description: "Webhook signing secret found in openclaw.json instead of .env",
          risk: "Exposed webhook secrets allow forging webhook payloads",
          remediation: "Move webhook secrets to .env and use ${VAR} substitution",
          autoFixable: false,
          file: files.configPath ?? undefined,
        });
        break;
      }
    }
  }

  // SECRET-018: SSH keys in workspace
  if (files.sshKeyFiles.length > 0) {
    findings.push({
      id: "SECRET-018",
      severity: Severity.High,
      confidence: "high",
      category: "Secret Scanning",
      title: "SSH keys in workspace",
      description: `SSH key file(s) found: ${files.sshKeyFiles.map((f) => basename(f)).join(", ")}`,
      risk: "SSH keys in the workspace can be read by agents or committed to git",
      remediation: "Move SSH keys to ~/.ssh/ and add id_rsa, id_ed25519 to .gitignore",
      autoFixable: false,
      file: files.sshKeyFiles[0],
    });
  }

  // SECRET-019: AWS credentials in config (not env ref)
  if (configRaw) {
    const awsKeyPattern = /AWS_ACCESS_KEY_ID\s*[=:]\s*["']?(?!\$\{)[A-Z0-9]{16,}/;
    const awsSecretPattern = /AWS_SECRET_ACCESS_KEY\s*[=:]\s*["']?(?!\$\{)[a-zA-Z0-9/+=]{30,}/;
    if (awsKeyPattern.test(configRaw) || awsSecretPattern.test(configRaw)) {
      findings.push({
        id: "SECRET-019",
        severity: Severity.Critical,
        confidence: "high",
        category: "Secret Scanning",
        title: "AWS credentials in config",
        description: "AWS access key or secret key found hardcoded in openclaw.json",
        risk: "AWS credentials grant access to cloud resources — billing, data, infrastructure",
        remediation: "Move AWS credentials to .env or use IAM roles/instance profiles",
        autoFixable: false,
        file: files.configPath ?? undefined,
      });
    }
  }

  // SECRET-020: JWT secrets weak
  if (configRaw) {
    const jwtMatch = configRaw.match(/jwt[_-]?secret\s*[=:]\s*["']([^"'$][^"']{0,30})["']/i);
    if (jwtMatch && jwtMatch[1] && jwtMatch[1].length < 32) {
      findings.push({
        id: "SECRET-020",
        severity: Severity.Medium,
        confidence: "medium",
        category: "Secret Scanning",
        title: "JWT secret is weak",
        description: `JWT signing secret is only ${jwtMatch[1].length} characters (minimum 32 recommended)`,
        risk: "Short JWT secrets can be brute-forced, allowing token forgery",
        remediation: "Use a JWT secret of at least 32 random characters or use asymmetric keys",
        autoFixable: false,
      });
    }
  }

  // SECRET-021: API keys not documented
  if (files.envPath) {
    const envExamplePath = join(files.openclawDir, ".env.example");
    try {
      await access(envExamplePath, constants.R_OK);
    } catch {
      findings.push({
        id: "SECRET-021",
        severity: Severity.Low,
        confidence: "low",
        category: "Secret Scanning",
        title: "No .env.example file",
        description: ".env exists but no .env.example to document required variables",
        risk: "Team members may not know which environment variables are needed",
        remediation: "Create a .env.example with variable names (no values) for documentation",
        autoFixable: false,
      });
    }
  }

  // SECRET-022: Hardcoded IPs/domains in config
  if (configRaw) {
    const internalPatterns = [
      /\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/,
      /\b172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b/,
      /\b192\.168\.\d{1,3}\.\d{1,3}\b/,
      /staging\./i,
      /\.internal\b/i,
      /\.local\b/i,
    ];
    const hasInternal = internalPatterns.some((p) => p.test(configRaw));
    if (hasInternal) {
      findings.push({
        id: "SECRET-022",
        severity: Severity.Low,
        confidence: "low",
        category: "Secret Scanning",
        title: "Internal IPs or staging domains in config",
        description: "Config contains internal IP addresses or staging/internal domain names",
        risk: "Exposes internal network topology if config is shared or committed",
        remediation: "Use ${VAR} substitution for environment-specific URLs and IPs",
        autoFixable: false,
      });
    }
  }

  // SECRET-023: No credential rotation policy
  // Only fire if we actually found credentials to rotate (env file with keys, or API keys in config)
  const hasCredentials = files.envPath ||
    (configRaw && API_KEY_PATTERNS.some((p) => p.test(configRaw)));

  if (hasCredentials) {
    // Check for rotation evidence in .env files
    let hasRotationEvidence = false;
    if (files.envPath) {
      try {
        const envContent = await readFile(files.envPath, "utf-8");
        // Look for rotation-related patterns
        if (/(?:_OLD|_BACKUP|_PREVIOUS|ROTATED|EXPIRED)/i.test(envContent) ||
            /(?:rotation|rotate_at|expires|valid_until)/i.test(envContent)) {
          hasRotationEvidence = true;
        }
        // Also check file modification date - if modified recently, might indicate rotation
        const envStat = await stat(files.envPath);
        const daysSinceModified = (Date.now() - envStat.mtime.getTime()) / (1000 * 60 * 60 * 24);
        if (daysSinceModified < 30) {
          // Modified in last 30 days - possible rotation activity
          hasRotationEvidence = true;
        }
      } catch {
        // Can't read/stat
      }
    }

    if (!hasRotationEvidence) {
      findings.push({
        id: "SECRET-023",
        severity: Severity.Low,
        confidence: "low",
        category: "Secret Scanning",
        title: "No credential rotation evidence",
        description: "No evidence of key rotation policy (no expiry dates, rotation scripts, or recent credential updates)",
        risk: "Long-lived credentials increase exposure window if compromised",
        remediation: "Implement a key rotation schedule and document the rotation procedure",
        autoFixable: false,
      });
    }
  }

  // SECRET-024: Shared credentials across envs
  if (files.envPath && files.workspaceDir) {
    // Check for multiple .env files with potentially shared values
    const envFiles: string[] = [files.envPath];
    const additionalEnvs = [".env.production", ".env.staging", ".env.development"];
    for (const envName of additionalEnvs) {
      const candidate = join(files.openclawDir, envName);
      try {
        await access(candidate, constants.R_OK);
        envFiles.push(candidate);
      } catch {
        // doesn't exist
      }
    }
    if (envFiles.length > 1) {
      // Read all env files and check for identical values
      const envContents: string[] = [];
      for (const ef of envFiles) {
        try {
          envContents.push(await readFile(ef, "utf-8"));
        } catch {
          // Can't read
        }
      }
      if (envContents.length > 1) {
        // FIX: Use exact line matching to avoid partial-match false positives
        // (e.g., "KEY=val" should not match "MY_KEY=value")
        const lines0 = envContents[0].split("\n").map((l) => l.trim()).filter((l) => l.includes("=") && !l.startsWith("#"));
        const otherLineSets = envContents.slice(1).map((content) =>
          new Set(content.split("\n").map((l) => l.trim()))
        );
        const shared = lines0.filter((line) =>
          otherLineSets.some((lineSet) => lineSet.has(line))
        );
        if (shared.length > 0) {
          findings.push({
            id: "SECRET-024",
            severity: Severity.Medium,
            confidence: "medium",
            category: "Secret Scanning",
            title: "Shared credentials across environments",
            description: `${shared.length} credential(s) appear identical across multiple .env files`,
            risk: "Shared credentials mean a breach in one environment compromises all environments",
            remediation: "Use unique credentials for each environment (production, staging, development)",
            autoFixable: false,
          });
        }
      }
    }
  }

  // SECRET-025: Credentials in error messages (session logs)
  for (const logFile of files.sessionLogFiles.slice(0, 3)) {
    try {
      // FIX: Use capped read to avoid OOM on large session logs
      const content = await readFileCapped(logFile, 512 * 1024);
      const hasStackLeak = /(?:Error|Exception|Traceback)[\s\S]{0,200}(?:password|token|secret|key)\s*[=:]/i.test(content);
      if (hasStackLeak) {
        findings.push({
          id: "SECRET-025",
          severity: Severity.Medium,
          confidence: "medium",
          category: "Secret Scanning",
          title: "Credentials in error messages",
          description: `${basename(logFile)} contains stack traces that may leak secret values`,
          risk: "Error messages in logs can expose credentials to anyone with log access",
          remediation: "Sanitize error output to strip credential values before logging",
          autoFixable: false,
          file: logFile,
        });
        break;
      }
    } catch {
      // Can't read
    }
  }

  // SECRET-026: No secrets scanning in CI
  if (files.workspaceDir) {
    // FIX: .github/workflows is a directory — need to glob for YAML files inside it.
    // Check individual CI files first, then scan workflow directory separately.
    const ciFiles = [
      join(files.workspaceDir, ".gitlab-ci.yml"),
      join(files.workspaceDir, "Jenkinsfile"),
    ];
    const workflowDir = join(files.workspaceDir, ".github", "workflows");
    let hasCI = false;
    let hasSecretScan = false;

    // Check if .github/workflows/ directory exists
    try {
      const wfStat = await stat(workflowDir);
      if (wfStat.isDirectory()) {
        hasCI = true;
        // Read all YAML files in the workflows dir
        const { readdir } = await import("node:fs/promises");
        const wfFiles = await readdir(workflowDir);
        for (const wf of wfFiles.filter((f) => f.endsWith(".yml") || f.endsWith(".yaml"))) {
          const content = await readFile(join(workflowDir, wf), "utf-8").catch(() => "");
          if (/trufflehog|gitguardian|gitleaks|detect-secrets|secret.*scan/i.test(content)) {
            hasSecretScan = true;
          }
        }
      }
    } catch {
      // No workflows dir
    }

    for (const ciPath of ciFiles) {
      try {
        await access(ciPath, constants.R_OK);
        hasCI = true;
        const content = await readFile(ciPath, "utf-8").catch(() => "");
        if (/trufflehog|gitguardian|gitleaks|detect-secrets|secret.*scan/i.test(content)) {
          hasSecretScan = true;
        }
      } catch {
        // doesn't exist
      }
    }
    if (hasCI && !hasSecretScan) {
      findings.push({
        id: "SECRET-026",
        severity: Severity.Low,
        confidence: "low",
        category: "Secret Scanning",
        title: "No secrets scanning in CI",
        description: "CI pipeline exists but no secret scanning tool detected",
        risk: "Secrets committed accidentally won't be caught by CI",
        remediation: "Add TruffleHog, GitGuardian, or gitleaks to your CI pipeline",
        autoFixable: false,
      });
    }
  }

  // SECRET-027: Password/token in git commit messages
  if (files.workspaceDir) {
    try {
      const { execFile: ef } = await import("node:child_process");
      const { promisify: p } = await import("node:util");
      const execAsync = p(ef);
      const startTime = Date.now();
      const { stdout } = await execAsync(
        "git",
        ["log", "--oneline", "-50", "--format=%s"],
        { cwd: files.workspaceDir, timeout: 5000 }
      );
      const duration = Date.now() - startTime;

      // FIX: Log warning if git command takes >2s (may indicate large/slow repo)
      if (duration > 2000) {
        console.error(`  Warning: git log took ${duration}ms — consider optimizing git history`);
      }

      const sensitiveCommit = /\b(?:password|token|secret|api[_-]?key)\s*[=:]/i.test(stdout);
      if (sensitiveCommit) {
        findings.push({
          id: "SECRET-027",
          severity: Severity.Medium,
          confidence: "medium",
          category: "Secret Scanning",
          title: "Sensitive terms in git commit messages",
          description: "Git commit messages contain references to passwords, tokens, or API keys",
          risk: "Commit messages are visible to anyone with repository access",
          remediation: "Avoid including credential values in commit messages",
          autoFixable: false,
        });
      }
    } catch {
      // git not available or not a repo
    }
  }

  // SECRET-028: Service account keys exposed
  if (files.workspaceDir) {
    for (const mdFile of files.workspaceMarkdownFiles.slice(0, 10)) {
      try {
        const content = await readFile(mdFile, "utf-8");
        if (/service[_-]?account|client_email.*iam\.gserviceaccount/i.test(content)) {
          findings.push({
            id: "SECRET-028",
            severity: Severity.High,
            confidence: "medium",
            category: "Secret Scanning",
            title: "Service account key referenced in workspace",
            description: `${basename(mdFile)} references a GCP/cloud service account`,
            risk: "Service account keys grant programmatic access to cloud infrastructure",
            remediation: "Remove service account references from workspace files; use workload identity instead",
            autoFixable: false,
            file: mdFile,
          });
          break;
        }
      } catch {
        // Can't read
      }
    }
  }

  // SECRET-029: API keys with billing risk (Stripe live keys, etc.)
  if (configRaw) {
    const billingPatterns = [
      /sk_live_[a-zA-Z0-9]{20,}/,  // Stripe live secret key
      /rk_live_[a-zA-Z0-9]{20,}/,  // Stripe restricted key
    ];
    for (const pattern of billingPatterns) {
      if (pattern.test(configRaw)) {
        findings.push({
          id: "SECRET-029",
          // FIX: Elevated from MEDIUM to CRITICAL — live Stripe secret keys can create charges
          severity: Severity.Critical,
          confidence: "high",
          category: "Secret Scanning",
          title: "Live billing API key in config",
          description: "Stripe live secret key found in config — has billing access",
          risk: "Live billing keys can create charges, refunds, and access financial data",
          remediation: "Move billing keys to .env; use restricted keys with minimum required permissions",
          autoFixable: false,
          file: files.configPath ?? undefined,
        });
        break;
      }
    }
  }

  // SECRET-030: Shared API keys (same key in config and markdown)
  if (configRaw) {
    for (const mdFile of files.workspaceMarkdownFiles.slice(0, 5)) {
      try {
        const mdContent = await readFile(mdFile, "utf-8");
        for (const pattern of API_KEY_PATTERNS) {
          const configMatches = [...configRaw.matchAll(new RegExp(pattern, "g"))].map((m) => m[0]);
          for (const key of configMatches) {
            if (mdContent.includes(key)) {
              findings.push({
                id: "SECRET-030",
                severity: Severity.Low,
                confidence: "medium",
                category: "Secret Scanning",
                title: "API key duplicated across files",
                description: `Same API key appears in both config and ${basename(mdFile)}`,
                risk: "Duplicated keys increase the surface area for accidental exposure",
                remediation: "Use ${VAR} references everywhere — define keys only in .env",
                autoFixable: false,
                file: mdFile,
              });
              break;
            }
          }
        }
      } catch {
        // Can't read
      }
    }
  }

  return findings;
}
