# Scanner Expansion Handoff — 51 → 100 Checks
**Date:** 2026-02-05  
**Task:** TASKSEC-02.02  
**For:** Claude Code (Opus 4.6)  
**Goal:** Add 49 new automated security checks to the scanner

---

## Current State

**What's Done:**
- 51 checks implemented and working
- Tested on production OpenClaw setup
- Real validation: 40/100 → 93/100 score improvement
- Scanner location: `C:\Users\RICHARD\clawd\clawhatch\scanner\`
- All code compiles with zero errors
- Auto-fix working for safe mutations

**Current Check Breakdown:**
- Identity & Access: 15 checks
- Network Exposure: 10 checks
- Sandbox Configuration: 8 checks
- Secret Scanning: 10 checks
- Model Security: 7 checks
- Cloud Sync Detection: 1 check

**Total: 51 checks**

---

## What Needs Building

Add 49 new checks across 6 categories to reach 100 total.

### Category 1: Tool & Execution Policy (20 checks)
**Focus:** What tools/commands the agent can execute and with what permissions.

**Files to scan:**
- `openclaw.json` (tools.elevated, commands config)
- `AGENTS.md` (operational protocol)
- `.claude/commands/` (custom slash commands)

**Checks to implement:**

1. **tools.elevated list size** — Flag if >5 tools elevated (suggests over-privilege)
2. **Dangerous elevated tools** — Detect exec, shell, bash in elevated list
3. **useAccessGroups not enabled** — Commands should require access group membership
4. **No tool allowlist** — If tools.allowlist is missing and elevated exists
5. **Exec tool unrestricted** — exec tool available but no constraints
6. **Browser relay enabled without constraints** — browser.allowHostControl but no documentation
7. **File write permissions too broad** — No workspace boundaries on file writes
8. **Docker socket mounted** — Extreme privilege escalation risk
9. **Host network mode** — Container can access host network without isolation
10. **Sudo in custom commands** — Custom commands contain sudo/doas/runas
11. **Eval/exec in skills** — Skills execute arbitrary code (eval, exec, subprocess)
12. **Custom tool injection risk** — Tools loaded from workspace override managed skills
13. **Missing tool documentation** — Elevated tools lack CLAUDE.md explanation
14. **Tool version pinning** — No version constraints on external tools
15. **Shell command history exposed** — Session logs leak shell commands with secrets
16. **Unrestricted file deletion** — Delete/rm operations not logged or restricted
17. **No command audit trail** — Tools executed but not logged to audit table
18. **Dynamic tool loading** — Tools can be loaded at runtime from arbitrary paths
19. **Tool timeout missing** — Long-running tools can DoS the agent
20. **No rate limiting on tools** — Tool execution not throttled (can spam external APIs)

**Where to add:** `src/checks/tools.ts` (new file)

---

### Category 2: Credentials & Secrets (18 checks)
**Focus:** API keys, tokens, passwords, certificates.

**Files to scan:**
- `openclaw.json`
- `.env`, `.env.local`, `.env.production`
- `credentials/*.json`
- `auth-profiles.json`
- Session logs (sample)
- Git history (if accessible)

**Additional checks beyond existing 10:**

11. **Private keys in workspace** — Detect .pem, .key, .p12 files in workspace
12. **Certificates in git** — SSL certs committed to git repo
13. **Database URLs in config** — Postgres/MySQL connection strings in plaintext
14. **OAuth tokens in logs** — Access tokens leaked to session logs
15. **Webhook secrets in plaintext** — Stripe/Clerk webhook secrets not in .env
16. **SSH keys in workspace** — id_rsa, id_ed25519 files exposed
17. **AWS credentials in config** — AWS_ACCESS_KEY_ID in config not .env
18. **JWT secrets weak** — JWT signing keys <32 chars
19. **API keys in environment** — Keys in process.env but not documented in .env.example
20. **Hardcoded IPs/domains** — Internal IPs or staging domains in config (info leak)
21. **No credential rotation policy** — No evidence of key rotation schedule
22. **Shared credentials across environments** — Same API key for dev/staging/prod
23. **Credentials in error messages** — Stack traces or error logs leak secrets
24. **No secrets scanning in CI** — No GitGuardian/TruffleHog in CI pipeline
25. **Password in git commit messages** — Git log contains "password" or "token"
26. **Service account keys exposed** — GCP/Azure service account JSON in repo
27. **API keys with billing enabled** — Gemini/OpenAI keys have billing but no spend limits
28. **Shared API keys** — Same key used by multiple users/agents

**Where to add:** `src/checks/secrets.ts` (extend existing file)

---

### Category 3: Plugin & Skill Security (12 checks)
**Focus:** Custom skills, MCP servers, npm packages.

**Files to scan:**
- `skills/*/SKILL.md`
- `skills/*/package.json`
- `.openclaw/skills/` (managed skills)
- `workspace/skills/` (custom skills)

**Checks:**

1. **Skills from untrusted sources** — Skills installed from non-verified URLs
2. **Outdated skill dependencies** — npm packages with known CVEs
3. **Skills with network access** — Skills make HTTP requests without disclosure
4. **Skills modify system files** — Skills write outside workspace boundaries
5. **No skill sandboxing** — Skills run in main process not isolated
6. **Skill package-lock missing** — No dependency pinning (supply chain risk)
7. **Skills use eval/Function** — Dynamic code execution in skill code
8. **Skills load native modules** — .node binaries without verification
9. **Skills access credentials** — Skills read auth-profiles.json or .env
10. **No skill signature verification** — Skills not signed or hash-verified
11. **Skills auto-update** — Skills update without user approval
12. **Workspace skill override** — Local skills shadow managed skills (injection risk)

**Where to add:** `src/checks/skills.ts` (new file)

---

### Category 4: Model & Prompt Security (8 checks)
**Focus:** System prompts, injection resistance, model config.

**Files to scan:**
- `SOUL.md`
- `AGENTS.md`
- `openclaw.json` (model config, reasoning settings)

**Additional checks beyond existing 7:**

8. **System prompt injection resistance** — SOUL.md doesn't include anti-injection instructions
9. **Prompt includes sensitive data** — SOUL.md contains API keys, internal IPs, or PII
10. **No prompt versioning** — SOUL.md not in git (can't audit changes)
11. **User input sanitization missing** — No evidence of input validation in operational protocol
12. **Model temperature too high** — temperature >0.9 (unpredictable outputs)
13. **No output filtering** — Agent responses not checked for PII/secrets before sending
14. **Context window abuse** — No limits on message history size (DoS vector)
15. **Multi-agent trust boundaries** — Multiple agents share same SOUL.md (privilege confusion)

**Where to add:** `src/checks/model.ts` (extend existing file)

---

### Category 5: Data Protection (10 checks)
**Focus:** PII, data retention, GDPR compliance.

**Files to scan:**
- Session logs
- `openclaw.json` (retention settings)
- Database config
- Backup locations

**Checks:**

1. **Session logs contain PII** — User emails, phone numbers in logs
2. **No data retention policy** — Session logs kept indefinitely
3. **Logs not encrypted at rest** — Session JSONL files in plaintext
4. **No log rotation** — Session logs never deleted or archived
5. **Backups not encrypted** — Database backups in plaintext
6. **No data anonymization** — PII not redacted before analysis
7. **Third-party data sharing** — Session data uploaded to analytics without consent
8. **No right-to-deletion** — No documented process for user data deletion
9. **Logs in public directory** — Session logs in web-accessible directory
10. **No audit trail for data access** — Who accessed what data not logged

**Where to add:** `src/checks/data-protection.ts` (new file)

---

### Category 6: Operational Hygiene (7 checks)
**Focus:** Maintenance, monitoring, error handling.

**Files to scan:**
- `openclaw.json` (logging config)
- Session logs
- Error logs
- Git repo metadata

**Checks:**

1. **No structured logging** — Logs are unstructured text not JSON
2. **Error messages too verbose** — Stack traces include file paths, secrets
3. **No monitoring/alerting** — No integration with Sentry, Datadog, etc.
4. **Stale dependencies** — npm/pip packages >6 months old
5. **No health check endpoint** — Gateway has no /health endpoint
6. **Git repo has secrets in history** — Old commits contain API keys (BFG needed)
7. **No rollback plan** — No documented incident response or rollback procedure

**Where to add:** `src/checks/operational.ts` (new file)

---

## Implementation Guide

### File Structure

Add 4 new check files:
```
src/checks/
├── identity.ts        # Existing (15 checks)
├── network.ts         # Existing (10 checks)
├── sandbox.ts         # Existing (8 checks)
├── secrets.ts         # Existing (10 checks) → extend to 28 checks
├── model.ts           # Existing (7 checks) → extend to 15 checks
├── cloud-sync.ts      # Existing (1 check)
├── tools.ts           # NEW (20 checks)
├── skills.ts          # NEW (12 checks)
├── data-protection.ts # NEW (10 checks)
└── operational.ts     # NEW (7 checks)
```

### Code Pattern to Follow

Each check file exports a `run*Checks()` function:

```typescript
import { Finding, Severity, OpenClawConfig } from '../types.js';

export async function runToolChecks(
  config: OpenClawConfig,
  files: DiscoveredFiles
): Promise<Finding[]> {
  const findings: Finding[] = [];

  // Check 1: tools.elevated list size
  const elevatedTools = config.tools?.elevated || [];
  if (elevatedTools.length > 5) {
    findings.push({
      id: 'TOOLS-001',
      severity: Severity.Medium,
      confidence: 'high',
      category: 'Tool & Execution Policy',
      title: 'Excessive elevated tools',
      description: `${elevatedTools.length} tools are elevated (recommended: ≤5)`,
      risk: 'Large elevated tool lists increase attack surface',
      remediation: 'Review elevated tools list and remove unnecessary elevations',
      autoFixable: false,
    });
  }

  // Check 2: Dangerous elevated tools
  const dangerousTools = ['exec', 'shell', 'bash', 'zsh', 'powershell'];
  const elevated = elevatedTools.filter(t => 
    dangerousTools.some(d => t.toLowerCase().includes(d))
  );
  if (elevated.length > 0) {
    findings.push({
      id: 'TOOLS-002',
      severity: Severity.Critical,
      confidence: 'high',
      category: 'Tool & Execution Policy',
      title: 'Dangerous tools elevated',
      description: `Shell execution tools in elevated list: ${elevated.join(', ')}`,
      risk: 'Elevated shell access allows arbitrary command execution',
      remediation: 'Remove shell tools from elevated list or add strict constraints',
      autoFixable: false,
    });
  }

  // ... more checks

  return findings;
}
```

### Update Main Scanner

In `src/scanner.ts`, import and call new check functions:

```typescript
import { runToolChecks } from './checks/tools.js';
import { runSkillChecks } from './checks/skills.js';
import { runDataProtectionChecks } from './checks/data-protection.js';
import { runOperationalChecks } from './checks/operational.js';

// In scan() function, after existing checks:
const toolFindings = await runToolChecks(config, files);
allFindings.push(...toolFindings);

const skillFindings = await runSkillChecks(config, files);
allFindings.push(...skillFindings);

const dataFindings = await runDataProtectionChecks(config, files);
allFindings.push(...dataFindings);

const opFindings = await runOperationalChecks(config, files);
allFindings.push(...opFindings);
```

### Update Constants

In `src/scanner.ts`:
```typescript
const TOTAL_CHECKS = 100; // was 51
```

---

## Testing Requirements

### 1. Build Test
```bash
cd C:\Users\RICHARD\clawd\clawhatch\scanner
pnpm build
```
Must compile with zero errors.

### 2. Smoke Test
```bash
node dist/index.js scan --workspace C:\Users\RICHARD\clawd
```
Should run without crashing and report 100 checks run.

### 3. Validation Test
Run on Rich's actual setup and verify:
- New checks find real issues (if any exist)
- No false positives on passing checks
- Terminal output is still readable with more findings
- Score calculation still works correctly
- JSON output includes all new checks

### 4. Coverage Test
Check that all 6 new categories are represented in output.

---

## Success Criteria

- [ ] 49 new checks implemented across 6 categories
- [ ] All checks follow the existing code pattern
- [ ] Scanner compiles with zero errors
- [ ] Total checks reported: 100
- [ ] Tested on Rich's setup successfully
- [ ] No regression in existing 51 checks
- [ ] New findings (if any) are actionable and specific
- [ ] Terminal output still clear and readable

---

## Priority Guidance

**Start with highest-value checks first:**

1. **TOOLS-002** (dangerous elevated tools) — Critical severity
2. **SECRETS-011** (private keys in workspace) — High severity
3. **SKILLS-001** (untrusted skill sources) — High severity
4. **DATA-001** (session logs contain PII) — High severity
5. **TOOLS-001** (excessive elevated tools) — Medium severity

Work through categories in order: Tools → Secrets → Skills → Data Protection → Model → Operational

---

## Notes

- Maintain the existing confidence scoring (high/medium/low)
- Low-confidence checks should be suggestions, not findings
- Include file paths in Finding objects where applicable
- Keep descriptions specific and actionable
- Remediation steps should be concrete ("do X") not vague ("improve Y")
- Reference check IDs should be sequential within category (TOOLS-001, TOOLS-002, etc.)

---

**When Done:**

1. Commit changes with message: "feat(scanner): expand to 100 checks - add tools, skills, data protection, operational categories"
2. Run full test on Rich's setup
3. Document any new findings in a summary
4. Report back on completion

---

**End of Handoff**

Go build those 49 checks. The architecture is solid — just follow the existing patterns and you'll crush this.

— Max
