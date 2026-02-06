# clawhatch

> Security scanner for OpenClaw AI agents — 100-point audit with auto-fix.

[![npm version](https://img.shields.io/npm/v/clawhatch.svg)](https://www.npmjs.com/package/clawhatch)
[![license](https://img.shields.io/npm/l/clawhatch.svg)](https://opensource.org/licenses/MIT)
[![node](https://img.shields.io/node/v/clawhatch.svg)](https://nodejs.org/)

Clawhatch runs **100 automated security checks** against your [OpenClaw](https://openclaw.com) installation, scores it on a 100-point scale (A+ to F), and can auto-fix safe issues. Think of it as `npm audit` for your AI agent.

## Quick Start

```bash
npx clawhatch scan
```

No installation required. Clawhatch auto-detects your OpenClaw installation at `~/.openclaw` (or `%APPDATA%\openclaw` on Windows).

## Installation

```bash
npm install -g clawhatch
```

## Usage

```bash
# Basic scan — auto-detects your OpenClaw config
clawhatch scan

# Scan with workspace files (SOUL.md, skills, markdown)
clawhatch scan --workspace .

# Deep scan — analyze full session logs (slower)
clawhatch scan --deep

# JSON output for scripting and CI
clawhatch scan --json

# HTML report
clawhatch scan --format html

# Auto-fix safe issues (prompts for behavioral changes)
clawhatch scan --fix

# Custom OpenClaw installation path
clawhatch scan --path /custom/path

# Combine flags
clawhatch scan --workspace . --deep --fix
```

## Example Output

```
  Clawhatch Security Scanner v0.1.0

  Clawhatch Security Scan
  ==================================================

  Security Score: 72/100 (B — Acceptable)

  Platform: win32
  OpenClaw: 1.2.0
  Checks: 100 run, 94 passed, 6 findings
  Duration: 842ms
  Scanned: 14 files

  --------------------------------------------------

  HIGH (2 findings)

  ! Gateway auth token is weak
     Auth token is short or low-entropy (< 32 characters)
     Risk: Weak tokens can be brute-forced
     Fix: Generate a strong token: openssl rand -hex 32

  ! Session logs contain potential secrets
     API keys or tokens detected in session log files
     Risk: Secrets persisted in plaintext logs
     Fix: Enable log sanitization and rotate exposed keys

  MEDIUM (3 findings)

  ~ DM policy set to "open"
     Channel accepts messages from any sender
     Risk: Unauthorized users can interact with the agent
     Fix: Set dmPolicy to "allowlist" and configure allowFrom

  ~ No tool rate limiting configured
     Tool execution has no throttle (tools.rateLimit missing)
     Risk: Rapid tool invocation can spam external APIs
     Fix: Set tools.rateLimit in openclaw.json (e.g., 60)

  ~ Session log retention not configured
     No sessionLogTTL set — logs kept indefinitely
     Risk: Stale data accumulation and potential compliance issues
     Fix: Set retention.sessionLogTTL (e.g., 30 days)

  LOW (1 finding)

  - No health check endpoint configured
     Gateway has no monitoring.enabled setting
     Risk: No automated way to verify agent is running correctly
     Fix: Enable monitoring in openclaw.json

  ==================================================

  3 issue(s) can be auto-fixed. Run with --fix
  Run with --json for machine-readable output
  Run with --deep for thorough session log scanning
```

## What It Checks

Clawhatch runs 100 checks across **10 security categories**:

| Category | Checks | What It Covers |
|----------|--------|----------------|
| **Identity & Access** | 15 | DM policies, allowlists, pairing config, access groups, OAuth, API key rotation |
| **Network Exposure** | 10 | Gateway binding, auth mode, TLS, trusted proxies, insecure auth flags |
| **Sandbox Configuration** | 8 | Sandbox mode, workspace access, Docker isolation, browser host control |
| **Secret Scanning** | 10 | Hardcoded API keys, .env permissions, secrets in markdown, session log leakage |
| **Model Security** | 7 | Model config, legacy models, injection resistance, SOUL.md analysis, fallback order |
| **Cloud Sync** | 1 | iCloud, OneDrive, Dropbox, Google Drive detection |
| **Tool Security** | 20 | Elevated tools, command injection, Docker socket exposure, audit logging |
| **Skill Security** | 12 | Untrusted sources, dangerous dependencies, native modules, sandboxing |
| **Data Protection** | 10 | PII in logs, retention policies, encryption at rest, log rotation |
| **Operational** | 7 | Logging config, monitoring, git secrets, health checks, dependency staleness |

## Scoring

Clawhatch uses a **100-point scoring system** with severity-based penalties:

| Severity | Penalty per finding |
|----------|---------------------|
| Critical | −15 points |
| High | −8 points |
| Medium | −3 points |
| Low | −1 point |

**Critical cap:** Any critical finding hard-caps the score at **40**, regardless of calculated total. Fix critical issues first.

### Grade Scale

| Score | Grade | Label |
|-------|-------|-------|
| 90–100 | A+ | Excellent |
| 80–89 | A | Good |
| 70–79 | B | Acceptable |
| 50–69 | C | Needs Work |
| 30–49 | D | Poor |
| 0–29 | F | Critical |

## Auto-Fix (`--fix`)

When you run `clawhatch scan --fix`, the scanner applies fixes in two tiers:

**Safe fixes** — applied automatically:
- File permission corrections (e.g., tightening `.env` to 600)
- Adding secrets to `.gitignore`
- Generating strong replacement tokens

**Behavioral fixes** — prompts for confirmation:
- Changing DM policies from "open" to "allowlist"
- Enabling sandbox mode
- Modifying gateway bind addresses

All fixes create timestamped backups (`.bak.<timestamp>`) before modifying any file.

## JSON Export (`--json`)

```bash
clawhatch scan --json > report.json
```

Outputs a structured `ScanResult` object:

```json
{
  "timestamp": "2026-02-06T12:00:00.000Z",
  "openclawVersion": "1.2.0",
  "score": 82,
  "findings": [
    {
      "id": "NETWORK-001",
      "severity": "CRITICAL",
      "confidence": "high",
      "category": "Network Exposure",
      "title": "Gateway bound to 0.0.0.0",
      "description": "...",
      "risk": "...",
      "remediation": "...",
      "autoFixable": true,
      "fixType": "behavioral"
    }
  ],
  "suggestions": [],
  "summary": {
    "score": 82,
    "grade": "A",
    "label": "Good",
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 0,
    "suggestions": 3,
    "autoFixable": 1
  },
  "filesScanned": 14,
  "checksRun": 100,
  "checksPassed": 97,
  "duration": 1234,
  "platform": "win32"
}
```

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan passed (no critical findings) |
| `1` | Critical findings detected |

## Findings vs. Suggestions

Clawhatch separates output into two groups:

- **Findings** (high/medium confidence) — count toward your score and represent actionable security issues.
- **Suggestions** (low confidence) — informational recommendations that do not affect your score.

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Audit
on: [push, pull_request]

jobs:
  clawhatch:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '18'

      - name: Run Clawhatch scan
        run: npx clawhatch scan --workspace . --json > clawhatch-report.json

      - name: Check score
        run: |
          score=$(jq '.score' clawhatch-report.json)
          echo "Security score: $score"
          [ "$score" -ge 50 ] || exit 1

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: clawhatch-report
          path: clawhatch-report.json
```

## Platform Support

| Platform | Status | Notes |
|----------|--------|-------|
| **Windows** | ✅ Supported | Full support including `%APPDATA%\openclaw` detection |
| **Linux** | 🔄 Coming soon | Core checks work, platform-specific checks in progress |
| **macOS** | 🔄 Coming soon | Core checks work, platform-specific checks in progress |

## Other Commands

### `clawhatch init`

Generate a secure baseline OpenClaw configuration:

```bash
clawhatch init
clawhatch init --path /custom/path
```

Creates a hardened `openclaw.json` and `.env` template with secure defaults.

## Community Threat Intelligence

Clawhatch includes a community threat intelligence network. When you share your scan results, they're anonymized and aggregated to protect everyone:

### Share your results

```bash
clawhatch scan --share              # Anonymize and share with community
clawhatch scan --upload             # Same as --share
```

Only check IDs, severity levels, and categories are shared. **No file paths, secrets, or descriptions ever leave your machine.**

### View community threats

```bash
clawhatch threats                   # View the community threat feed
```

Shows the top threats across all users, trending attacks, new advisories, and the community average score.

### Subscribe to alerts

```bash
clawhatch subscribe --webhook https://discord.com/api/webhooks/...   # Discord
clawhatch subscribe --webhook https://hooks.slack.com/services/...   # Slack
clawhatch subscribe --threshold CRITICAL                             # Only critical alerts
```

When a new threat is detected across the community, subscribers are notified instantly via their configured webhook.

### How it works

1. You run `clawhatch scan --share`
2. Findings are stripped to just check IDs + severity (no file paths, no secrets)
3. Anonymized report is uploaded to the community feed
4. If 45% of users suddenly have NETWORK-001, that's flagged as trending
5. Subscribers with that vulnerability get an instant webhook alert

### Privacy

- Instance ID is a SHA-256 hash of your hostname -- we never see your actual machine name
- No file paths, descriptions, or secret values are ever transmitted
- You can inspect exactly what's sent with `clawhatch scan --json --share`

## Requirements

- **Node.js** >= 18.0.0
- **OpenClaw** installed (auto-detected or specify with `--path`)

## Contributing

Contributions welcome! Please see the [GitHub repository](https://github.com/wlshlad85/clawhatch) for details.

1. Fork the repo
2. Create a feature branch (`git checkout -b feat/my-check`)
3. Add your checks following the existing pattern in `src/checks/`
4. Run tests: `npm test`
5. Submit a PR

## License

[MIT](LICENSE) © Clawhatch
