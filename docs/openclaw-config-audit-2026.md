# OpenClaw Configuration Security Audit 2026

**Published:** 8 February 2026  
**Author:** Rich — [Clawhatch](https://clawhatch.com)  
**Scanner:** [`npx clawhatch scan`](https://github.com/clawhatch/clawhatch)  
**License:** MIT

---

## Summary

I scanned publicly committed OpenClaw configurations on GitHub. Every single one had at least one security issue. Many had multiple critical vulnerabilities including hardcoded API keys, missing sandboxes, exposed gateways, and no access controls.

This document presents the findings, explains why they matter, and provides fixes.

---

## Methodology

1. **Discovery:** Searched the GitHub API for repositories matching "openclaw" — found **5,797 results**
2. **Filtering:** Narrowed to repos containing configuration files (`openclaw.json`, `configs/`, `.openclaw/`, etc.)
3. **Scanning:** Ran each configuration through the Clawhatch scanner (128 checks across 10 categories)
4. **Analysis:** Focused on four high-impact categories: hardcoded credentials, network exposure, sandbox configuration, and access controls
5. **Anonymization:** All findings are anonymized — no individuals named, no repository URLs published

### Responsible Disclosure

We contacted affected repository owners via GitHub issues before publishing. No usernames, repo names, or credential values appear in this document. We did not attempt to use any exposed credentials or access any systems.

---

## Key Findings

### Finding 1: Hardcoded Credentials in Public Repos

| | |
|---|---|
| **Severity** | 🔴 CRITICAL |
| **Prevalence** | ~40% of scanned repos |
| **Check IDs** | `SECRET-001`, `SECRET-002`, `DATA-007` |

We found multiple repositories containing **actual, working API keys and bot tokens** committed in plaintext. These aren't placeholder values — they're real, active credentials:

- Anthropic Claude API keys (`sk-ant-api03-...`)
- OpenAI API keys (`sk-proj-...`)
- Telegram bot tokens
- Discord bot tokens
- Brave Search API keys
- Database connection strings

**The pattern:** User sets up OpenClaw, gets it working, commits their entire config directory to a dotfiles or backup repo. The config works — but it now contains production credentials visible to anyone.

#### The Issue #9627 Problem

This is made significantly worse by [OpenClaw Issue #9627](https://github.com/openclaw/openclaw/issues/9627) (filed February 5, 2026 — still open).

**What happens:**

1. **Day 1:** User sets up OpenClaw correctly, storing API keys in environment variables
2. **Day 1:** Config references the variable: `"apiKey": "${ANTHROPIC_API_KEY}"`
3. **Day 30:** User runs `openclaw update` to get the latest version
4. **Day 30:** The update command *resolves* the variable and writes: `"apiKey": "sk-ant-api03-actual-key-value"`
5. **Day 31:** User commits their config
6. **Day 31:** API key is now public

The user did everything right. They used environment variables. They followed best practices. But OpenClaw's config write operations don't preserve the `${...}` syntax — they replace it with the resolved value.

| Stat | Value |
|------|-------|
| OpenClaw repos on GitHub | 5,797 |
| Issue filed | Feb 5, 2026 |
| Fixes from maintainers | 0 |

**Impact:** Anyone with access to these repos can extract working API keys. Depending on billing settings, attackers could rack up thousands in API charges, exfiltrate conversation history, or use messaging capabilities for spam/phishing.

---

### Finding 2: Missing Sandbox Configuration

| | |
|---|---|
| **Severity** | 🟠 HIGH |
| **Prevalence** | ~65% of scanned repos |
| **Check IDs** | `SANDBOX-001`, `SANDBOX-003`, `SANDBOX-008` |

The majority of configs had **no sandbox configuration**, running in OpenClaw's default "main" mode. In this mode, the AI agent executes shell commands with the same permissions as the user who launched OpenClaw:

- Execute any shell command
- Read/write any file the user can access
- Install system packages
- Access the network without restrictions
- Access cloud provider credentials (AWS, GCP, Azure)

**Fix:**

```json
{
  "agents": {
    "defaults": {
      "sandbox": {
        "mode": "non-main"
      }
    }
  }
}
```

A prompt injection or malicious plugin could execute arbitrary code with full user privileges. This isn't a sandboxed interpreter — it's unrestricted shell access.

---

### Finding 3: No DM Allowlists

| | |
|---|---|
| **Severity** | 🟡 MEDIUM |
| **Prevalence** | ~80% of scanned repos |
| **Check IDs** | `IDENTITY-001`, `IDENTITY-004`, `IDENTITY-011` |

Most configs had **no DM allowlist**, meaning anyone who can message the bot can issue commands. For Telegram, Discord, and WhatsApp integrations, attackers can:

- Send direct messages to the agent
- Attempt prompt injection attacks
- Probe for sensitive information
- Test for command execution

**Fix:**

```json
{
  "identity": {
    "dmAllowlist": [
      "your-telegram-id",
      "your-discord-id",
      "+15555551234"
    ]
  }
}
```

Without an allowlist, you're relying entirely on prompt engineering to distinguish legitimate from malicious requests. That's not a security boundary.

---

### Finding 4: Network-Exposed Gateways

| | |
|---|---|
| **Severity** | 🔴 CRITICAL |
| **Prevalence** | ~15% of scanned repos |
| **Check IDs** | `NETWORK-001`, `NETWORK-003`, `NETWORK-007` |

Some configs bind the OpenClaw gateway to `0.0.0.0` (all interfaces) instead of `127.0.0.1` (localhost). Combined with weak/missing auth tokens, this exposes the agent's control API to:

- Anyone on the same local network
- The entire internet (if port-forwarded)
- Other containers/VMs in cloud environments

**Fix:**

```json
{
  "gateway": {
    "bind": "127.0.0.1:18080",
    "authToken": "your-secure-random-token-here"
  }
}
```

Generate a token: `openssl rand -hex 32`

**Scenario:** Attacker on your coffee shop WiFi scans for common ports, finds your OpenClaw gateway, issues commands directly. No Telegram needed. No prompt injection. Just raw API access.

---

## Why This Matters

AI agents are not chatbots. They're **automation platforms** with capabilities that would have required custom software a few years ago:

| Capability | Risk |
|---|---|
| Shell access | Execute commands, install packages, modify system config |
| File access | Read/write/delete any file user can access |
| Browser control | Navigate sites, extract data, access cookies |
| Messaging | Send messages via Telegram, Discord, WhatsApp, SMS |
| Remote execution | Run code on paired mobile devices |
| Credential access | Read cloud configs, SSH keys, password managers |

**A compromised agent config = a compromised system.**

Traditional security tools don't understand AI agent config semantics. A static analysis scanner won't flag `sandbox.mode: "main"` as a vulnerability. An endpoint protection tool won't detect an empty DM allowlist. This is a **new category of vulnerability that needs purpose-built tooling**.

---

## How to Check Your Own Config

```bash
npx clawhatch scan
```

128 checks. Under 1 second. 100% local — nothing leaves your machine.

### Common Issues and Fixes

| Check | Severity | Issue | Fix |
|-------|----------|-------|-----|
| `SECRET-001` | CRITICAL | API keys in config | Move to `.env`, use `${ENV_VAR}` references. Auto-fix: `npx clawhatch scan --fix` |
| `SANDBOX-001` | CRITICAL | Sandbox disabled | Set `agents.defaults.sandbox.mode` to `"non-main"` |
| `IDENTITY-001` | MEDIUM | DM policy open | Set `identity.dmAllowlist` with your IDs |
| `NETWORK-001` | CRITICAL | Gateway on 0.0.0.0 | Bind to `127.0.0.1`, set strong `authToken` |

### Check if your config was committed to Git

```bash
# Check history
git log --all --full-history -- openclaw.json

# View old versions
git show <commit-hash>:openclaw.json
```

If credentials appear in history, **rotate them immediately** and consider the repo compromised.

### Contribute to the Community Threat Feed

```bash
npx clawhatch scan --share
```

Anonymously contribute scan results to help others prioritize fixes based on real-world threat patterns.

---

## Recommendations

### For OpenClaw Users

1. **Never commit `openclaw.json` to Git.** Add it to `.gitignore`.
2. **Use `${ENV_VAR}` references for all secrets.** Store credentials in `.env` (also gitignored).
3. **Be aware of Issue #9627.** Check your config after running `openclaw update` or `openclaw doctor`.
4. **Run `npx clawhatch scan` regularly.** Add it to your deploy checklist or CI pipeline.
5. **Configure defense-in-depth.** Sandbox mode + DM allowlists + localhost binding + strong auth tokens.

### For the OpenClaw Project

1. **Fix [Issue #9627](https://github.com/openclaw/openclaw/issues/9627).** Preserve `${...}` syntax during config writes.
2. **Add a `.gitignore` template** that includes `openclaw.json` and `.env` during `openclaw init`.
3. **Default to secure settings.** Ship with `sandbox.mode: "non-main"`, `gateway.bind: "127.0.0.1"`.
4. **Integrate security checks into `openclaw doctor`.** Or provide an official security scanning subcommand.

---

## Conclusion

AI agent security is a new problem. The tools are powerful, the defaults are insecure, and the ecosystem is growing fast.

Every configuration we analyzed had vulnerabilities. Hardcoded credentials, missing sandboxes, exposed gateways, and no access controls are the norm, not the exception.

The good news: **these vulnerabilities are fixable.** Most require only simple configuration changes. The challenge is awareness.

---

## Links

- **Scanner:** [github.com/clawhatch/clawhatch](https://github.com/clawhatch/clawhatch)
- **Install:** `npx clawhatch scan`
- **npm:** [npmjs.com/package/clawhatch](https://www.npmjs.com/package/clawhatch)
- **Website:** [clawhatch.com](https://clawhatch.com)
- **OpenClaw Issue #9627:** [github.com/openclaw/openclaw/issues/9627](https://github.com/openclaw/openclaw/issues/9627)
- **Contact:** clawhatch@proton.me
