# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | ✅ Current release |

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

If you discover a security vulnerability in Clawhatch, please report it responsibly:

### How to Report

1. **Email:** Send details to **security@clawhatch.com**
2. **Subject line:** `[SECURITY] Brief description of the issue`
3. **Include:**
   - Description of the vulnerability
   - Steps to reproduce
   - Affected version(s)
   - Potential impact assessment
   - Suggested fix (if you have one)

### What to Expect

- **Acknowledgement** within **48 hours** of your report
- **Initial assessment** within **5 business days**
- **Regular updates** on progress toward a fix
- **Credit** in the release notes (unless you prefer to remain anonymous)

### Responsible Disclosure

We follow a **90-day disclosure policy:**

1. You report the vulnerability privately
2. We acknowledge and begin working on a fix
3. We coordinate with you on the timeline
4. We release the fix and publish an advisory
5. You're free to publish details after the fix is released (or after 90 days, whichever comes first)

### Scope

The following are **in scope** for security reports:

- Vulnerabilities in Clawhatch scanner code
- Issues that could cause false negatives (missing real security problems)
- Issues that could expose user configuration or secrets during scanning
- Dependency vulnerabilities that affect Clawhatch users

The following are **out of scope:**

- Vulnerabilities in OpenClaw itself (report those to the OpenClaw team)
- Issues in user configurations that Clawhatch correctly identifies
- Denial of service via extremely large config files

### Safe Harbour

We will not take legal action against security researchers who:

- Act in good faith
- Follow this responsible disclosure process
- Do not access or modify other users' data
- Do not publicly disclose before a fix is available

## Security Best Practices

When using Clawhatch:

- Always run the latest version
- Review auto-fix changes before applying (`--fix` modifies files)
- Don't pipe `--json` output to untrusted systems (may contain config paths)
- Run scans in the same security context as your OpenClaw installation

## Contact

- Security issues: security@clawhatch.com
- General issues: [GitHub Issues](https://github.com/wlshlad85/clawhatch/issues)
