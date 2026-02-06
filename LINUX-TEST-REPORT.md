# Clawhatch Scanner — Linux Cross-Platform Test Report

**Date:** 2026-02-06 06:16 GMT  
**Tester:** Automated (subagent linux-scanner-test)  
**Environment:** Docker `node:20-bookworm` (Debian 12) on Windows Docker Desktop  
**Scanner version:** 0.2.0  
**Node.js:** v20.x (container), v25.6.0 (host)

---

## Executive Summary

**✅ ALL 100 CHECKS EXECUTE SUCCESSFULLY ON LINUX — NO BUGS FOUND**

The Clawhatch security scanner builds, compiles, and runs cleanly on Linux with zero platform-specific failures. All unit tests pass (51/51). The Linux-specific permission checks (`chmod 600/700`) work correctly and are properly activated on Linux (while being correctly skipped on Windows).

---

## Build Results

| Step | Result | Notes |
|------|--------|-------|
| `npm ci` | ✅ Pass | 45 packages installed, 0 vulnerabilities |
| `npx tsc` | ✅ Pass | Clean compilation, no errors or warnings |
| Unit tests (`npm test`) | ✅ Pass | 51 tests, 8 suites, 0 failures |

**npm warning:** `glob@11.1.0` is flagged as deprecated. Non-blocking, but worth upgrading to current `glob` when convenient.

---

## Scanner Execution Results

### Test 1: Clean scan (proper permissions — 700/600)

| Metric | Value |
|--------|-------|
| Score | 95/100 (A+ — Excellent) |
| Platform reported | `linux` ✅ |
| Checks run | 100 |
| Checks passed | 97 |
| Findings (high confidence) | 3 |
| Suggestions (low confidence) | 12 |
| Duration | 65-134ms |
| Files scanned | 4 |

**Findings (expected for a minimal test config):**
- `TOOLS-004` MEDIUM — No tool allowlist configured
- `MODEL-004` LOW — Reasoning enabled in group contexts
- `MODEL-005` LOW — Verbose mode enabled in group contexts

### Test 2: Loose permissions scan (755/644)

| Metric | Value |
|--------|-------|
| Score | 79/100 (B — Acceptable) |
| Findings | 5 |

**Additional findings (Linux-specific permission checks activated):**
- `SECRET-003` HIGH — OpenClaw directory has permissions 755 (should be 700) ✅
- `SECRET-004` HIGH — Config file has permissions 644 (should be 600) ✅

**Verdict:** Linux permission checks work correctly. On Windows these would be skipped with an informational note (SECRET-003 LOW).

---

## Feature-by-Feature Linux Verification

| Feature | Status | Notes |
|---------|--------|-------|
| File discovery (`discover.ts`) | ✅ Pass | `~/.openclaw` resolved correctly on Linux |
| Config parsing (JSON5) | ✅ Pass | All parser tests pass |
| Environment file parsing | ✅ Pass | All parser tests pass |
| Identity checks (1-15) | ✅ Pass | All 15 checks execute |
| Network checks (16-25) | ✅ Pass | All 10 checks execute |
| Sandbox checks (26-33) | ✅ Pass | All 8 checks execute |
| Secret scanning (34-43+) | ✅ Pass | All checks execute; Linux chmod checks active |
| Model checks (44-58) | ✅ Pass | All 15 checks execute |
| Tool checks (TOOLS-001–020) | ✅ Pass | All 20 checks execute |
| Skill checks (SKILLS-001–012) | ✅ Pass | All 12 checks execute |
| Data protection (DATA-001–010) | ✅ Pass | All 10 checks execute |
| Operational (OPS-001–007) | ✅ Pass | All 7 checks execute |
| Cloud sync detection | ✅ Pass | Linux cloud paths checked |
| Scoring engine | ✅ Pass | All 8 scoring tests pass |
| Sanitization | ✅ Pass | All 8 sanitization tests pass |
| Auto-fix (`--fix`) | ✅ Pass | Permissions corrected 755→700, 644→600 |
| HTML report (`--format html`) | ✅ Pass | 15KB HTML report generated |
| JSON output (`--json`) | ✅ Pass | Valid JSON with correct structure |
| Init command | ✅ Pass | Creates config, .env, .gitignore |
| Missing path handling | ✅ Pass | Correct error message, exit code 1 |
| Platform detection | ✅ Pass | `process.platform === "linux"` |
| Error message paths | ✅ Pass | Shows `macOS/Linux: ~/.openclaw` (not Windows path) |

---

## Platform-Specific Handling Review

The scanner correctly handles platform differences in these areas:

### 1. File Permissions (secrets.ts, lines 57-120)
- **Windows:** Skips chmod checks, reports informational `SECRET-003` LOW finding
- **Linux:** Runs full permission checks for directory (700), config (600), credentials (600), auth profiles (600)
- **Verified:** Both paths work correctly ✅

### 2. Path Discovery (discover.ts)
- **Windows:** Checks `%APPDATA%\openclaw` and `~\AppData\Roaming\openclaw`
- **Linux:** Checks `~/.openclaw` only
- **Verified:** Linux path resolution works ✅

### 3. Cloud Sync Detection (cloud-sync.ts)
- **Windows:** Checks OneDrive, Dropbox, Google Drive, iCloud paths (Windows-style)
- **Linux:** Checks `~/Dropbox`, `~/Google Drive`, `~/OneDrive`
- **Verified:** No false positives in Docker container ✅

### 4. Identity checks (identity.ts, line 112)
- **Windows:** OAuth token permission check uses basic `fs.access` 
- **Linux:** Uses `fs.stat` and checks for exact `0o600` mode
- **Verified:** Both paths work ✅

---

## Minor Observations (Not Bugs)

### 1. `init` command creates files with 644 permissions
The `init` command creates `openclaw.json` and `.env` with default `644` permissions on Linux (Node.js default `umask`). Users would need to manually `chmod 600` after init. Consider adding `chmod` calls to `init.ts` for Linux.

**Severity:** Cosmetic/enhancement  
**Priority:** Low — the scanner will correctly flag this on subsequent scan and `--fix` will correct it.

### 2. glob@11.1.0 deprecation warning
npm warns that `glob@11.1.0` is deprecated. This doesn't affect functionality but should be updated.

**Severity:** Maintenance  
**Priority:** Low

### 3. No .env.example created by init
The `init` command doesn't create `.env.example`, which the scanner will suggest. Minor consistency issue.

**Severity:** Cosmetic  
**Priority:** Low

---

## Unit Test Results (Full)

```
TAP version 13
# tests 51
# suites 8
# pass 51
# fail 0
# cancelled 0
# skipped 0
# duration_ms 162ms

Suites:
  ✅ runIdentityChecks (8 tests)
  ✅ runNetworkChecks (9 tests)
  ✅ parseConfig (4 tests)
  ✅ readConfigRaw (2 tests)
  ✅ parseEnv (5 tests)
  ✅ sanitizeFindings (8 tests)
  ✅ calculateScore (8 tests)
  ✅ getScoreGrade (7 tests)
```

---

## Conclusion

The Clawhatch scanner is **fully cross-platform compatible**. No code changes are needed for Linux support. All 100 security checks execute correctly, platform detection works as designed, and the Linux-specific permission checks (chmod 600/700) are properly activated.

**Recommended follow-ups (non-blocking):**
1. Consider adding `chmod 600` to `init.ts` file creation on non-Windows platforms
2. Update `glob` dependency to latest version
3. Add a `.env.example` to the `init` command output

---

*Report generated automatically by Clawhatch Linux test suite*
