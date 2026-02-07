# Clawhatch Scanner — Iteration Report

**Date:** 2026-02-06  
**Iteration:** Quality Pass v2  
**Author:** Subagent (scanner-iteration-v2)  
**Model:** Opus 4.6

---

## Executive Summary

This iteration addressed **17 remaining concerns** from the code review. All architectural fixes, false-positive reductions, cross-platform improvements, security enhancements, and test coverage expansions were implemented in a single coordinated pass.

**Final Stats:**
- **Tests:** 303 total (301 passed, 2 skipped Unix-only)
- **Build:** ✅ Clean (no errors or warnings)
- **Scanner score on Rich's setup:** 40/100 (D — capped due to CRITICAL: API keys in config)

---

## What Was Fixed

### 1. Architectural Fixes

#### ✅ readFileCapped Usage Verified
- **Status:** Already properly used everywhere (secrets.ts, tools.ts)
- **Evidence:** Both files import from `../utils.js`

#### ✅ TOTAL_CHECKS = 100 Documented
- **Before:** Unexplained magic number
- **After:** Comprehensive comment explaining it's the "marketed" number, actual checks vary by config

```typescript
/**
 * TOTAL_CHECKS: This is the "marketed" number of checks (100-point audit).
 * The actual number of check IDs varies based on config and files found,
 * since some checks only fire conditionally. We track checksRun separately
 * from this constant, which represents the maximum possible checks in a
 * comprehensive scan. The score formula uses actual findings, not this number.
 */
const TOTAL_CHECKS = 100;
```

#### ✅ Finding Deduplication Added
- **Before:** Same issue in multiple files = multiple findings, inflated count
- **After:** Findings with same ID are aggregated
- **Example output:** `"Large session log (15.0MB) — sampled (3 occurrences in: file1.jsonl, file2.jsonl, file3.jsonl)"`

#### ✅ ora Dependency Verified Gone
- **Status:** Not in package.json dependencies
- **Note:** Clean `npm ci` will remove from node_modules if present

---

### 2. False Positive Fixes

#### ✅ IDENTITY-013 (No API Key Rotation Evidence)
- **Before:** Always fired, even with no credentials
- **After:** Only fires when credential files or auth profiles exist
- **Heuristic:** Checks for rotation-related patterns (`_old`, `_backup`, `rotated`, etc.)

#### ✅ SECRET-023 (No Credential Rotation Evidence)
- **Before:** Always fired
- **After:** Only fires when .env exists or API keys found in config
- **Heuristics:** 
  - Looks for rotation patterns in .env
  - Checks .env modification date (if <30 days, assumes recent rotation)

#### ✅ TOOLS-017 (No Command Audit Trail)
- **Before:** Always fired
- **After:** Only fires when `hasRiskyTools` = true
- **Conditions:** elevated tools exist, OR workspace has `rw` access

#### ✅ MODEL-013 (No Output Filtering)
- **Before:** Always fired
- **After:** Only fires when:
  - `hasElevatedTools` = true, OR
  - `hasExternalChannels` = true (open DM or group policies)

---

### 3. Cross-Platform Fixes

#### ✅ Windows OneDrive Duplicate Paths Fixed
- **Before:** `[home\OneDrive, C:\Users\username\OneDrive]` (duplicate)
- **After:** `[home\OneDrive]` (correct)
- **File:** `cloud-sync.ts`

#### ✅ Windows ACL Checking Added
- **Before:** Just skipped with "cannot verify on Windows" message
- **After:** Actually runs `icacls` to check for dangerous groups (Everyone, Users)
- **Fallback:** If icacls fails, falls back to informational message

```typescript
const { stdout } = await execAsync("icacls", [files.openclawDir], { timeout: 5000, windowsHide: true });
const dangerousGroups = /\b(Everyone|Users|BUILTIN\\Users|Authenticated Users)\s*:\s*\((?!N\))/i;
if (dangerousGroups.test(stdout)) {
  // Flag as HIGH - permissive ACLs
}
```

---

### 4. Security Improvements

#### ✅ JSON5 Exotic Values Warning
- **File:** `parsers/config.ts`
- **Checks for:** `Infinity`, `-Infinity`, `NaN`, hexadecimal literals
- **Output:** Warnings to stderr when detected

#### ✅ Git Commands Slow Warning
- **Files:** `secrets.ts`, `operational.ts`
- **Behavior:** If git log takes >2s, logs warning
- **Message:** `"Warning: git log took ${duration}ms — consider optimizing git history"`

#### ✅ --redact-paths Flag Added
- **CLI:** `clawhatch scan --redact-paths`
- **Effect:** Replaces full file paths with `[path]/filename`
- **Use case:** Safe to share results publicly

---

### 5. Test Coverage Added

#### ✅ Integration Tests (`integration.test.ts`)
- Creates mock ~/.openclaw/ directory
- Runs full scanner
- Validates output structure
- Tests: minimal secure config, insecure config, secrets detection, finding deduplication

#### ✅ Fixer Tests (`fixer.test.ts`)
- Tests .gitignore fix (create, update, backup)
- Tests permission fix (Unix chmod, Windows skip)
- Tests config fix (NETWORK-001 gateway bind)
- Tests graceful handling of non-fixable and missing files

#### ✅ Format Tests (`formats.test.ts`)
- JSON output: valid structure, all required fields, special characters, empty arrays
- HTML output: valid document, score/grade, severity levels, HTML escaping, metadata, suggestions

---

## Test Results Summary

| Category | Before | After | Change |
|----------|--------|-------|--------|
| Total tests | 254 | 303 | +49 |
| Test files | 13 | 16 | +3 |
| Pass | 254 | 301 | +47 |
| Skip | 0 | 2 | +2 (Unix-only) |
| Fail | 0 | 0 | ✓ |

---

## Build Status

```
> clawhatch@0.1.0 build
> tsc

(no errors)
```

---

## Scanner Score on Rich's Setup

```json
{
  "score": 40,
  "grade": "D",
  "label": "Poor",
  "critical": 1,
  "high": 2,
  "medium": 4,
  "low": 4,
  "suggestions": 11
}
```

**Capped at 40 due to:**
- `SECRET-001` CRITICAL: 2 hardcoded API keys in openclaw.json

**Other findings:**
- `SECRET-016` HIGH: OAuth/access token in session log
- `DATA-001` HIGH: Session log may contain PII
- `SECRET-025` MEDIUM: Credentials in error messages
- `TOOLS-004` MEDIUM: No tool allowlist
- `TOOLS-015` MEDIUM: Shell commands may contain secrets
- `DATA-002` MEDIUM: No data retention policy

**Deduplication working:**
- `SECRET-011` shows "(3 occurrences in: ...)" for large session logs

---

## What Was Intentionally Left

### TOTAL_CHECKS Remains 100
- **Reasoning:** It's the marketed "100-point audit" number
- **Alternative considered:** Dynamic counting of checks that ran
- **Decision:** Document it, keep as-is for marketing consistency

### No Luhn Check for Credit Cards
- **Current:** Simple pattern match with separator requirement
- **Considered:** Full Luhn algorithm validation
- **Decision:** Out of scope, current pattern is reasonably specific

### Unix Permission Tests Skipped on Windows
- **Tests:** 2 tests skipped (`fixes directory permissions on Unix`, `fixes file permissions on Unix`)
- **Reasoning:** Node.js `chmod` only works on Unix; tests correctly skip on Windows

---

## Files Modified

### Source Files
- `src/scanner.ts` — Deduplication function, step renumbering, TOTAL_CHECKS docs
- `src/index.ts` — --redact-paths flag
- `src/sanitize.ts` — redactPaths function
- `src/parsers/config.ts` — checkExoticValues function
- `src/checks/identity.ts` — IDENTITY-013 gating
- `src/checks/secrets.ts` — SECRET-023 gating, Windows ACL check, git timing
- `src/checks/tools.ts` — TOOLS-017 gating
- `src/checks/model.ts` — MODEL-013 gating
- `src/checks/cloud-sync.ts` — Windows OneDrive path fix
- `src/checks/operational.ts` — Git timing warning

### Test Files (New)
- `src/__tests__/integration.test.ts` — End-to-end scanner tests
- `src/__tests__/fixer.test.ts` — Auto-fix system tests
- `src/__tests__/formats.test.ts` — JSON/HTML output tests

### Test Files (Updated)
- `src/__tests__/identity.test.ts` — IDENTITY-013 behavior
- `src/__tests__/secrets.test.ts` — SECRET-003, SECRET-023 behavior
- `src/__tests__/tools.test.ts` — TOOLS-017 behavior
- `src/__tests__/model.test.ts` — MODEL-013 behavior

### Documentation
- `CHANGELOG.md` — v0.1.1 entry

---

## Verification Commands

```powershell
# Build
cd C:\Users\RICHARD\clawd\clawhatch\scanner
npm run build

# Test
npm test

# Scan with new flag
node dist/index.js scan --redact-paths --json
```

---

## Conclusion

All 17 concerns from the code review have been addressed:

1. ✅ `readFileCapped` verified everywhere
2. ✅ TOTAL_CHECKS documented
3. ✅ Finding deduplication added
4. ✅ `ora` verified gone
5. ✅ IDENTITY-013 gated
6. ✅ SECRET-023 gated
7. ✅ TOOLS-017 gated
8. ✅ MODEL-013 gated
9. ✅ Windows OneDrive paths fixed
10. ✅ Windows ACL checking added
11. ✅ JSON5 exotic values warning
12. ✅ Git commands slow warning
13. ✅ --redact-paths flag added
14. ✅ Integration tests added
15. ✅ Fixer tests added
16. ✅ JSON format tests added
17. ✅ HTML format tests added

The scanner is now higher quality, produces fewer false positives, works better on Windows, and has comprehensive test coverage for all major features.
