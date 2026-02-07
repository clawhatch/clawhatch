# Clawhatch Scanner — Code Review Report

**Reviewer:** Claude (subagent code-review)
**Date:** 2026-02-06
**Scope:** Full codebase review of `clawhatch/scanner/src/`
**Files reviewed:** 24 TypeScript source files + 5 test files + config files
**Tests:** 51/51 passing before and after fixes

---

## Summary

Overall code quality is **good**. The codebase is well-organized, has reasonable type safety with TypeScript strict mode, and follows sensible patterns. However, the review found **18 issues** requiring fixes across several categories: bugs, false-positive generators, memory safety, cross-platform issues, and security concerns.

**All fixes applied directly. No breaking changes to CLI interface.**

---

## Issues Found & Fixes Applied

### CRITICAL Fixes

| # | File | Issue | Fix |
|---|------|-------|-----|
| 1 | `secrets.ts`, `tools.ts` | **Unbounded file reads** — `readFile(logFile).then(c => c.slice(...))` reads the entire file into memory before slicing. Session logs can be hundreds of MB, causing OOM. | Added `readFileCapped()` helper that uses `createReadStream` with byte-counting to cap reads without loading full file. |
| 2 | `jsonl.ts` | **Deep mode reads unlimited data** — `deep: true` calls `readFile` on entire session log with no cap. A 500MB log file would crash the scanner. | Added `DEEP_MAX_BYTES = 50MB` hard cap for deep mode. Also fixed byte-counting: removed `encoding: "utf-8"` from stream so `chunk.length` reports bytes not characters. |
| 3 | `secrets.ts` | **SECRET-029 severity too low** — Stripe live secret key (`sk_live_`) rated MEDIUM, but live billing keys can create charges and access financial data. | Elevated from MEDIUM to CRITICAL. |

### HIGH Fixes

| # | File | Issue | Fix |
|---|------|-------|-----|
| 4 | `data-protection.ts` | **PII regex false positives** — Phone pattern `\d{3}[-.]?\d{3}[-.]?\d{4}` matches any 10-digit number (timestamps, versions, ports). SSN pattern matches any 9-digit number. Credit card pattern matches any 16-digit number. Email regex had `[A-Z\|a-z]` (literal pipe char in class). | Removed phone/SSN patterns entirely (unusable false-positive rate). Tightened credit card pattern to require separators. Fixed email regex from `[A-Z\|a-z]` to `[A-Za-z]`. |
| 5 | `fixer.ts` | **IDENTITY-008 in isConfigFix but not in applyConfigMutation** — Fix would be attempted but silently fail with "Mutation not implemented". | Removed IDENTITY-008 from `isConfigFix()` list. |
| 6 | `secrets.ts` | **SECRET-026 reads directory as file** — `.github/workflows` is a directory, but the code treats it as a file. `readFile` on a directory throws, caught by `.catch(() => "")` but CI detection is broken for GitHub Actions. | Rewrote to check if workflows dir is a directory first, then `readdir` + iterate YAML files inside. |
| 7 | `secrets.ts` | **SECRET-024 partial line matching** — `content.includes(line)` for shared credential detection matches substrings (e.g., `KEY=val` matches inside `MY_KEY=value`). | Changed to exact line matching using `Set` of trimmed lines. |
| 8 | `index.ts` | **Windows `~` expansion broken** — `init` command uses `process.env.HOME` which is undefined on Windows. Falls back to `USERPROFILE`, but `String.replace("~", ...)` only replaces first occurrence and doesn't handle path joining. | Replaced with `os.homedir()` + `path.join()` for reliable cross-platform expansion. |

### MEDIUM Fixes

| # | File | Issue | Fix |
|---|------|-------|-----|
| 9 | `scanner.ts` | **`checksPassed` can go negative** — `TOTAL_CHECKS - findings.length` can be negative if there are >100 findings. | Added `Math.max(0, ...)` clamp. |
| 10 | `scanner.ts` | **Silent config parse failure** — If `openclaw.json` exists but is corrupt, `parseConfig` returns `null` and all config checks are silently skipped with no warning. | Added warning log when config file exists but parsing fails. |
| 11 | `sanitize.ts` | **Missing secret patterns** — Sanitizer didn't catch Stripe webhook secrets, restricted keys, or Discord tokens that the scanner itself can detect. | Added `whsec_`, `rk_live_`, and Discord token patterns to `SECRET_INDICATORS`. |
| 12 | `model.ts` | **`parseFloat` NaN guard** — Temperature check could compare NaN > 1.0 (which is false, so no crash, but semantically wrong). | Added `!isNaN(temp)` guard. |
| 13 | `discover.ts` | **Case-sensitive path comparison on Linux** — `safeResolvePath` uses `.toLowerCase()` for symlink boundary checking, which is wrong on case-sensitive Linux filesystems. | Made comparison platform-aware: case-insensitive on Windows/macOS, case-sensitive on Linux. |
| 14 | `skills.ts` | **SKILLS-009 credential patterns too broad** — `/token/i`, `/secret/i`, `/password/i` match any mention of these common words in SKILL.md documentation, causing frequent false positives. | Tightened to require assignment/access syntax context (e.g., `process.env.SOME_VAR`, `key="value"` patterns). |
| 15 | `reporter-html.ts` | **Version mismatch** — HTML report footer says "v0.2.0" but package.json says "v0.1.0". | Fixed to "v0.1.0". |

### LOW Fixes

| # | File | Issue | Fix |
|---|------|-------|-----|
| 16 | `fixer.ts` | **Redundant dynamic import** — `applyGitignoreFix` does `await import("node:path")` to get `join`, but could use a top-level import. | Moved `join` to top-level import, removed dynamic import. |
| 17 | `operational.ts` | **Dead code** — `API_KEY_PATTERNS` defined but never used (unused constant). | Removed the dead code. |
| 18 | `parsers/env.ts` | **Missing `export` prefix handling** — Many `.env` files use `export KEY=value` syntax; parser would include "export" in the key name. | Added `export` prefix stripping. |

---

## Remaining Concerns (Not Fixed)

### Architectural / Design

1. **`readFileCapped` duplicated in secrets.ts and tools.ts** — Should be extracted to a shared utility module. Didn't refactor to avoid breaking module structure.

2. **TOTAL_CHECKS constant (100) is hardcoded** — The actual number of checks varies based on config and files found. The "100 checks" claim is aspirational/marketing rather than accurate. Not a bug, but misleading.

3. **No check deduplication** — If the same issue is found in multiple files (e.g., SECRET-005 for each credential file), findings accumulate and can exceed 100. The `checksPassed` calculation assumes 1 finding = 1 check failed, which isn't true.

4. **`ora` dependency imported but never used** — Listed in package.json but not imported in any source file. Could be removed to reduce package size.

### Cross-Platform

5. **Windows file permission checks limited** — The scanner correctly skips Unix chmod checks on Windows (SECRET-003 → informational finding), but can't check Windows ACLs. Would need `icacls` or PowerShell commands for full Windows support.

6. **`cloud-sync.ts` Windows OneDrive paths** — Generates duplicate path (`home\\OneDrive` appears twice with different construction). Not harmful but wasteful.

7. **`discover.ts` glob patterns use forward slashes** — `agents/*/sessions/*.jsonl` — the `glob` package handles this cross-platform, so this is fine, but worth noting for future maintainers.

### Security of Scanner Itself

8. **Config parsing uses JSON5** — JSON5 is more permissive than JSON. If a config file contains unexpected constructs (e.g., `Infinity`, `NaN` as values), `JSON5.parse` will accept them where `JSON.parse` wouldn't. Not a security risk per se, but worth noting.

9. **`git log` commands have 5-second timeouts** — Good practice, but a malicious `.git` directory could potentially hang the scanner for up to 5s per git command (there are 2 git commands: SECRET-027 and OPS-006).

10. **Scanner output includes file paths** — Finding objects include `file` paths which could reveal directory structure. The sanitizer only redacts secret patterns, not paths. This is by design but worth noting for deployment contexts.

### False Positive Risks

11. **IDENTITY-013 always fires** — "No API key rotation evidence" is emitted for every scan regardless of actual rotation practices. Should probably be gated behind some heuristic.

12. **SECRET-023 always fires** — "No credential rotation evidence" same issue.

13. **TOOLS-017 fires without elevated tools** — "No command audit trail" fires even if there are no elevated tools and no tool usage.

14. **MODEL-013 always fires** — "No output filtering configured" fires for all setups. Most OpenClaw deployments don't have output filtering config keys.

### Test Coverage

15. **No tests for check modules** — Only `identity.ts` and `network.ts` have unit tests. The other 8 check modules (`sandbox`, `secrets`, `model`, `tools`, `skills`, `data-protection`, `operational`, `cloud-sync`) have zero test coverage.

16. **No tests for fixer.ts** — The auto-fix system has no tests, which is risky since it modifies files.

17. **No integration tests** — No end-to-end scan test with a mock OpenClaw directory.

---

## Overall Assessment

| Category | Rating | Notes |
|----------|--------|-------|
| **Type Safety** | ⭐⭐⭐⭐ | Strict mode enabled. Good use of typed interfaces. No loose `any` types found. |
| **Error Handling** | ⭐⭐⭐ | All file reads wrapped in try/catch. Missing: corrupt JSON warning, stream error handling edge cases. |
| **Memory Safety** | ⭐⭐⭐ (was ⭐⭐) | Fixed unbounded reads. Deep mode now has 50MB cap. Session log scanning was previously unsafe for large files. |
| **Cross-Platform** | ⭐⭐⭐ | Good Windows awareness (permission checks, homedir). Fixed: case-sensitive path comparison, `~` expansion. Remaining: ACL checks. |
| **Logic Correctness** | ⭐⭐⭐⭐ | Scoring formula correct per spec. Severity ratings appropriate (fixed SECRET-029). Fixed several false-positive generators. |
| **Security of Scanner** | ⭐⭐⭐⭐ | Sanitization works well. Fixed missing sanitization patterns. No injection risks found. |
| **Code Organization** | ⭐⭐⭐⭐⭐ | Excellent modular structure. Clean separation of concerns. |
| **Test Coverage** | ⭐⭐ | Core modules tested. Check modules largely untested. No integration tests. |

**Overall: 3.5/5 — Solid foundation, production-ready after these fixes. Needs more test coverage for the check modules.**

---

## Files Modified

- `src/scanner.ts` — checksPassed clamp, config parse warning
- `src/index.ts` — cross-platform `~` expansion
- `src/sanitize.ts` — additional secret patterns
- `src/scoring.ts` — (no changes needed, correct per spec)
- `src/reporter-html.ts` — version string fix
- `src/fixer.ts` — removed broken IDENTITY-008 fix, top-level import
- `src/parsers/env.ts` — `export` prefix handling
- `src/parsers/jsonl.ts` — stream byte counting, deep mode cap
- `src/checks/secrets.ts` — readFileCapped, SECRET-029 severity, SECRET-024 matching, SECRET-026 directory handling
- `src/checks/tools.ts` — readFileCapped
- `src/checks/model.ts` — NaN guard
- `src/checks/data-protection.ts` — PII pattern false positives
- `src/checks/skills.ts` — credential pattern false positives
- `src/checks/operational.ts` — removed dead code
- `src/checks/cloud-sync.ts` — (no changes needed)
- `src/checks/network.ts` — (no changes needed)
- `src/checks/sandbox.ts` — (no changes needed)
- `src/checks/identity.ts` — (no changes needed)
- `src/discover.ts` — case-sensitive symlink boundary check
