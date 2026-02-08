# Clawhatch v0.2.1 Patch Release Report

**Status:** ✅ Ready for release (DO NOT PUBLISH — as requested)  
**Version:** 0.2.0 → 0.2.1  
**Date:** 2026-02-07  
**Test Results:** 314/314 passed ✅ (2 skipped on Windows)

---

## Issues Fixed

### 1. ✅ npm `glob@11.1.0` deprecation warning
**Problem:** The `glob` package had deprecation warnings urging upgrade to v13, but v13 requires Node 20+ (incompatible with our Node 18+ target).

**Solution:** Replaced `glob@11.1.0` with `fast-glob@3.3.3`
- Modern, actively maintained alternative
- No deprecation warnings
- Better performance and smaller bundle size
- Fully compatible with Node 18+
- All glob patterns tested and working

**Files changed:**
- `package.json` — replaced dependency
- `src/discover.ts` — updated all glob imports and calls (9 locations)
- Changed `maxDepth: 3` to `deep: 3` (fast-glob API difference)

---

### 2. ✅ npm publish bin warning
**Status:** No issue found — bin field is correct

**Verification:**
```json
"bin": {
  "clawhatch": "./dist/index.js"
}
```

- ✅ File exists at `dist/index.js` after build
- ✅ Shebang present: `#!/usr/bin/env node`
- ✅ File is executable and runs correctly
- ✅ `--help` and `--version` work as expected

---

### 3. ✅ CLI polish
**What was done:**
- ✅ Verified `--help` works for all commands (scan, init, monitor, threats, subscribe)
- ✅ Error messages are clear and actionable
- ✅ Output formatting is consistent and professional
- ✅ Color coding works properly (CRITICAL=red, HIGH=yellow, etc.)

---

### 4. ✅ Added `--json` flag
**Status:** Already existed! Just verified it works correctly.

**Verification:**
- ✅ `--json` flag documented in help text
- ✅ Outputs valid JSON to stdout
- ✅ Sanitizes secrets before JSON export
- ✅ Includes summary object with counts
- ✅ Suppresses verbose messages in JSON mode

---

### 5. ✅ Added `--quiet` flag (NEW)
**Purpose:** Minimal output for CI/CD scripting

**Implementation:**
- Added `--quiet` option to scan command
- Created `reportQuiet()` function in `reporter.ts`
- Output format: `{score}/100 {grade} ({label})`
- Example: `85/100 A (Good)`
- Suppresses all webhook/community messages
- Ideal for CI/CD scripts that just need pass/fail + score

**Usage:**
```bash
clawhatch scan --quiet
# Output: 85/100 A (Good)
# Exit code: 0 (or 1 if CRITICAL findings)
```

---

## Test Results

### Full test suite run:
```
✔ tests 316
✔ pass 314
✔ fail 0
✔ skipped 2 (Windows-specific Unix permission tests)
✔ duration_ms 1718.68
```

### Categories tested:
- ✅ Cloud sync checks
- ✅ Data protection checks
- ✅ Auto-fix system
- ✅ JSON/HTML output formats
- ✅ Identity & authentication checks
- ✅ Integration tests (full scanner)
- ✅ Model security checks
- ✅ Monitor/history features
- ✅ Network security checks
- ✅ Operational checks
- ✅ Config/env parsers
- ✅ Sandbox checks
- ✅ Sanitization (secret redaction)
- ✅ Scoring system
- ✅ Secret detection
- ✅ Skill checks
- ✅ Tool permission checks

**No tests broken by changes!**

---

## Version Bump

**Changes:**
- `package.json`: `0.2.0` → `0.2.1`
- `src/index.ts`: Updated all version strings
- `CHANGELOG.md`: Added v0.2.1 entry

---

## Files Changed

### Modified:
1. `package.json` — version bump, glob → fast-glob
2. `src/index.ts` — added --quiet flag, version strings
3. `src/discover.ts` — replaced glob with fast-glob
4. `src/reporter.ts` — added reportQuiet() function
5. `CHANGELOG.md` — added v0.2.1 entry

### No breaking changes!

---

## What Was NOT Done (as requested)

❌ **Did NOT publish to npm** — ready but not published  
❌ **Did NOT create git tag** — ready to tag as v0.2.1  
❌ **Did NOT create GitHub release** — ready to release

---

## Ready for Release

The package is ready for release:

```bash
# To publish (when ready):
npm publish

# To tag:
git tag v0.2.1
git push origin v0.2.1
```

---

## Summary

✅ All known issues fixed  
✅ New features added (--quiet flag)  
✅ All 314 tests passing  
✅ No breaking changes  
✅ CHANGELOG updated  
✅ Version bumped to 0.2.1  
✅ Ready for npm publish (but NOT published per instructions)

**Recommendation:** This is a clean patch release ready to ship.
