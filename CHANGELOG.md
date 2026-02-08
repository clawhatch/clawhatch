# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] — 2026-02-07

### Added
- **`--quiet` flag** — Minimal output mode that only displays score and grade (useful for CI/CD scripts)
- Replaced `glob` with `fast-glob` for better performance and no deprecation warnings

### Fixed
- **npm deprecation warning** — Replaced deprecated `glob@11.1.0` with modern `fast-glob@3.x`
- **CLI output polish** — Suppressed webhook/community messages in quiet and JSON modes

### Changed
- All glob patterns now use `fast-glob` (lighter, faster, actively maintained)
- Improved CI/CD integration with `--quiet` flag for scripting

## [0.2.0] — 2026-02-07

### Added
- **Monitoring tier** — Scheduled scanning and trend analysis
  - `clawhatch monitor` — Manual scan with comparison to previous scan
  - `clawhatch monitor --start` — Start scheduled monitoring (paid tier)
  - `clawhatch monitor --stop` — Stop scheduled monitoring
  - `clawhatch monitor --status` — View monitoring status and scan history
  - `clawhatch monitor --report` — Generate trend report (paid tier)
- **Scan history** — Results stored in `~/.clawhatch/history/` as timestamped JSON files
- **Scan comparison** — Detects new issues, resolved issues, and score changes
- **Trend reports** — Shows score trends, new/resolved/persistent issues over time
- **License key support** — Validates license from `~/.clawhatch/license.key`
- **Freemium model** — Free tier (manual scans) vs. paid tier (scheduled monitoring + history + reports)
- **Tasteful upsell messaging** — Encourages upgrade without being intrusive

### Changed
- Version bumped to 0.2.0 in package.json and CLI

## [0.1.1] — 2026-02-06

### Added
- **Finding deduplication** — Same check ID across multiple files now aggregates into single finding with count
- **`--redact-paths` flag** — Redacts file paths in output for safe sharing of results
- **Windows ACL checking** — Now uses `icacls` to actually check file permissions on Windows (was just skipped)
- **JSON5 exotic value warnings** — Warns if config contains Infinity, NaN, or hex literals
- **Git command performance warnings** — Logs warning if git commands take >2s (may indicate large repo)
- **Integration tests** — End-to-end tests with mock ~/.openclaw/ directories
- **Fixer tests** — Tests for the auto-fix system
- **Format tests** — Tests for JSON and HTML output structure

### Changed
- **IDENTITY-013** — Now only fires when credential files exist (was always firing)
- **SECRET-023** — Now only fires when .env or API keys exist (was always firing)
- **TOOLS-017** — Now only fires when elevated tools or rw workspace exist (was always firing)
- **MODEL-013** — Now only fires when elevated tools or external channels exist (was always firing)
- **Windows OneDrive paths** — Fixed duplicate path construction in cloud-sync detection
- **TOTAL_CHECKS** — Documented why it's 100 (marketing number, actual checks vary by config)

### Fixed
- Finding deduplication prevents inflated finding counts when same issue appears in multiple files

## [0.1.0] — Unreleased

### Added
- **100 security checks** across 8 categories:
  - Identity & Authentication
  - Secrets & Credential Exposure
  - Network & API Security
  - Sandbox & Isolation
  - Model & Prompt Security
  - Tool & Permission Security
  - Skills & Plugin Security
  - Cloud Sync & Backup
- **Auto-fix mode** (`--fix`) — automatically remediate common misconfigurations
- **JSON export** (`--json`) — machine-readable output for CI/CD integration
- **HTML report** generation for shareable audit results
- **Severity scoring** — weighted risk assessment (critical/high/medium/low/info)
- **Config auto-discovery** — finds OpenClaw config files automatically
- **Init command** (`clawhatch init`) — guided setup for new users
- **Cross-platform support** — Windows and Linux
- **Zero-config scanning** — works out of the box with sensible defaults
- Parsers for JSON, JSON5, JSONL, ENV, and Markdown config formats
- Comprehensive test suite

[0.1.0]: https://github.com/wlshlad85/clawhatch/releases/tag/v0.1.0
