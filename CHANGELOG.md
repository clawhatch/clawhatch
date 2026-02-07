# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
