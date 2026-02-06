# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
