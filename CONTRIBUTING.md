# Contributing to Clawhatch

Thanks for your interest in improving AI agent security! Here's how to get involved.

## Development Setup

1. **Clone the repo:**
   ```bash
   git clone https://github.com/wlshlad85/clawhatch.git
   cd clawhatch
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Build:**
   ```bash
   npm run build
   ```

4. **Run in dev mode:**
   ```bash
   npm run dev -- scan /path/to/openclaw/config
   ```

### Requirements
- Node.js ≥ 18.0.0
- TypeScript 5.x
- Works on Windows and Linux

## Running Tests

```bash
npm test
```

Tests live in `src/__tests__/` and use Node's built-in test runner. The build step runs first automatically.

To type-check without building:
```bash
npm run typecheck
```

## Adding New Security Checks

Checks live in `src/checks/`. Each file exports an array of check functions grouped by category.

### Steps to add a check:

1. **Pick the right category file** (or create one if it's a new category):
   - `identity.ts` — Identity & authentication
   - `secrets.ts` — Secrets & credential exposure
   - `network.ts` — Network & API security
   - `sandbox.ts` — Sandbox & isolation
   - `model.ts` — Model & prompt security
   - `tools.ts` — Tool & permission security
   - `skills.ts` — Skills & plugin security
   - `cloud-sync.ts` — Cloud sync & backup
   - `data-protection.ts` — Data protection
   - `operational.ts` — Operational security

2. **Define the check** following the `CheckDefinition` type in `src/types.ts`:
   ```typescript
   {
     id: 'CATEGORY-NNN',
     title: 'Short description',
     description: 'Why this matters',
     severity: 'critical' | 'high' | 'medium' | 'low' | 'info',
     category: 'category-name',
     check: async (ctx: ScanContext) => CheckResult,
     fix?: async (ctx: ScanContext) => FixResult,
   }
   ```

3. **Write the check function** — it receives a `ScanContext` with parsed config, env, and file paths.

4. **Optionally add an auto-fix** — the `fix` function runs when `--fix` is passed.

5. **Add a test** in `src/__tests__/` covering pass, fail, and edge cases.

6. **Update the count** if you've increased the total number of checks.

## Code Style

- **TypeScript strict mode** — no `any` unless absolutely necessary
- **ESM imports** — use `import`, not `require`
- **Descriptive names** — `checkTlsEnforcement` not `chk17`
- **Pure functions** where possible — checks should be deterministic
- **No external runtime dependencies** unless critical — keep the package light
- **Comments** — explain *why*, not *what*

## Pull Request Process

1. **Fork** the repo and create a feature branch from `main`
2. **Make your changes** — keep PRs focused (one feature/fix per PR)
3. **Run tests** — `npm test` must pass
4. **Run type-check** — `npm run typecheck` must pass
5. **Update CHANGELOG.md** if adding user-facing changes
6. **Open a PR** with a clear description of what and why
7. **Wait for review** — maintainers will respond within a few days

### PR Checklist
- [ ] Tests pass
- [ ] Types check
- [ ] New checks have tests
- [ ] CHANGELOG updated (if applicable)
- [ ] No secrets or credentials in the diff

## Reporting Bugs

Use the [bug report template](https://github.com/wlshlad85/clawhatch/issues/new?template=bug_report.md) on GitHub Issues.

## Suggesting Features

Use the [feature request template](https://github.com/wlshlad85/clawhatch/issues/new?template=feature_request.md) on GitHub Issues.

## Security Issues

**Do NOT open a public issue for security vulnerabilities.** See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
