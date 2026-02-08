# Clawhatch Monitor — Quick Start

## Installation

```bash
npm install -g clawhatch@0.2.0
# or
npx clawhatch@0.2.0 monitor
```

## Commands

### Manual Scan with Comparison

```bash
clawhatch monitor
```

Runs a scan, saves to history, and compares to the previous scan.

**Free tier** ✅

### View Status

```bash
clawhatch monitor --status
```

Shows:
- License tier (Free/Paid)
- Monitoring status
- Scan history count
- Recent scans

**Free tier** ✅

### Generate Trend Report

```bash
clawhatch monitor --report
```

Shows score trends, new/resolved/persistent issues.

**Requires paid tier** 🔒

### Start Scheduled Monitoring

```bash
clawhatch monitor --start
clawhatch monitor --start --schedule daily
```

Enables automatic scheduled scans.

**Requires paid tier** 🔒

### Stop Scheduled Monitoring

```bash
clawhatch monitor --stop
```

Disables automatic scans.

## Getting a License

1. Visit [clawhatch.com/pricing](https://clawhatch.com/pricing)
2. Purchase a license key
3. Save it to `~/.clawhatch/license.key`:
   ```bash
   echo "YOUR-LICENSE-KEY" > ~/.clawhatch/license.key
   ```

## Example Workflow

```bash
# First scan (creates history)
clawhatch monitor

# Check status
clawhatch monitor --status

# Run again after making changes
clawhatch monitor
# → Shows changes since last scan

# Get trend report (paid tier)
clawhatch monitor --report
```

## Output Example

```
Clawhatch Monitor — Manual Scan

  Discovering files...
  Parsing configuration...
  Running 100 security checks...
  Saved to: ~/.clawhatch/history/2026-02-07T10-30-45Z.json

  Changes Since Last Scan
    Score: 75/100 📈 +10
    New issues: 0
    Resolved issues: 2
      ✓ API key(s) found in openclaw.json
      ✓ OAuth/access token in session log

  Security Score: 75/100 (B — Acceptable)
  ...
```

## Data Location

- **Config:** `~/.clawhatch/config.json`
- **License:** `~/.clawhatch/license.key`
- **History:** `~/.clawhatch/history/*.json`

## Storage

Each scan stores ~6KB. 100 scans = ~600KB.

History is kept indefinitely (future: auto-cleanup options).

## Free vs. Paid

| Feature | Free | Paid |
|---------|------|------|
| Manual scans | ✅ | ✅ |
| History storage | ✅ | ✅ |
| Change detection | ✅ | ✅ |
| Scheduled scans | ❌ | ✅ |
| Trend reports | ❌ | ✅ |
| Alerts | ❌ | ✅ |

## Need Help?

- **GitHub:** [github.com/wlshlad85/clawhatch](https://github.com/wlshlad85/clawhatch)
- **Email:** security@clawhatch.com
- **Docs:** Run `clawhatch monitor --help`
