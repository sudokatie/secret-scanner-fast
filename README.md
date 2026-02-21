# secret-scanner-fast

Blazing fast secret scanner for codebases. Finds API keys, tokens, and credentials before they hit production.

## Why This Exists

You're about to push code. There's a 99% chance you didn't accidentally commit your AWS keys. But that 1%? That's the one that costs you $50k in crypto mining charges.

This tool catches secrets *fast* - we're talking 10k+ files per second on modern hardware - so you can run it on every commit without thinking about it.

## Installation

```bash
cargo install secret-scanner-fast
```

Or build from source:

```bash
git clone https://github.com/sudokatie/secret-scanner-fast
cd secret-scanner-fast
cargo build --release
```

## Quick Start

```bash
# Scan current directory
secret-scanner-fast

# Scan specific path
secret-scanner-fast scan ./src

# JSON output for CI
secret-scanner-fast scan --format json

# Only high severity
secret-scanner-fast scan --min-severity high

# SARIF for GitHub Code Scanning
secret-scanner-fast scan --format sarif > results.sarif
```

## What It Detects

**High Confidence** (unique prefixes, unambiguous):
- AWS Access Keys (`AKIA...`)
- GitHub Tokens (`ghp_`, `gho_`, `ghs_`, `ghr_`)
- GitLab Tokens (`glpat-...`)
- Slack Tokens (`xoxb-`, `xoxp-`)
- Stripe Keys (`sk_live_`, `sk_test_`)
- SendGrid Keys (`SG.`)
- Private Keys (`-----BEGIN RSA PRIVATE KEY-----`)
- And 15+ more patterns

**Medium Confidence** (validated with entropy):
- Generic API keys
- Bearer tokens
- Database connection strings
- JWTs

## Configuration

Create `.secretscanner.yaml`:

```bash
secret-scanner-fast init
# Or with all options documented:
secret-scanner-fast init --full
```

Example config:

```yaml
scan:
  exclude:
    - "**/test/**"
    - "**/*.test.*"
  max_file_size: 1048576

output:
  format: text
  redact: true

rules:
  min_severity: low
  allowlist:
    - pattern: "EXAMPLE|example|test|fake"
      reason: "Test values"
```

## Output Formats

**Text** (default) - Human readable with colors:
```
src/config.py:42:5: aws-access-key [high] AKIA...MPLE
```

**JSON** - Machine parseable:
```bash
secret-scanner-fast scan --format json
```

**SARIF** - GitHub Code Scanning integration:
```bash
secret-scanner-fast scan --format sarif > results.sarif
```

**CSV** - Spreadsheet friendly:
```bash
secret-scanner-fast scan --format csv
```

## CI Integration

### GitHub Actions

```yaml
- name: Scan for secrets
  run: |
    cargo install secret-scanner-fast
    secret-scanner-fast scan --format sarif > results.sarif
    
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

### Pre-commit Hook

```bash
#!/bin/sh
secret-scanner-fast scan --staged
if [ $? -ne 0 ]; then
    echo "Secrets detected! Commit blocked."
    exit 1
fi
```

## Performance

Built with Rust and rayon for parallel scanning:

- **10k+ files/second** on modern hardware
- Streams large files (constant memory)
- Respects `.gitignore`
- Skips binary files automatically

## Exit Codes

- `0` - No secrets found
- `1` - Secrets found
- `2` - Error (invalid args, file not found, etc.)

## List Detection Rules

```bash
# Human readable
secret-scanner-fast rules

# JSON
secret-scanner-fast rules --format json

# Filter by severity
secret-scanner-fast rules --severity high
```

## License

MIT
