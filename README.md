# Security Gate Action

[![CI](https://github.com/HatakuSec/security-gate-action/actions/workflows/ci.yml/badge.svg)](https://github.com/HatakuSec/security-gate-action/actions/workflows/ci.yml)

> Config-driven security scanner orchestrator for GitHub repositories.

**Security Gate** is a GitHub Action that scans your repository for security issues across multiple dimensions:

- 🔑 **Secrets** — Detect leaked credentials, API keys, and tokens (including custom rules)
- 📦 **Dependencies** — Identify known vulnerabilities via the OSV API
- 🏗️ **Infrastructure as Code** — Find misconfigurations in Terraform and Kubernetes files (via Trivy)
- 🐳 **Containers** — Validate Dockerfile best practices and optionally scan with Trivy
- 📋 **Allowlists** — Suppress known false positives with expiry dates
- 📄 **SARIF Output** — Integration with GitHub Code Scanning

The action produces actionable **GitHub annotations**, a **job summary**, and optional **SARIF output** with findings organised by severity.

## Documentation

- [**Configuration Reference**](docs/CONFIGURATION.md) — Complete configuration file documentation
- [**Scanner Reference**](docs/SCANNERS.md) — Detailed scanner documentation and rules
- [**Troubleshooting**](docs/TROUBLESHOOTING.md) — Common issues and solutions
- [**JSON Schema**](schema/config.schema.json) — Schema for IDE validation
- [**Example Repository**](https://github.com/HatakuSec/security-gate-example-repo) — Integration tests and demo configurations

---

## Quick Start

Add this workflow to your repository at `.github/workflows/security-gate.yml`:

```yaml
name: Security Gate

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Security Gate
        uses: HatakuSec/security-gate-action@v1.0.0
        with:
          fail_on: high
```

That's it! The action runs in **auto mode** by default, automatically detecting which scanners are relevant for your repository.

---

## Configuration

### Config File Discovery

Security Gate looks for a configuration file in this order:

1. Path specified via `config_path` input
2. `.security-gate.yml`
3. `.security-gate.yaml`
4. `security-gate.yml`
5. `security-gate.yaml`

If no configuration file is found, sensible defaults are used.

### Example Configuration

```yaml
# .security-gate.yml
version: '1'

# Minimum severity to fail the workflow
fail_on: high # high | medium | low

# Scanner mode
mode: auto # auto | explicit

# Scanner-specific settings
scanners:
  secrets:
    enabled: true
  dependencies:
    enabled: true
  iac:
    enabled: true
  container:
    enabled: true
```

In **auto mode**, scanners are enabled based on repository content:

- **Secrets**: Always enabled
- **Dependencies**: Enabled if lockfiles are present (package-lock.json, yarn.lock, requirements.txt, Pipfile.lock, etc.)
- **IaC**: Enabled if Terraform files (\*.tf) or Kubernetes manifests are detected
- **Container**: Enabled if Dockerfile or docker-compose.yml is present

In **explicit mode**, only scanners explicitly set to `enabled: true` will run.

---

## Inputs

| Input               | Description                                                                                              | Default              | Required |
| ------------------- | -------------------------------------------------------------------------------------------------------- | -------------------- | -------- |
| `config_path`       | Path to the Security Gate configuration file (relative to repository root)                               | `.security-gate.yml` | No       |
| `fail_on`           | Minimum severity level that will cause the action to fail. Options: `high`, `medium`, `low`              | `high`               | No       |
| `mode`              | Scanner mode. `auto` detects and runs relevant scanners; `explicit` only runs scanners enabled in config | `auto`               | No       |
| `verbose`           | Enable verbose debug logging (secrets are still masked)                                                  | `false`              | No       |
| `working_directory` | Directory to scan (relative to repository root). Useful for monorepos                                    | `.`                  | No       |
| `sarif_output`      | Path to write SARIF output file. If not set, SARIF output is disabled                                    | (empty)              | No       |

---

## Outputs

| Output           | Description                                       |
| ---------------- | ------------------------------------------------- |
| `findings_count` | Total number of security findings detected        |
| `high_count`     | Number of high-severity findings                  |
| `medium_count`   | Number of medium-severity findings                |
| `low_count`      | Number of low-severity findings                   |
| `passed`         | Whether the security gate passed (`true`/`false`) |
| `sarif_path`     | Path to SARIF output file (if enabled)            |

---

## Behaviour

### Threshold Logic

The `fail_on` input controls which severity levels cause the action to fail:

| `fail_on` | High Findings | Medium Findings | Low Findings | Result   |
| --------- | ------------- | --------------- | ------------ | -------- |
| `high`    | ≥1            | any             | any          | **FAIL** |
| `high`    | 0             | any             | any          | PASS     |
| `medium`  | ≥1            | any             | any          | **FAIL** |
| `medium`  | 0             | ≥1              | any          | **FAIL** |
| `medium`  | 0             | 0               | any          | PASS     |
| `low`     | ≥1            | any             | any          | **FAIL** |
| `low`     | 0             | ≥1              | any          | **FAIL** |
| `low`     | 0             | 0               | ≥1           | **FAIL** |

### Exit Codes

| Code | Meaning                                         |
| ---- | ----------------------------------------------- |
| `0`  | All checks passed (no findings above threshold) |
| `1`  | Policy violation (findings above threshold)     |
| `2`  | Configuration error                             |
| `3`  | Scanner execution error                         |

### Annotations

- **High-severity** findings produce `error` annotations
- **Medium-severity** findings produce `warning` annotations
- **Low-severity** findings produce `notice` annotations

A maximum of **50 annotations** are emitted per run. If more findings exist, a notice is added indicating additional findings are available in the summary.

### Secret Masking

All detected secrets are:

1. Registered with `core.setSecret()` to prevent logging
2. Displayed with only the first 4 and last 2 characters visible (e.g., `AKIA************LE`)
3. Never logged in full, even in verbose mode

### Trivy Integration

For IaC and Container scanning, Security Gate uses [Trivy](https://trivy.dev/):

- **Version**: Trivy v0.58.0 is pinned for reproducibility
- **Auto-download**: If Trivy is not in PATH, it is automatically downloaded
- **Platforms**: Supports Linux and macOS (amd64 and arm64)
- **No shell piping**: Downloads are performed securely without `curl | sh`

---

## Examples

### Minimal Workflow

```yaml
name: Security Gate

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: HatakuSec/security-gate-action@v1.0.0
```

### Strict Mode (Fail on Any Finding)

```yaml
name: Security Gate (Strict)

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: HatakuSec/security-gate-action@v1.0.0
        with:
          fail_on: low # Fail on any severity
```

### Explicit Scanner Selection

```yaml
name: Security Gate (Secrets Only)

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: HatakuSec/security-gate-action@v1.0.0
        with:
          mode: explicit
```

With config file:

```yaml
# .security-gate.yml
version: '1'
mode: explicit

scanners:
  secrets:
    enabled: true
  dependencies:
    enabled: false
  iac:
    enabled: false
  container:
    enabled: false
```

### Monorepo Scanning

```yaml
name: Security Gate (Backend)

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: HatakuSec/security-gate-action@v1.0.0
        with:
          working_directory: packages/backend
```

### Using Outputs

```yaml
name: Security Gate with Outputs

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Security Gate
        id: security
        uses: HatakuSec/security-gate-action@v1.0.0
        continue-on-error: true

      - name: Check results
        run: |
          echo "Total findings: ${{ steps.security.outputs.findings_count }}"
          echo "High: ${{ steps.security.outputs.high_count }}"
          echo "Medium: ${{ steps.security.outputs.medium_count }}"
          echo "Low: ${{ steps.security.outputs.low_count }}"
          echo "Passed: ${{ steps.security.outputs.passed }}"
```

---

## Scanners

### Secrets Scanner

Detects high-signal credential patterns:

| Pattern | Description                  | Severity |
| ------- | ---------------------------- | -------- |
| SEC001  | AWS Access Key               | high     |
| SEC002  | AWS Secret Key               | high     |
| SEC003  | GitHub Token (ghp\_)         | high     |
| SEC004  | GitHub OAuth Token (gho\_)   | high     |
| SEC005  | GitHub PAT (fine-grained)    | high     |
| SEC006  | Private Key (RSA/EC/OPENSSH) | high     |
| SEC007  | Generic API Key              | medium   |
| SEC008  | Generic Secret/Password      | medium   |
| SEC009  | Slack Token                  | high     |
| SEC010  | Stripe Live Key              | high     |

### Dependency Scanner

Queries the [OSV (Open Source Vulnerabilities)](https://osv.dev/) API to identify known vulnerabilities in:

- `package-lock.json` (npm)
- `yarn.lock`
- `requirements.txt` (Python)
- `Pipfile.lock` (Python)

Severity is mapped from CVSS scores:

- CVSS ≥ 9.0 → high
- CVSS ≥ 7.0 → medium
- CVSS < 7.0 → low

### IaC Scanner

Uses Trivy to scan infrastructure-as-code files:

- Terraform (`*.tf`, `*.tfvars`)
- Kubernetes manifests (YAML with `apiVersion` and `kind`)
- CloudFormation templates
- Helm charts

### Container Scanner

Validates Dockerfiles against best practices:

| Rule    | Description                                  | Severity |
| ------- | -------------------------------------------- | -------- |
| DOCK001 | Using `:latest` tag for base image           | medium   |
| DOCK002 | Missing `USER` instruction (running as root) | medium   |
| DOCK003 | Missing `HEALTHCHECK` instruction            | low      |
| DOCK004 | `sudo` usage in RUN commands                 | high     |
| DOCK005 | `ADD` used instead of `COPY` for local files | medium   |
| DOCK006 | Missing `.dockerignore` file                 | low      |
| DOCK007 | Secrets passed via `ARG`                     | medium   |
| DOCK008 | `curl \| sh` pattern detected                | high     |

Optionally runs Trivy filesystem scan for additional vulnerability detection.

---

## Custom Rules

Define custom regex patterns to detect organisation-specific secrets or tokens:

```yaml
# .security-gate.yml
version: '1'

rules:
  - id: INTERNAL-TOKEN
    name: Internal API Token
    description: Detects internal API tokens with INT_TOKEN prefix
    regex: 'INT_TOKEN_[A-Za-z0-9]{16,}'
    severity: high
    file_globs:
      - '**/*.ts'
      - '**/*.js'
    allowlist:
      - match: 'INT_TOKEN_EXAMPLE'
        reason: Documentation example
```

### Custom Rule Fields

| Field         | Description                                  | Required |
| ------------- | -------------------------------------------- | -------- |
| `id`          | Unique rule identifier (max 64 chars)        | Yes      |
| `name`        | Human-readable name (max 128 chars)          | Yes      |
| `regex`       | Regular expression pattern (max 500 chars)   | Yes      |
| `severity`    | Finding severity: `high`, `medium`, or `low` | Yes      |
| `description` | Detailed description (max 500 chars)         | No       |
| `file_globs`  | Array of glob patterns to match (max 25)     | No       |
| `allowlist`   | Patterns to exclude from matches (max 20)    | No       |

### Safety Limits

Custom rules are protected against dangerous patterns:

- **Maximum 50 rules** per configuration
- **Regex length** limited to 500 characters
- **ReDoS protection** — patterns with nested quantifiers like `(a+)+` or catastrophic backtracking are rejected

---

## Ignore Paths

Exclude files or directories from scanning:

```yaml
# .security-gate.yml
version: '1'

ignore:
  paths:
    - '**/*.md' # All markdown files
    - 'docs/**' # Documentation directory
    - 'tests/fixtures/**' # Test fixtures
    - 'vendor/**' # Vendored dependencies
```

Ignore patterns use glob syntax and are applied to **all scanners**.

---

## Allowlist

Suppress specific findings with audit trails and optional expiry dates:

```yaml
# .security-gate.yml
version: '1'

allowlist:
  - id: allow-test-credentials
    reason: Test credentials for CI, rotated weekly
    expires: '2026-06-01'
    match:
      path_glob: 'tests/fixtures/**'
      rule_id: SEC007

  - id: allow-legacy-code
    reason: Legacy module, scheduled for removal in Q2
    expires: '2026-04-01'
    match:
      path_glob: 'src/legacy/**'

  - id: allow-specific-finding
    reason: False positive - this is not a real secret
    match:
      finding_id: 'secrets:SEC001:config.ts:42'
```

### Allowlist Match Criteria

| Field              | Description                                                 |
| ------------------ | ----------------------------------------------------------- |
| `scanner`          | Scanner name: `secrets`, `dependencies`, `iac`, `container` |
| `finding_id`       | Exact finding ID or prefix match with `*`                   |
| `rule_id`          | Rule ID to match (e.g., `SEC001`, `AVD-AWS-0086`)           |
| `path_glob`        | File path glob pattern                                      |
| `message_contains` | Substring match in finding message                          |

Multiple criteria in a single entry are combined with AND logic.

### Expiry Handling

- Expired entries are **ignored** (findings are not suppressed)
- A **warning** is emitted for each expired entry
- Expiry dates use ISO 8601 format (e.g., `2026-03-01`)

---

## SARIF Output

Generate SARIF 2.1.0 output for integration with GitHub Code Scanning:

```yaml
name: Security Gate with SARIF

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Security Gate
        uses: HatakuSec/security-gate-action@v1.0.0
        with:
          sarif_output: results.sarif

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### SARIF Features

- **SARIF 2.1.0** compliant output
- **Deterministic** — no timestamps or random values
- **Secret masking** — snippets never contain raw secrets
- **Fingerprints** — findings tracked across runs via finding ID
- **Invocation status** — scanner errors and allowlist warnings included

---

## Release Process

Security Gate follows a standard GitHub Action release process:

1. Make code changes
2. Run `npm run build` to regenerate `dist/index.js`
3. Commit the updated `dist/` folder
4. Create a version tag (e.g., `v1.0.0`)
5. Push the tag to trigger the release workflow

```bash
npm run build
git add dist/
git commit -m "chore: rebuild dist for release"
git tag v1.0.0
git push origin main --tags
```

The `dist/index.js` file must be committed because GitHub Actions runs the compiled JavaScript directly from the repository.

---

## Contributing

Contributions are welcome! Please ensure:

1. All tests pass: `npm test`
2. Linting passes: `npm run lint`
3. Build is up-to-date: `npm run build`
4. `dist/` changes are committed

---

## Licence

MIT

---

_Security Gate v1.0.0_
