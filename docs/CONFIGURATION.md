# Configuration Reference

This document provides a complete reference for the Security Gate configuration file.

## Overview

Security Gate uses a YAML configuration file for customising scanner behaviour. The file can be named:

- `.security-gate.yml` (recommended)
- `.security-gate.yaml`
- `security-gate.yml`
- `security-gate.yaml`

## IDE Support

For IntelliSense and validation in your editor, add the schema directive at the top of your configuration file:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/HatakuSec/security-gate-action/main/schema/config.schema.json
version: '1'
fail_on: high
```

## Schema

The JSON Schema is generated from the source Zod definitions and is available at:

```
schema/config.schema.json
```

---

## Root Properties

### `version`

| Type   | Default | Required |
|--------|---------|----------|
| string | `"1"`   | No       |

Schema version identifier. Currently only `"1"` is supported.

```yaml
version: '1'
```

### `fail_on`

| Type   | Default | Required | Options                    |
|--------|---------|----------|----------------------------|
| enum   | `high`  | No       | `high`, `medium`, `low`    |

Minimum severity level that causes the action to fail. The action exits with code 1 when findings at or above this severity are detected.

```yaml
fail_on: medium  # Fail on medium or high severity findings
```

### `mode`

| Type   | Default | Required | Options               |
|--------|---------|----------|-----------------------|
| enum   | `auto`  | No       | `auto`, `explicit`    |

Scanner execution mode:

- **`auto`** — Detect and run relevant scanners based on repository content
- **`explicit`** — Only run scanners explicitly enabled in configuration

```yaml
mode: explicit  # Only run scanners explicitly enabled
```

### `exclude_paths`

| Type          | Default | Required | Max Items |
|---------------|---------|----------|-----------|
| array[string] | `[]`    | No       | 100       |

Global path exclusions applied to all scanners. Uses glob patterns.

```yaml
exclude_paths:
  - '**/node_modules/**'
  - '**/vendor/**'
  - '**/dist/**'
  - '**/*.min.js'
```

---

## Scanners Configuration

### `scanners`

Container object for scanner-specific configuration.

```yaml
scanners:
  secrets:
    enabled: true
  dependencies:
    enabled: true
  iac:
    enabled: true
  container:
    enabled: false
```

### `scanners.secrets`

Secrets scanner configuration.

| Property        | Type          | Default | Description                           |
|-----------------|---------------|---------|---------------------------------------|
| `enabled`       | boolean       | `true`  | Enable/disable secrets scanning       |
| `include_paths` | array[string] | `[]`    | Additional file patterns to scan      |
| `exclude_paths` | array[string] | `[]`    | File patterns to exclude from scanning|

```yaml
scanners:
  secrets:
    enabled: true
    include_paths:
      - '**/.env*'
    exclude_paths:
      - '**/test/**'
```

### `scanners.dependencies`

Dependency vulnerability scanner configuration.

| Property      | Type          | Default | Description                      |
|---------------|---------------|---------|----------------------------------|
| `enabled`     | boolean       | `true`  | Enable/disable dependency scanning|
| `ignore_cves` | array[string] | `[]`    | CVE IDs to ignore                |

```yaml
scanners:
  dependencies:
    enabled: true
    ignore_cves:
      - CVE-2021-44228  # Log4Shell - mitigated in our deployment
      - CVE-2022-12345  # Not applicable to our use case
```

### `scanners.iac`

Infrastructure-as-Code scanner configuration.

| Property      | Type          | Default | Description                      |
|---------------|---------------|---------|----------------------------------|
| `enabled`     | boolean       | `true`  | Enable/disable IaC scanning      |
| `skip_checks` | array[string] | `[]`    | Check IDs to skip (Trivy format) |

```yaml
scanners:
  iac:
    enabled: true
    skip_checks:
      - CKV_AWS_1    # S3 versioning not required for logs bucket
      - AVD-AWS-0086 # Public subnets intentional for bastion
```

### `scanners.container`

Container/Dockerfile scanner configuration.

| Property           | Type          | Default | Description                        |
|--------------------|---------------|---------|------------------------------------|
| `enabled`          | boolean       | `true`  | Enable/disable container scanning  |
| `dockerfile_paths` | array[string] | `[]`    | Specific Dockerfiles to scan       |

```yaml
scanners:
  container:
    enabled: true
    dockerfile_paths:
      - docker/Dockerfile.prod
      - docker/Dockerfile.dev
```

---

## Custom Rules

### `rules`

Array of custom secret detection rules. Maximum 50 rules.

```yaml
rules:
  - id: INTERNAL-TOKEN
    name: Internal API Token
    regex: 'INT_TOKEN_[A-Za-z0-9]{16,}'
    severity: high
```

### Rule Properties

| Property      | Type          | Default    | Required | Description                           |
|---------------|---------------|------------|----------|---------------------------------------|
| `id`          | string        | -          | Yes      | Unique rule identifier (3-32 chars, uppercase, numbers, underscores, hyphens) |
| `name`        | string        | -          | Yes      | Human-readable name (max 100 chars)   |
| `regex`       | string        | -          | Yes      | Regular expression pattern (max 500 chars) |
| `severity`    | enum          | `medium`   | No       | `high`, `medium`, or `low`            |
| `type`        | enum          | `secret`   | No       | Rule type (currently only `secret`)   |
| `description` | string        | -          | No       | Detailed description (max 500 chars)  |
| `flags`       | string        | `g`        | No       | Regex flags (allowed: `g`, `i`, `m`, `s`, `u`) |
| `file_globs`  | array[string] | all files  | No       | Glob patterns for files to scan (max 25) |
| `allowlist`   | array[object] | `[]`       | No       | Patterns to exclude from matches (max 50) |

### Rule ID Format

Rule IDs must match the pattern: `^[A-Z0-9_-]{3,32}$`

Valid examples:
- `INTERNAL-TOKEN`
- `MY_CUSTOM_RULE`
- `ORG-SECRET-001`

### Rule Allowlist

Inline allowlist for specific rules:

```yaml
rules:
  - id: INTERNAL-TOKEN
    name: Internal API Token
    regex: 'INT_TOKEN_[A-Za-z0-9]{16,}'
    severity: high
    allowlist:
      - pattern: 'INT_TOKEN_EXAMPLE'
        reason: Documentation example
      - pattern: 'INT_TOKEN_TEST*'
        reason: Test fixtures
```

### Safety Limits

Custom rules are protected against dangerous patterns:

| Limit                 | Value | Description                           |
|-----------------------|-------|---------------------------------------|
| `MAX_RULES`           | 50    | Maximum number of custom rules        |
| `MAX_REGEX_LENGTH`    | 500   | Maximum regex pattern length          |
| `MAX_GLOBS_PER_RULE`  | 25    | Maximum file globs per rule           |
| `MAX_ALLOWLIST_PER_RULE` | 50 | Maximum allowlist entries per rule    |

### ReDoS Protection

Patterns with dangerous characteristics are rejected:

- Nested quantifiers: `(a+)+`, `(.*)*`
- Overlapping alternatives with quantifiers
- Catastrophic backtracking patterns

If a pattern is rejected, the action fails with exit code 2 (configuration error).

---

## Ignore Configuration

### `ignore`

Global ignore configuration for excluding paths from all scanners.

```yaml
ignore:
  paths:
    - '**/*.md'
    - 'docs/**'
    - 'tests/fixtures/**'
```

### `ignore.paths`

| Type          | Default | Max Items | Description                      |
|---------------|---------|-----------|----------------------------------|
| array[string] | `[]`    | 100       | Glob patterns for paths to exclude |

Ignore patterns are applied to all scanners before any other processing.

---

## Allowlist Configuration

### `allowlist`

Array of allowlist entries for suppressing specific findings. Maximum 200 entries.

```yaml
allowlist:
  - id: allow-test-credentials
    reason: Test credentials for CI
    expires: '2026-06-01'
    match:
      path_glob: 'tests/**'
      rule_id: SEC007
```

### Allowlist Entry Properties

| Property  | Type   | Required | Description                                |
|-----------|--------|----------|--------------------------------------------|
| `id`      | string | Yes      | Unique identifier (max 64 chars)           |
| `reason`  | string | Yes      | Explanation for allowlisting (max 500 chars)|
| `expires` | string | No       | ISO 8601 date when entry expires           |
| `match`   | object | No       | Match criteria (at least one required)     |

### Match Criteria

| Property           | Type   | Description                                |
|--------------------|--------|--------------------------------------------|
| `scanner`          | enum   | Scanner name: `secrets`, `dependencies`, `iac`, `container` |
| `finding_id`       | string | Exact finding ID or prefix with `*`        |
| `rule_id`          | string | Rule ID to match                           |
| `path_glob`        | string | File path glob pattern                     |
| `message_contains` | string | Substring match in finding message         |

When multiple criteria are specified, they are combined with AND logic.

### Examples

#### Suppress by Path

```yaml
allowlist:
  - id: allow-test-secrets
    reason: Test fixtures contain fake secrets
    match:
      path_glob: 'tests/fixtures/**'
```

#### Suppress by Rule

```yaml
allowlist:
  - id: allow-legacy-api-keys
    reason: Legacy module uses different auth mechanism
    match:
      rule_id: SEC007
      path_glob: 'src/legacy/**'
```

#### Suppress with Expiry

```yaml
allowlist:
  - id: temp-allow-vuln
    reason: Vulnerability being patched in sprint 12
    expires: '2026-03-15'
    match:
      scanner: dependencies
      finding_id: 'GHSA-*'
```

#### Suppress Specific Finding

```yaml
allowlist:
  - id: false-positive-config
    reason: Not a real secret - configuration constant
    match:
      finding_id: 'secrets:SEC001:config/settings.ts:42'
```

### Expiry Behaviour

- Entries with expired dates are **ignored** (findings are not suppressed)
- A **warning annotation** is emitted for each expired entry
- Expiry dates must be valid ISO 8601 format (e.g., `2026-03-01`)
- Expiry is evaluated at scan time

---

## Complete Example

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/HatakuSec/security-gate-action/main/schema/config.schema.json

version: '1'
fail_on: high
mode: auto

# Global exclusions
exclude_paths:
  - '**/node_modules/**'
  - '**/vendor/**'
  - '**/*.min.js'

# Scanner configuration
scanners:
  secrets:
    enabled: true
    exclude_paths:
      - '**/test/**'
  dependencies:
    enabled: true
    ignore_cves:
      - CVE-2021-44228
  iac:
    enabled: true
    skip_checks:
      - CKV_AWS_1
  container:
    enabled: true

# Custom detection rules
rules:
  - id: INTERNAL-API
    name: Internal API Token
    description: Detects internal API tokens
    regex: 'INT_API_[A-Za-z0-9]{32}'
    severity: high
    file_globs:
      - '**/*.ts'
      - '**/*.js'
    allowlist:
      - pattern: 'INT_API_EXAMPLE*'
        reason: Documentation example

# Path ignore
ignore:
  paths:
    - 'docs/**'
    - '**/*.md'

# Allowlist for known exceptions
allowlist:
  - id: test-fixtures
    reason: Test data contains fake secrets
    match:
      path_glob: 'tests/fixtures/**'

  - id: temp-vuln-patch
    reason: Patching in progress
    expires: '2026-04-01'
    match:
      scanner: dependencies
```

---

## Environment Variables

Security Gate respects standard GitHub Actions environment variables:

| Variable          | Description                           |
|-------------------|---------------------------------------|
| `GITHUB_WORKSPACE`| Repository checkout directory         |
| `GITHUB_EVENT_NAME`| Event that triggered the workflow    |
| `GITHUB_REF`      | Git ref being scanned                 |

---

## Troubleshooting

See [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) for common issues and solutions.
