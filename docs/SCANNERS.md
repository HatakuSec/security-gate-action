# Scanner Reference

This document provides detailed information about each scanner included in Security Gate.

---

## Scanner Overview

| Scanner        | Description                           | Auto-Detection                     |
|----------------|---------------------------------------|------------------------------------|
| **Secrets**    | Detect leaked credentials and tokens  | Always enabled                     |
| **Dependencies**| Find known vulnerabilities (CVEs)    | Lockfiles present                  |
| **IaC**        | Infrastructure-as-Code misconfigs     | Terraform/Kubernetes files present |
| **Container**  | Dockerfile best practices             | Dockerfile/compose.yml present     |

---

## Secrets Scanner

### Overview

The secrets scanner detects leaked credentials, API keys, tokens, and other sensitive data using high-signal regular expression patterns.

### Detection Strategy

Security Gate uses precision over recall — patterns are designed to minimise false positives while catching common secret formats.

### Built-in Rules

| Rule ID | Name                        | Severity | Pattern Description                          |
|---------|-----------------------------| ---------|----------------------------------------------|
| SEC001  | AWS Access Key ID           | high     | `AKIA[0-9A-Z]{16}`                          |
| SEC002  | AWS Secret Access Key       | high     | 40-char base64 following specific keywords   |
| SEC003  | GitHub Personal Access Token| high     | `ghp_[A-Za-z0-9]{36,}`                      |
| SEC004  | GitHub OAuth Token          | high     | `gho_[A-Za-z0-9]{36,}`                      |
| SEC005  | GitHub PAT (fine-grained)   | high     | `github_pat_[A-Za-z0-9_]{36,}`              |
| SEC006  | Private Key                 | high     | `-----BEGIN (RSA\|EC\|OPENSSH) PRIVATE KEY-----` |
| SEC007  | Generic API Key             | medium   | `api[_-]?key.*[=:]['"][A-Za-z0-9...]{16,}`  |
| SEC008  | Generic Secret/Password     | medium   | `(password\|secret\|token).*[=:]['"][^'"]{8,}` |
| SEC009  | Slack Token                 | high     | `xox[baprs]-[A-Za-z0-9-]{24,}`              |
| SEC010  | Stripe Live Key             | high     | `sk_live_[A-Za-z0-9]{24,}`                  |

### File Handling

- **Scanned**: All text files under 1MB
- **Skipped**: Binary files, node_modules, .git, vendor directories
- **Encoding**: UTF-8 assumed; non-UTF8 files are skipped with a warning

### Configuration

```yaml
scanners:
  secrets:
    enabled: true
    include_paths:
      - '**/.env*'  # Include dotenv files
    exclude_paths:
      - '**/test/**'  # Exclude test directories
```

### Custom Rules

Extend detection with organisation-specific patterns:

```yaml
rules:
  - id: ORG-API-KEY
    name: Organisation API Key
    regex: 'ORG_[A-Z]{3}_[A-Za-z0-9]{32}'
    severity: high
    description: Internal API keys with ORG_ prefix
```

See [CONFIGURATION.md](./CONFIGURATION.md#custom-rules) for full custom rule documentation.

### Secret Masking

All detected secrets are:

1. **Registered** with GitHub Actions `core.setSecret()` to prevent logging
2. **Masked** in output showing only first 4 and last 2 characters
3. **Sanitised** in SARIF output to prevent exposure

Example masked output:
```
AKIA************LE
ghp_a***********************************Xy
```

---

## Dependencies Scanner

### Overview

The dependencies scanner identifies known vulnerabilities in project dependencies by querying the [OSV (Open Source Vulnerabilities)](https://osv.dev/) API.

### Supported Package Managers

| Lockfile              | Ecosystem | Parser                    |
|-----------------------|-----------|---------------------------|
| `package-lock.json`   | npm       | JSON parse of dependencies|
| `yarn.lock`           | npm       | Custom yarn.lock parser   |
| `requirements.txt`    | PyPI      | PEP 440 compliant parser  |
| `requirements-*.txt`  | PyPI      | PEP 440 compliant parser  |
| `Pipfile.lock`        | PyPI      | JSON parse                |

### Auto-Detection

The scanner runs automatically if any supported lockfile is found in the repository or specified working directory.

### Vulnerability Sources

OSV aggregates vulnerabilities from:

- GitHub Security Advisories (GHSA)
- National Vulnerability Database (NVD)
- Python Packaging Advisory Database (PyPA)
- RubyGems Advisory Database
- And many more

### Severity Mapping

CVSS scores are mapped to Security Gate severity levels:

| CVSS Range | Severity |
|------------|----------|
| 9.0 - 10.0 | high     |
| 7.0 - 8.9  | medium   |
| 0.0 - 6.9  | low      |

When no CVSS score is available, the vulnerability is assigned `medium` severity.

### Configuration

```yaml
scanners:
  dependencies:
    enabled: true
    ignore_cves:
      - CVE-2021-44228  # Log4Shell - mitigated
      - GHSA-xxxx-yyyy  # Known false positive
```

### Rate Limiting

The OSV API has a generous rate limit. Security Gate batches queries (up to 1000 packages per request) to minimise API calls.

### Example Finding

```
📦 lodash@4.17.20
   └─ GHSA-jf85-cpcp-j695 (high)
   └─ Prototype pollution via merge
   └─ Fixed in: 4.17.21
```

---

## IaC Scanner

### Overview

The Infrastructure-as-Code (IaC) scanner detects misconfigurations in infrastructure definitions using [Trivy](https://trivy.dev/).

### Supported Formats

| Format              | File Patterns                          |
|---------------------|----------------------------------------|
| Terraform           | `*.tf`, `*.tfvars`                    |
| Kubernetes          | `*.yaml`, `*.yml` (with apiVersion)   |
| CloudFormation      | `*.yaml`, `*.yml`, `*.json`           |
| Helm Charts         | `Chart.yaml` + templates              |
| Azure Resource Mgr  | ARM templates (JSON)                  |

### Auto-Detection

The scanner runs automatically if:

- Any `*.tf` files exist
- Any YAML files contain Kubernetes `apiVersion` and `kind` fields
- CloudFormation `AWSTemplateFormatVersion` is detected

### Trivy Integration

Security Gate automatically downloads and manages Trivy:

- **Version**: v0.58.0 (pinned for reproducibility)
- **Platforms**: Linux and macOS (amd64, arm64)
- **Cache**: Downloaded to a temp directory per run
- **Security**: No `curl | sh` patterns used

### Severity Mapping

Trivy severity levels map directly:

| Trivy Severity | Security Gate Severity |
|----------------|------------------------|
| CRITICAL       | high                   |
| HIGH           | high                   |
| MEDIUM         | medium                 |
| LOW            | low                    |

### Configuration

```yaml
scanners:
  iac:
    enabled: true
    skip_checks:
      - CKV_AWS_1     # S3 versioning
      - AVD-AWS-0086  # Public subnet
      - AVD-K8S-0001  # Pod security
```

### Example Finding

```
🏗️ terraform/main.tf:15
   └─ AVD-AWS-0086 (medium)
   └─ S3 bucket does not have logging enabled
   └─ Rule: aws-s3-enable-bucket-logging
```

### Check ID Formats

Different check ID formats are supported:

- **Trivy AVD**: `AVD-AWS-0086`
- **Checkov**: `CKV_AWS_1`
- **tfsec**: `aws-s3-enable-bucket-logging`

---

## Container Scanner

### Overview

The container scanner validates Dockerfiles against security best practices and optionally runs Trivy for deeper analysis.

### Dockerfile Rules

| Rule ID | Name                    | Severity | Description                          |
|---------|-------------------------|----------|--------------------------------------|
| DOCK001 | Latest Tag              | medium   | Using `:latest` tag for base image   |
| DOCK002 | No USER Instruction     | medium   | Container runs as root by default    |
| DOCK003 | No HEALTHCHECK          | low      | Missing health check for orchestrators|
| DOCK004 | Sudo Usage              | high     | `sudo` in RUN commands               |
| DOCK005 | ADD vs COPY             | medium   | `ADD` used for local files           |
| DOCK006 | Missing .dockerignore   | low      | No .dockerignore file present        |
| DOCK007 | Secrets in ARG          | medium   | Sensitive values in build arguments  |
| DOCK008 | Curl Pipe Shell         | high     | `curl ... | sh` pattern detected     |

### Auto-Detection

The scanner runs automatically if:

- `Dockerfile` exists in root or common locations
- `docker-compose.yml` or `docker-compose.yaml` exists
- Any file matching `Dockerfile*` pattern exists

### Detection Logic

#### DOCK001 - Latest Tag

```dockerfile
# BAD: Using latest tag
FROM node:latest

# GOOD: Pin specific version
FROM node:20.10.0-alpine
```

#### DOCK002 - No USER

```dockerfile
# BAD: No USER instruction
FROM node:20-alpine
RUN npm install
CMD ["node", "app.js"]

# GOOD: Non-root user
FROM node:20-alpine
RUN adduser -D appuser
USER appuser
RUN npm install
CMD ["node", "app.js"]
```

#### DOCK004 - Sudo Usage

```dockerfile
# BAD: Using sudo
RUN sudo apt-get update

# GOOD: Run as root temporarily
USER root
RUN apt-get update
USER appuser
```

#### DOCK008 - Curl Pipe Shell

```dockerfile
# BAD: Insecure installation
RUN curl -s https://example.com/install.sh | bash

# GOOD: Verify before executing
RUN curl -O https://example.com/install.sh && \
    sha256sum -c checksums.txt && \
    bash install.sh
```

### Configuration

```yaml
scanners:
  container:
    enabled: true
    dockerfile_paths:
      - docker/Dockerfile.prod
      - docker/Dockerfile.dev
```

### Example Finding

```
🐳 Dockerfile:1
   └─ DOCK001 (medium)
   └─ Base image uses :latest tag
   └─ Pin image to specific version for reproducible builds
```

---

## Scanner Execution Order

Scanners run in parallel for performance, with results aggregated at the end:

1. All scanners start simultaneously
2. Each scanner produces findings independently
3. Findings are sorted by severity, then by file path
4. Policy evaluation determines pass/fail

### Error Handling

- **Scanner failure**: Other scanners continue; error is logged
- **Partial results**: Available findings are still reported
- **Exit codes**: See README for exit code reference

---

## Adding Scanner Support

Security Gate's modular architecture allows adding new scanners. Each scanner implements the `Scanner` interface:

```typescript
interface Scanner {
  name: string;
  run(context: ScanContext): Promise<ScanResult>;
}

interface ScanResult {
  findings: Finding[];
  errors?: ScanError[];
}
```

See the source code in `src/scanners/` for implementation examples.
