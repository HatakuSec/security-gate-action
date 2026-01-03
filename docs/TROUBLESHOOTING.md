# Troubleshooting Guide

This document covers common issues and their solutions when using Security Gate.

---

## Quick Diagnostics

### Enable Verbose Logging

Add `verbose: true` to your workflow to get detailed debug output:

```yaml
- uses: HatakuSec/security-gate-action@v1.0.0
  with:
    verbose: true
```

### Check Exit Codes

| Code | Meaning                          | Action                                |
|------|----------------------------------|---------------------------------------|
| 0    | Passed                           | No action needed                      |
| 1    | Policy violation                 | Review findings, fix or allowlist     |
| 2    | Configuration error              | Check config file syntax              |
| 3    | Scanner execution error          | Check scanner-specific troubleshooting|

---

## Configuration Issues

### "Configuration validation failed"

**Symptoms:**
- Exit code 2
- Error message about invalid configuration

**Common causes and solutions:**

#### Invalid YAML Syntax

```yaml
# BAD: Missing quotes around version
version: 1

# GOOD: Version as string
version: '1'
```

#### Invalid Rule ID Format

```yaml
# BAD: Lowercase and special characters
rules:
  - id: my-rule!

# GOOD: Uppercase, numbers, underscores, hyphens
rules:
  - id: MY-RULE-001
```

Rule IDs must match pattern: `^[A-Z0-9_-]{3,32}$`

#### Invalid Severity Value

```yaml
# BAD: Invalid severity
fail_on: critical

# GOOD: Valid severities
fail_on: high  # or: medium, low
```

#### Missing Required Fields in Rules

```yaml
# BAD: Missing required fields
rules:
  - id: MY-RULE
    regex: 'pattern'
    # Missing 'name' field!

# GOOD: All required fields present
rules:
  - id: MY-RULE
    name: My Custom Rule
    regex: 'pattern'
```

### "ReDoS pattern rejected"

**Symptoms:**
- Exit code 2
- Error about dangerous regex pattern

**Cause:** The custom rule regex contains patterns that could cause catastrophic backtracking.

**Solution:** Simplify your regex to avoid:

```yaml
# BAD: Nested quantifiers
regex: '(a+)+'

# BAD: Overlapping alternatives
regex: '.*.*'

# GOOD: Specific patterns
regex: '[A-Z]{3}_[A-Za-z0-9]{32}'
```

### Config File Not Found

**Symptoms:**
- Action uses defaults instead of your config

**Solution:** Check file name and location:

```bash
# Supported names (in order of precedence):
.security-gate.yml
.security-gate.yaml
security-gate.yml
security-gate.yaml
```

Or specify explicitly:

```yaml
- uses: HatakuSec/security-gate-action@v1.0.0
  with:
    config_path: path/to/my-config.yml
```

---

## Scanner Issues

### Secrets Scanner

#### False Positives in Test Files

**Solution:** Use path-based allowlist:

```yaml
allowlist:
  - id: test-secrets
    reason: Test fixtures contain fake credentials
    match:
      path_glob: 'tests/**'
```

Or exclude test directories:

```yaml
scanners:
  secrets:
    exclude_paths:
      - '**/test/**'
      - '**/tests/**'
      - '**/__tests__/**'
```

#### Missing Detection for Custom Token Format

**Solution:** Add a custom rule:

```yaml
rules:
  - id: CUSTOM-TOKEN
    name: Internal Token
    regex: 'INT_[A-Z]{4}_[A-Za-z0-9]{24}'
    severity: high
```

#### Too Many Findings

**Solution:** Check for common issues:

1. Are you scanning build output? Add to exclude_paths
2. Are you scanning vendored code? Add vendor paths to exclusions
3. Are patterns too broad? Use custom rules with tighter patterns

### Dependencies Scanner

#### "No lockfiles found"

**Symptoms:**
- Scanner reports no lockfiles found
- Dependencies not being scanned

**Solution:** Ensure lockfiles are committed:

```bash
# npm
git add package-lock.json

# yarn
git add yarn.lock

# Python
git add requirements.txt
# or
git add Pipfile.lock
```

#### False Positive CVE

**Solution:** Ignore specific CVEs:

```yaml
scanners:
  dependencies:
    ignore_cves:
      - CVE-2021-44228  # Mitigated in our deployment
      - GHSA-xxxx-yyyy  # Not applicable
```

#### OSV API Timeout

**Symptoms:**
- Scanner times out
- Network error messages

**Possible causes:**
- Very large number of dependencies
- Network restrictions in your environment
- OSV API temporary issues

**Solution:** The scanner has built-in retry logic. If persistent, check:
1. GitHub Actions runner network access
2. Consider splitting into smaller scans for monorepos

### IaC Scanner

#### Trivy Download Failed

**Symptoms:**
- Error downloading Trivy
- Network timeout during scanner setup

**Solutions:**

1. **Check network access**: Ensure runner can access GitHub releases
2. **Pre-install Trivy**: Add Trivy to your runner:

```yaml
- name: Install Trivy
  run: |
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.58.0

- uses: HatakuSec/security-gate-action@v1.0.0
```

#### "No IaC files detected"

**Symptoms:**
- IaC scanner skipped
- Terraform files not found

**Check:**
1. Files have `.tf` extension
2. Kubernetes files have correct structure:
   ```yaml
   apiVersion: v1
   kind: Deployment
   ```
3. Files are not in excluded paths

#### Skip Specific Checks

**Solution:** Use skip_checks:

```yaml
scanners:
  iac:
    skip_checks:
      - AVD-AWS-0086  # Public subnets intentional
      - CKV_AWS_1     # S3 versioning not required
```

### Container Scanner

#### "Dockerfile not found"

**Symptoms:**
- Container scanner skipped
- Dockerfile exists but not detected

**Solution:** Check Dockerfile location and name:

```yaml
scanners:
  container:
    dockerfile_paths:
      - Dockerfile              # Root
      - docker/Dockerfile       # Subdirectory
      - Dockerfile.prod         # Custom name
```

#### False Positive for DOCK002 (No USER)

**Cause:** Multi-stage build where USER is set in a different stage.

**Solution:** Allowlist the specific finding:

```yaml
allowlist:
  - id: docker-user-stage
    reason: USER set in final stage, not builder
    match:
      rule_id: DOCK002
      path_glob: '**/Dockerfile.builder'
```

---

## Allowlist Issues

### Allowlist Entry Not Working

**Checklist:**

1. **Entry not expired:**
   ```yaml
   expires: '2026-12-31'  # Future date
   ```

2. **Match criteria correct:**
   ```yaml
   match:
     path_glob: 'tests/**'  # Glob pattern, not regex
     rule_id: SEC007        # Exact rule ID
   ```

3. **Multiple criteria are AND:**
   ```yaml
   # Both conditions must match
   match:
     scanner: secrets
     path_glob: 'tests/**'
   ```

### Expired Allowlist Warning

**Symptoms:**
- Warning about expired allowlist entry
- Finding not suppressed

**Solution:** Update or remove the expired entry:

```yaml
# Update expiry date
allowlist:
  - id: temp-allow
    reason: Extended for Q2
    expires: '2026-06-30'  # Updated from past date
```

### Finding ID Format

**Correct format:** `{scanner}:{rule_id}:{file}:{line}`

Example:
```yaml
allowlist:
  - id: specific-finding
    reason: False positive verified
    match:
      finding_id: 'secrets:SEC001:config/settings.ts:42'
```

---

## SARIF Issues

### SARIF File Empty or Invalid

**Symptoms:**
- SARIF upload fails
- Empty sarif_path output

**Solutions:**

1. Check sarif_output path is valid:
   ```yaml
   with:
     sarif_output: results.sarif  # Relative to workspace
   ```

2. Ensure action completes (even with findings):
   ```yaml
   - uses: HatakuSec/security-gate-action@v1.0.0
     continue-on-error: true  # Allow SARIF upload even on failure
     with:
       sarif_output: results.sarif
   ```

### SARIF Upload Fails

**Common issues:**

1. **Permissions:** Ensure workflow has `security-events: write`
   ```yaml
   permissions:
     security-events: write
   ```

2. **Path mismatch:**
   ```yaml
   - uses: github/codeql-action/upload-sarif@v3
     with:
       sarif_file: results.sarif  # Must match sarif_output
   ```

---

## Performance Issues

### Slow Scans

**Solutions:**

1. **Exclude irrelevant paths:**
   ```yaml
   exclude_paths:
     - '**/node_modules/**'
     - '**/vendor/**'
     - '**/dist/**'
     - '**/*.min.js'
   ```

2. **Disable unused scanners:**
   ```yaml
   mode: explicit
   scanners:
     secrets:
       enabled: true
     dependencies:
       enabled: false  # Skip if not needed
     iac:
       enabled: false
     container:
       enabled: false
   ```

3. **Use working_directory for monorepos:**
   ```yaml
   with:
     working_directory: packages/backend
   ```

### High Memory Usage

**Solutions:**

1. **Reduce file scanning scope:**
   ```yaml
   exclude_paths:
     - '**/*.log'
     - '**/coverage/**'
     - '**/.git/**'
   ```

2. **Split scans across jobs:**
   ```yaml
   jobs:
     secrets:
       runs-on: ubuntu-latest
       steps:
         - uses: HatakuSec/security-gate-action@v1.0.0
           with:
             mode: explicit
     
     # ... separate job for dependencies
   ```

---

## Common Error Messages

### "Maximum annotation limit reached"

**Meaning:** More than 50 findings; only first 50 have annotations.

**Solution:** All findings are in the job summary. Fix highest severity first.

### "Scanner returned errors"

**Meaning:** A scanner encountered issues but partial results may be available.

**Solution:** Check the specific scanner section for details:
- IaC: Trivy download/execution issues
- Dependencies: OSV API issues
- Container: Dockerfile parsing issues

### "No scanners were enabled"

**Meaning:** In explicit mode, no scanners are configured.

**Solution:** Enable scanners in config:
```yaml
mode: explicit
scanners:
  secrets:
    enabled: true
```

---

## Getting Help

1. **Check the logs:** Enable verbose mode for detailed output
2. **Review configuration:** Use JSON Schema for validation
3. **Search issues:** Check [GitHub Issues](https://github.com/HatakuSec/security-gate-action/issues)
4. **Open an issue:** Include:
   - Security Gate version
   - Workflow configuration (sanitised)
   - Error messages
   - Verbose log output

---

## Quick Reference

### Minimum Working Configuration

```yaml
# .security-gate.yml
version: '1'
```

### Silence All Findings (Not Recommended)

```yaml
# For testing only - do not use in production
fail_on: high
exclude_paths:
  - '**/*'
```

### Debug Mode Workflow

```yaml
name: Security Gate Debug

on: workflow_dispatch

jobs:
  debug:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Security Gate (Debug)
        uses: HatakuSec/security-gate-action@v1.0.0
        continue-on-error: true
        with:
          verbose: true
          sarif_output: debug.sarif
      
      - name: Upload Debug Artifacts
        uses: actions/upload-artifact@v4
        with:
          name: security-gate-debug
          path: |
            debug.sarif
            .security-gate.yml
```
