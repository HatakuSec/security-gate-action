# Changelog

All notable changes to Security Gate Action are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-01-03

### Added

**Core Features:**

- Multi-scanner orchestration (gitleaks, trivy, semgrep, osv-scanner, actionlint, kubesec, checkov)
- Flexible configuration via `.security-gate.yml` with JSON Schema validation
- Severity-based failure thresholds (high/medium/low)
- Auto-detection mode for scanner selection based on repository content
- SARIF 2.1.0 output for GitHub Code Scanning integration

**Advanced Features:**

- Custom regex-based rules with ReDoS protection (max 50 rules per config)
- Allowlist system with expiry dates and audit trails
- Global ignore paths with glob pattern support
- Secret masking in all outputs and logs

**Scanners:**

- **Secrets Scanner**: 10 built-in patterns (AWS, GitHub, Slack, Stripe, etc.)
- **Dependencies Scanner**: OSV API integration for npm, yarn, pip, pipfile
- **IaC Scanner**: Terraform and Kubernetes misconfigurations via Trivy
- **Container Scanner**: Dockerfile best practices + optional vulnerability scanning

**Documentation:**

- Complete configuration reference (docs/CONFIGURATION.md)
- Scanner documentation with rule details (docs/SCANNERS.md)
- Troubleshooting guide (docs/TROUBLESHOOTING.md)
- JSON Schema for IDE autocompletion (schema/config.schema.json)

**Testing & Quality:**

- 550 comprehensive tests with 100% pass rate
- TypeScript codebase with strict type checking
- ESLint + Prettier code standards
- Automated CI/CD pipeline

### Technical Details

- **Node.js**: 20.x LTS
- **TypeScript**: 5.x with strict configuration
- **Dependencies**: Minimal external dependencies, security-focused
- **Build**: Single-file distribution (dist/index.js) for GitHub Actions
- **Platforms**: Linux and macOS support (amd64 and arm64)

---

## License

MIT License - see [LICENSE](LICENSE) for details.
