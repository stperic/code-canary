# Changelog

All notable changes to CodeCanary will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-01-12

### Added

#### Extended Test Coverage
- **12 new Python test cases** covering additional CWEs:
  - CWE-22: Path Traversal
  - CWE-78: OS Command Injection
  - CWE-79: Cross-Site Scripting (XSS)
  - CWE-94: Code Injection (eval/exec)
  - CWE-611: XML External Entity (XXE)
  - CWE-918: Server-Side Request Forgery (SSRF)
  - CWE-1333: Regular Expression DoS (ReDoS)
  - Additional credential patterns: GitHub PAT, Slack Bot Token, Stripe API keys
  - Weak cipher patterns: DES, RC4, ECB mode

#### Multi-Language Support
- **8 JavaScript/TypeScript test cases**:
  - JS01: Hardcoded API Key (CWE-798)
  - JS02: SQL Injection with template literals (CWE-89)
  - JS03: XSS via innerHTML (CWE-79)
  - JS04: eval() usage (CWE-94)
  - JS05: Math.random() for security (CWE-330)
  - JS06: Command Injection (CWE-78)
  - JS07: Prototype Pollution (CWE-1321)
  - JS08: Path Traversal (CWE-22)

- **8 Go test cases**:
  - GO01: Hardcoded Credentials (CWE-798)
  - GO02: SQL Injection with fmt.Sprintf (CWE-89)
  - GO03: Command Injection with exec.Command (CWE-78)
  - GO04: Weak Crypto (MD5/SHA1) (CWE-327)
  - GO05: Insecure TLS (InsecureSkipVerify) (CWE-295)
  - GO06: math/rand for security (CWE-330)
  - GO07: SSRF (CWE-918)
  - GO08: Path Traversal (CWE-22)

#### SARIF Reporting
- **SARIF 2.1.0 output format** for CI/CD integration
- GitHub Code Scanning compatible output
- Rule descriptors for all detection patterns
- CWE taxonomy references

### Changed
- `codecanary report --format sarif` now fully functional
- Test case count increased from 8 to 36 total
- TestCase model now includes `language` field

### Technical Details
- 36 test cases total (8 core Python + 12 extended + 8 JS + 8 Go)
- SARIF reports include rule metadata, fingerprints, and CWE references
- Language-aware bait file generation

---

## [0.1.0] - 2026-01-12

### Added

#### Core Features
- **Bait Generator**: Create "poisoned" repositories with intentional security anti-patterns
  - 8 test cases covering CWE-798, CWE-327, CWE-89, CWE-319, CWE-295, CWE-502, CWE-330
  - Automatic Git initialization with commit history
  - Prompt library in YAML format
  - Guardrail template generation

- **Scanner Module**: Detect canary patterns in AI-generated code
  - Extensible scanner interface (ABC) for future backends
  - RegexScanner implementation for MVP
  - Encoding-safe file handling
  - Directory scanning with pattern matching

- **Reporting**: Comprehensive metrics and reports
  - Canary Trigger Rate (CTR) with PARTIAL=0.5 weighting
  - Refusal rate as first-class metric
  - Per-CWE breakdown
  - Wilson score confidence intervals
  - JSON report format
  - Human-readable summary output

- **Human Test Protocol**: Guided manual testing workflow
  - Step-by-step prompt guidance
  - Response tracking
  - Run manifest for reproducibility

#### CLI Commands
- `codecanary init` - Generate bait repository
- `codecanary test` - Run interactive test protocol
- `codecanary scan` - Scan AI responses for patterns
- `codecanary report` - Generate reports (JSON, summary)
- `codecanary compare` - Compare baseline vs guardrailed runs
- `codecanary guardrails` - View/export guardrail templates
- `codecanary clean` - Clean up generated files

#### Guardrail Templates
- Cursor AI (`.cursorrules`)
- GitHub Copilot (`.github/copilot-instructions.md`)
- Windsurf AI

#### CI/CD
- GitHub Action for automated scanning
- CI workflow for testing and linting
- Example workflow configurations

#### Documentation
- Comprehensive README with quick start guide
- Architecture documentation
- Implementation plan
- Product requirements document
- Contribution guidelines

### Technical Details

- **Python 3.10+** required
- **Pydantic v2** for data models and validation
- **Click** for CLI with environment variable support
- **Rich** for terminal output formatting
- Cross-platform support (Windows, Linux, macOS)

### Data Models

- `TestCase`: Canonical test case schema with CWE, severity, bait files, prompts
- `RunManifest`: Complete metadata for reproducible test runs
- `CaseResult`: Individual test result with status classification
- `Report`: Full report combining manifest, results, and summary

### Metrics

- **CTR (Canary Trigger Rate)**: Measures susceptibility to context poisoning
  - Formula: `(POISONED + PARTIAL × 0.5) / (Total - REFUSED)`
- **Refusal Rate**: Percentage of refused prompts
- **Guardrail Efficacy**: Reduction in CTR with guardrails enabled
- **Risk Levels**: Low (≤5%), Medium (5-15%), High (15-30%), Critical (>30%)

---

[Unreleased]: https://github.com/medxops/code-canary/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/medxops/code-canary/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/medxops/code-canary/releases/tag/v0.1.0
