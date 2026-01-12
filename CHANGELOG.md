# Changelog

All notable changes to CodeCanary will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/medxops/code-canary/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/medxops/code-canary/releases/tag/v0.1.0
