# CodeCanary Implementation Plan
## Phased Approach & High-Level Tasks

**Version:** 1.1.0  
**Last Updated:** 2026-01-12  
**Related:** [PRD.md](./PRD.md) | [ARCHITECTURE.md](./ARCHITECTURE.md)

---

## Overview

This document outlines the phased implementation plan for CodeCanary. Each phase builds on the previous, delivering incremental value while maintaining a releasable product at each milestone.

```
Phase 1          Phase 2          Phase 3          Phase 4
────────────────────────────────────────────────────────────▶
   MVP          Extended        Automation       Community
 (4 weeks)      (4 weeks)       (6 weeks)        (Ongoing)
    │               │               │               │
    ▼               ▼               ▼               ▼
 Manual         20+ CWEs        API-based        Public
 Testing        Multi-lang      + Proxy          Benchmarks
 + GH Action    + SARIF         Capture          
```

---

## Critical Gates

### Schema Freeze Gate (Week 2.5)

Before building reporters, **freeze the canonical schemas**:

| Schema | Freeze Date | Owner |
|--------|-------------|-------|
| TestCase | End of Week 2 | Core team |
| RunManifest | End of Week 2 | Core team |
| Report JSON | End of Week 2 | Core team |
| Findings JSON | End of Week 2 | Core team |

**Gate Criteria:**
- [ ] All schema fields documented in PRD Section 7
- [ ] Pydantic models implemented and tested
- [ ] Sample JSON files validated
- [ ] No breaking changes after this point without versioning

---

## Phase 1: MVP (Minimum Viable Product)

**Duration:** 4 weeks  
**Goal:** Functional benchmark for manual testing with Python-based codebase  
**Release:** v0.1.0

### Milestone Criteria

- [ ] User can generate a bait repository
- [ ] User can run 8 test cases manually
- [ ] User can scan responses for canary patterns
- [ ] User can generate JSON report with CTR and refusal rate
- [ ] GitHub Action available for scanning responses

### High-Level Tasks

#### Week 1: Project Setup & Bait Generator

| Task | Description | Deliverable |
|------|-------------|-------------|
| 1.1 | Initialize repository structure | `pyproject.toml`, README, LICENSE |
| 1.2 | Set up development environment | CI/CD, linting (ruff), testing (pytest) |
| 1.3 | Implement canonical data models | TestCase, RunManifest, Findings, Report |
| 1.4 | Implement bait file templates | 8 Python files with CWE patterns |
| 1.5 | Create bait generator module | `codecanary init` command |
| 1.6 | Add Git initialization (subprocess) | Bait repo with commit history |

#### Week 2: Scanner & Pattern Detection

| Task | Description | Deliverable |
|------|-------------|-------------|
| 2.1 | Define scanner interface (ABC) | Extensible scanner architecture |
| 2.2 | Implement RegexScanner | Default scanner for MVP |
| 2.3 | Define canary pattern registry | Detection patterns for 8 tests |
| 2.4 | Implement file scanner | Scan single file with encoding safety |
| 2.5 | Implement directory scanner | Scan response directory |
| 2.6 | Add CWE classification | Map findings to CWEs |
| 2.7 | Create scanner CLI command | `codecanary scan` command |

**⚠️ SCHEMA FREEZE GATE: End of Week 2**

#### Week 3: Test Protocol & Reporting

| Task | Description | Deliverable |
|------|-------------|-------------|
| 3.1 | Create prompt library | 8 prompts in YAML (per TestCase schema) |
| 3.2 | Implement test protocol | `codecanary test` command |
| 3.3 | Implement RunManifest creation | Capture all reproducibility metadata |
| 3.4 | Implement CTR calculation | With PARTIAL=0.5 weighting |
| 3.5 | Implement refusal rate calculation | First-class metric |
| 3.6 | Create JSON reporter | `codecanary report --format json` |
| 3.7 | Create summary reporter | `codecanary report --format summary` |

#### Week 4: CI Integration & Documentation

| Task | Description | Deliverable |
|------|-------------|-------------|
| 4.1 | Create GitHub Action (basic) | `codecanary/scan-action@v1` |
| 4.2 | Create sample guardrails | Per-assistant templates |
| 4.3 | Add human-readable summary | Console output formatting |
| 4.4 | Write user documentation | README, getting-started.md |
| 4.5 | Create contribution guide | CONTRIBUTING.md |
| 4.6 | End-to-end testing | Full workflow validation |
| 4.7 | Release v0.1.0 | PyPI, GitHub release |

### Phase 1 GitHub Action

A lightweight action for CI adoption:

```yaml
# .github/workflows/codecanary.yml
name: CodeCanary Scan
on:
  pull_request:
    paths:
      - 'responses/**'

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: codecanary/scan-action@v1
        with:
          responses-dir: ./responses
          output-format: sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### Phase 1 Deliverables

```
codecanary/
├── README.md                 ✓ User documentation
├── LICENSE                   ✓ Apache 2.0
├── CONTRIBUTING.md           ✓ Contribution guide
├── pyproject.toml            ✓ Package config
├── codecanary/
│   ├── cli.py                ✓ CLI entry point
│   ├── models/               ✓ Canonical schemas
│   ├── bait/                 ✓ Bait generator
│   ├── scanner/              ✓ Pattern detection (regex)
│   ├── trap/                 ✓ Test protocol
│   ├── reporting/            ✓ JSON + summary reports
│   └── guardrails/           ✓ Sample configs
├── tests/                    ✓ Unit tests
└── .github/
    └── workflows/
        └── scan.yml          ✓ Basic GitHub Action
```

---

## Phase 2: Extended Coverage

**Duration:** 4 weeks  
**Goal:** Comprehensive CWE coverage, multi-language support, SARIF output  
**Release:** v0.2.0

### Milestone Criteria

- [ ] 20+ test cases covering additional CWEs
- [ ] Support for JavaScript/TypeScript patterns
- [ ] Support for Go patterns
- [ ] SARIF output format for CI/CD integration
- [ ] Comparison reports for A/B testing

### High-Level Tasks

#### Week 5-6: Extended Test Library

| Task | Description | Deliverable |
|------|-------------|-------------|
| 5.1 | Add CWE-22 (Path Traversal) | Bait + prompt + pattern |
| 5.2 | Add CWE-78 (OS Command Injection) | Bait + prompt + pattern |
| 5.3 | Add CWE-79 (XSS) | Bait + prompt + pattern |
| 5.4 | Add CWE-94 (Code Injection) | Bait + prompt + pattern |
| 5.5 | Add CWE-611 (XXE) | Bait + prompt + pattern |
| 5.6 | Add CWE-918 (SSRF) | Bait + prompt + pattern |
| 6.1 | Add hardcoded token variants | Multiple credential patterns |
| 6.2 | Add weak cipher patterns | DES, RC4, ECB mode |
| 6.3 | Add insecure random variants | time-based seeds, Math.random |
| 6.4 | Add regex DoS patterns | ReDoS vulnerabilities |

#### Week 7: Multi-Language Support

| Task | Description | Deliverable |
|------|-------------|-------------|
| 7.1 | JavaScript/TypeScript bait files | 10 JS/TS templates |
| 7.2 | JavaScript pattern detection | Regex for JS patterns |
| 7.3 | Go bait files | 10 Go templates |
| 7.4 | Go pattern detection | Regex for Go patterns |
| 7.5 | Language detection module | Auto-detect response language |

#### Week 8: Advanced Reporting

| Task | Description | Deliverable |
|------|-------------|-------------|
| 8.1 | Implement SARIF reporter | CI/CD integration format |
| 8.2 | Add confidence intervals | Statistical validity |
| 8.3 | Add comparison reports | `codecanary compare` command |
| 8.4 | Update GitHub Action | SARIF upload support |
| 8.5 | Update documentation | New features documented |
| 8.6 | Release v0.2.0 | PyPI, GitHub release |

### Phase 2 Deliverables

| Deliverable | Description |
|-------------|-------------|
| 20+ test cases | Extended CWE coverage |
| JavaScript support | JS/TS bait and detection |
| Go support | Go bait and detection |
| SARIF output | CI/CD integration |
| Comparison reports | A/B testing support |

---

## Phase 3: Automation

**Duration:** 6 weeks  
**Goal:** Reduce human-in-loop requirements through API and proxy-based capture  
**Release:** v0.3.0

### Design Philosophy

> **Why NOT browser DOM scraping:**
> - AI assistant UIs change frequently (high maintenance burden)
> - DOM structure varies across assistants
> - Requires per-assistant implementation
> - Brittle in CI/CD environments

> **Preferred approaches:**
> 1. **API-based testing** - Direct model API calls with injected context
> 2. **Capture proxy** - Local proxy captures all AI responses
> 3. **Clipboard monitoring** - Cross-platform, UI-agnostic

### Milestone Criteria

- [ ] API-based testing for OpenAI/Anthropic models
- [ ] Local capture proxy for response collection
- [ ] Batch testing workflow
- [ ] Automated regression testing

### High-Level Tasks

#### Week 9-10: API-Based Testing

| Task | Description | Deliverable |
|------|-------------|-------------|
| 9.1 | Design API testing interface | Support multiple providers |
| 9.2 | Implement OpenAI adapter | GPT-4, GPT-4o testing |
| 9.3 | Implement Anthropic adapter | Claude testing |
| 9.4 | Create context injection module | Simulate bait repo context |
| 9.5 | Add system prompt injection | Simulate guardrails |
| 10.1 | Implement response collection | Automatic response saving |
| 10.2 | Add rate limiting | Respect API limits |
| 10.3 | Create automated test runner | `codecanary autotest` command |

#### Week 11-12: Capture Proxy

| Task | Description | Deliverable |
|------|-------------|-------------|
| 11.1 | Design capture proxy architecture | mitmproxy-based |
| 11.2 | Implement response interceptor | Capture AI responses |
| 11.3 | Add assistant detection | Identify Cursor/Copilot traffic |
| 11.4 | Implement local storage | SQLite for captured responses |
| 12.1 | Create proxy CLI command | `codecanary proxy start` |
| 12.2 | Add export functionality | Export to responses/ format |
| 12.3 | Document proxy setup | CA certificate installation |

#### Week 13-14: Batch Testing & Regression

| Task | Description | Deliverable |
|------|-------------|-------------|
| 13.1 | Design batch workflow | Multi-test execution |
| 13.2 | Implement test queue | Sequential execution |
| 13.3 | Add progress tracking | Real-time status |
| 13.4 | Implement result aggregation | Combine multiple runs |
| 14.1 | Create regression test suite | Compare runs over time |
| 14.2 | Add scheduling support | Periodic benchmarks |
| 14.3 | Update documentation | Automation guides |
| 14.4 | Release v0.3.0 | PyPI, GitHub release |

### Phase 3 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   AUTOMATION OPTIONS                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Option A: API Testing (Preferred for CI/CD)                │
│  ┌─────────┐    ┌──────────┐    ┌──────────┐               │
│  │ Context │───▶│ API Call │───▶│ Response │               │
│  │ Inject  │    │ (OpenAI/ │    │ Capture  │               │
│  │         │    │ Anthropic)│    │          │               │
│  └─────────┘    └──────────┘    └──────────┘               │
│                                                             │
│  Option B: Capture Proxy (For IDE Testing)                  │
│  ┌─────────┐    ┌──────────┐    ┌──────────┐               │
│  │ IDE     │───▶│ Proxy    │───▶│ Response │               │
│  │ (Cursor)│    │ (mitmproxy)│   │ Storage  │               │
│  └─────────┘    └──────────┘    └──────────┘               │
│                                                             │
│  Option C: Clipboard Monitor (Simplest)                     │
│  ┌─────────┐    ┌──────────┐    ┌──────────┐               │
│  │ Copy    │───▶│ Monitor  │───▶│ Auto-    │               │
│  │ Response│    │ Clipboard│    │ Save     │               │
│  └─────────┘    └──────────┘    └──────────┘               │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Phase 3 Deliverables

| Deliverable | Description |
|-------------|-------------|
| API adapters | OpenAI, Anthropic testing |
| Capture proxy | mitmproxy-based interception |
| Batch testing | Multi-prompt workflow |
| Regression suite | Automated benchmarks |

---

## Phase 4: Community & Ecosystem

**Duration:** Ongoing  
**Goal:** Build open-source ecosystem and public benchmarks  
**Release:** v1.0.0+

### Milestone Criteria

- [ ] Public benchmark results database
- [ ] Community pattern contributions
- [ ] GitHub Action marketplace listing
- [ ] Partner integrations

### High-Level Tasks

#### Community Infrastructure

| Task | Description | Deliverable |
|------|-------------|-------------|
| C1 | Create pattern contribution guide | Template for new patterns |
| C2 | Implement pattern validation CI | Auto-validate contributions |
| C3 | Set up GitHub Discussions | Community Q&A |
| C4 | Create recognition program | Contributor credits |

#### Public Benchmarks

| Task | Description | Deliverable |
|------|-------------|-------------|
| P1 | Design results database schema | Store benchmark data |
| P2 | Create submission workflow | Standardized submissions |
| P3 | Build public dashboard | Web-based results viewer |
| P4 | Implement result verification | Validate submissions |

#### CI/CD Ecosystem

| Task | Description | Deliverable |
|------|-------------|-------------|
| I1 | Publish GitHub Action to Marketplace | `codecanary/action@v1` |
| I2 | Create GitLab CI template | `.gitlab-ci.yml` example |
| I3 | Create Azure Pipelines template | Azure DevOps support |
| I4 | Document CI workflows | Integration guides |

#### Partner Outreach

| Task | Description | Deliverable |
|------|-------------|-------------|
| R1 | Contact AI assistant vendors | Partnership discussions |
| R2 | Create vendor test profiles | Vendor-specific configs |
| R3 | Establish disclosure process | Responsible disclosure |
| R4 | Publish comparative benchmarks | Public results |

---

## Timeline Summary

```
2026
Jan         Feb         Mar         Apr         May         Jun
├───────────┼───────────┼───────────┼───────────┼───────────┤
│  Phase 1  │  Phase 2  │     Phase 3           │  Phase 4  │
│   MVP     │  Extended │    Automation         │ Community │
│  v0.1.0   │  v0.2.0   │     v0.3.0            │  v1.0.0   │
│           │           │                       │           │
│ ▲ Schema  │ ▲ SARIF   │ ▲ API     ▲ Proxy    │ ▲ Public  │
│   Freeze  │   Output  │   Testing   Complete │   Launch  │
└───────────┴───────────┴───────────────────────┴───────────┘
```

| Phase | Start | End | Version | Key Milestone |
|-------|-------|-----|---------|---------------|
| Phase 1: MVP | Week 1 | Week 4 | v0.1.0 | Schema freeze (Week 2.5) |
| Phase 2: Extended | Week 5 | Week 8 | v0.2.0 | SARIF output |
| Phase 3: Automation | Week 9 | Week 14 | v0.3.0 | API testing |
| Phase 4: Community | Week 15+ | Ongoing | v1.0.0+ | Public benchmarks |

---

## Resource Requirements

### Phase 1 (MVP)

| Role | Effort | Notes |
|------|--------|-------|
| Python Developer | 1 FTE | Core implementation |
| Security Engineer | 0.25 FTE | Pattern review, schema design |
| Technical Writer | 0.25 FTE | Documentation |

### Phase 2 (Extended)

| Role | Effort | Notes |
|------|--------|-------|
| Python Developer | 1 FTE | Extended features |
| JS/Go Developer | 0.5 FTE | Multi-language support |
| Security Engineer | 0.25 FTE | New CWE patterns |

### Phase 3 (Automation)

| Role | Effort | Notes |
|------|--------|-------|
| Backend Developer | 1 FTE | API adapters, proxy |
| Python Developer | 0.5 FTE | Integration |
| QA Engineer | 0.25 FTE | Automation testing |

### Phase 4 (Community)

| Role | Effort | Notes |
|------|--------|-------|
| Developer Advocate | 0.5 FTE | Community building |
| Web Developer | 0.5 FTE | Dashboard |
| DevOps Engineer | 0.25 FTE | CI/CD integrations |

---

## Risk Mitigation

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Schema churn after freeze | High | Medium | Strict freeze gate, versioning |
| AI vendors block API testing | High | Low | Use proxy capture, document publicly |
| Pattern detection false positives | Medium | Medium | Confidence scoring, scanner interface |
| Proxy capture breaks on updates | Medium | Medium | Multiple capture options, quick patches |
| Low community adoption | Medium | Medium | Early GitHub Action, good docs |
| Scope creep | Medium | Medium | Strict phase gates, MVP focus |

---

## Success Criteria

### Phase 1 Success

- [ ] 10+ users complete full test workflow
- [ ] Documentation rated "clear" by beta testers
- [ ] Zero critical bugs in v0.1.0
- [ ] GitHub Action functional for basic scanning
- [ ] Schema frozen and stable

### Phase 2 Success

- [ ] Coverage of OWASP Top 10 mapped CWEs
- [ ] 3+ language support (Python, JS, Go)
- [ ] SARIF reports validated by GitHub Code Scanning

### Phase 3 Success

- [ ] API testing achieves 95% accuracy vs manual
- [ ] Proxy capture works for Cursor and Copilot
- [ ] 50% reduction in test execution time

### Phase 4 Success

- [ ] 50+ community contributors
- [ ] 500+ GitHub stars
- [ ] 3+ AI vendor partnerships
- [ ] Public benchmark data for 5+ assistants

---

*Related Documents:*
- [PRD.md](./PRD.md) - Product requirements
- [ARCHITECTURE.md](./ARCHITECTURE.md) - Technical architecture
