# Contributing to CodeCanary

Thank you for your interest in contributing to CodeCanary! This document provides guidelines and instructions for contributing.

## Code of Conduct

Please be respectful and constructive in all interactions. We're building security tools together.

## Ways to Contribute

### 1. Report Bugs

Open an issue with:
- Clear title and description
- Steps to reproduce
- Expected vs actual behavior
- Environment details (OS, Python version, AI assistant)

### 2. Suggest Features

Open an issue with:
- Use case description
- Proposed solution
- Any alternatives considered

### 3. Add Test Patterns

See [docs/contributing-patterns.md](docs/contributing-patterns.md) for detailed instructions.

New patterns require:
- Complete TestCase definition (per PRD Section 7)
- CWE reference
- Bait files with canary tokens
- Detection regex patterns
- Expected secure behavior

### 4. Improve Documentation

- Fix typos or unclear explanations
- Add examples
- Improve getting started guide

### 5. Submit Code

See development setup below.

## Development Setup

```bash
# Clone the repository
git clone https://github.com/medxops/code-canary.git
cd code-canary

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows

# Install in development mode
pip install -e ".[dev]"

# Verify installation
codecanary --version
```

## Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=codecanary --cov-report=html

# Run specific test file
pytest tests/test_scanner.py
```

## Code Style

We use [ruff](https://github.com/astral-sh/ruff) for linting and formatting:

```bash
# Check for issues
ruff check .

# Fix auto-fixable issues
ruff check --fix .

# Format code
ruff format .
```

## Type Checking

We use mypy for static type checking:

```bash
mypy codecanary/
```

## Pull Request Process

1. **Fork** the repository
2. **Create a branch** from `main`: `git checkout -b feature/my-feature`
3. **Make changes** and add tests
4. **Run tests and linting**: `pytest && ruff check .`
5. **Commit** with clear message: `git commit -m "Add: new CWE-XXX pattern"`
6. **Push** to your fork: `git push origin feature/my-feature`
7. **Open PR** against `main`

### PR Requirements

- [ ] Tests pass
- [ ] Linting passes
- [ ] Type checking passes
- [ ] Documentation updated (if applicable)
- [ ] CHANGELOG.md updated (for features/fixes)

## Commit Messages

Use clear, descriptive commit messages:

```
Add: CWE-22 path traversal pattern
Fix: CTR calculation with zero refused tests
Update: README quick start section
Remove: deprecated API endpoint
```

## Security Patterns

When contributing security patterns:

1. **Use the issue template** for "New Pattern"
2. **Include complete TestCase** per schema in PRD.md
3. **Test detection regex** against known-vulnerable code
4. **Verify regex doesn't match** secure implementations
5. **Document CWE reference** and OWASP mapping

## Questions?

- Open a [Discussion](https://github.com/medxops/code-canary/discussions)
- Check existing [Issues](https://github.com/medxops/code-canary/issues)

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
