"""Scanner module for detecting canary patterns in AI responses.

Provides multiple scanner implementations:
- RegexScanner: Fast pattern matching (default)
- ASTScanner: Python-specific semantic analysis
- SemgrepScanner: Production-grade static analysis
- CombinedScanner: Uses multiple scanners together
- MultiScanner: Configurable multi-scanner
"""

from codecanary.scanner.interface import ScannerInterface
from codecanary.scanner.regex_scanner import RegexScanner
from codecanary.scanner.analyzer import Analyzer, get_scanner
from codecanary.scanner.ast_scanner import (
    ASTScanner,
    CombinedScanner,
    create_combined_scanner,
)
from codecanary.scanner.semgrep_scanner import (
    SemgrepScanner,
    MultiScanner,
)

__all__ = [
    # Interface
    "ScannerInterface",
    # Implementations
    "RegexScanner",
    "ASTScanner",
    "SemgrepScanner",
    # Combined scanners
    "CombinedScanner",
    "MultiScanner",
    "create_combined_scanner",
    # Analyzer
    "Analyzer",
    "get_scanner",
]
