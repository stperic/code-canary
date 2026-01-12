"""Scanner interface for extensible detection backends.

Per ARCHITECTURE.md Section 8, the scanner uses an abstract interface
to support multiple detection backends:
- RegexScanner: Fast, regex-based (default for MVP)
- ASTScanner: Python AST analysis (Phase 2)
- SemgrepScanner: Semgrep integration (Phase 2)
"""

from abc import ABC, abstractmethod
from typing import Optional

from codecanary.models.findings import Finding
from codecanary.models.test_case import DetectionPattern


class ScannerInterface(ABC):
    """Abstract base class for pattern scanners.

    Implementations:
    - RegexScanner: Fast, regex-based (default for MVP)
    - ASTScanner: Python AST analysis (Phase 2)
    - SemgrepScanner: Semgrep integration (Phase 2)

    Design notes:
    - Regex is sufficient for canary tokens (exact matches)
    - Regex has known limitations for SQLi, XSS, SSRF (context-dependent)
    - Future backends can provide higher accuracy for complex patterns
    """

    @abstractmethod
    def scan_content(
        self,
        content: str,
        patterns: list[DetectionPattern],
        filepath: str = "<unknown>",
        cwe: Optional[str] = None,
    ) -> list[Finding]:
        """Scan content for patterns.

        Args:
            content: File content to scan
            patterns: Detection patterns to look for
            filepath: Path for reporting (not used for scanning)
            cwe: CWE to associate with findings

        Returns:
            List of findings
        """
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Scanner name for reporting."""
        pass

    @property
    def capabilities(self) -> dict[str, bool]:
        """Scanner capabilities for pattern matching.

        Returns dict with:
        - exact_match: Can match exact strings
        - regex: Can use regex patterns
        - context_aware: Understands code context
        - cross_file: Can trace across files
        """
        return {
            "exact_match": True,
            "regex": True,
            "context_aware": False,
            "cross_file": False,
        }

    def supports_language(self, language: str) -> bool:
        """Check if scanner supports a specific language.

        Args:
            language: Language identifier (python, javascript, etc.)

        Returns:
            True if language is supported
        """
        # Default: regex scanner supports all languages
        return True
