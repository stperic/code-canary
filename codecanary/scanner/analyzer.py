"""File and directory analyzer for scanning AI responses.

Handles encoding issues, binary files, and size limits gracefully.
"""

from pathlib import Path
import logging
from typing import Optional

from codecanary.scanner.interface import ScannerInterface
from codecanary.scanner.regex_scanner import RegexScanner
from codecanary.models.findings import Finding, ScanResult
from codecanary.models.test_case import DetectionPattern
from codecanary.bait.patterns import TEST_CASES

logger = logging.getLogger(__name__)


# File extensions to scan
SCANNABLE_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".go",
    ".java",
    ".rb",
    ".php",
    ".cs",
    ".rs",
    ".swift",
    ".kt",
    ".scala",
    ".sh",
    ".bash",
    ".sql",
    ".txt",
    ".md",
}

# Extensions to skip (binary files)
BINARY_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".webp",
    ".pdf",
    ".zip",
    ".tar",
    ".gz",
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".pyc",
    ".pyo",
    ".class",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
}

# Maximum file size to scan (10 MB)
MAX_FILE_SIZE = 10 * 1024 * 1024


def get_scanner(scanner_type: str = "regex") -> ScannerInterface:
    """Get scanner instance by type.

    Args:
        scanner_type: One of "regex", "ast", "semgrep"

    Returns:
        Scanner instance

    Raises:
        ValueError: If scanner type is unknown or unavailable
    """
    if scanner_type == "regex":
        return RegexScanner()

    # Phase 2 scanners (lazy import to avoid dependency issues)
    if scanner_type == "ast":
        raise ValueError("AST scanner not yet implemented (Phase 2)")

    if scanner_type == "semgrep":
        raise ValueError("Semgrep scanner not yet implemented (Phase 2)")

    raise ValueError(f"Unknown scanner type: {scanner_type}")


def read_file_safe(filepath: Path, max_size_mb: int = 10) -> Optional[str]:
    """Read file with encoding detection and size limits.

    Returns None for:
    - Binary files
    - Files exceeding size limit
    - Undecodable files

    Args:
        filepath: Path to file
        max_size_mb: Maximum file size in MB

    Returns:
        File content or None if unreadable
    """
    # Check file size
    try:
        size = filepath.stat().st_size
        if size > max_size_mb * 1024 * 1024:
            logger.warning(f"File too large, skipping: {filepath} ({size} bytes)")
            return None
        if size == 0:
            return ""
    except OSError:
        return None

    # Try common encodings
    encodings = ["utf-8", "latin-1", "cp1252"]

    for encoding in encodings:
        try:
            with open(filepath, "r", encoding=encoding) as f:
                content = f.read()
            # Check for binary content (null bytes)
            if "\x00" in content:
                logger.debug(f"Binary content detected, skipping: {filepath}")
                return None
            return content
        except UnicodeDecodeError:
            continue
        except OSError as e:
            logger.warning(f"Error reading file {filepath}: {e}")
            return None

    logger.warning(f"Could not decode file with any encoding: {filepath}")
    return None


def should_scan(filepath: Path) -> bool:
    """Determine if file should be scanned.

    Args:
        filepath: Path to check

    Returns:
        True if file should be scanned
    """
    # Skip hidden files
    if filepath.name.startswith("."):
        return False

    # Skip binary extensions
    if filepath.suffix.lower() in BINARY_EXTENSIONS:
        return False

    # Check scannable extensions
    if filepath.suffix.lower() in SCANNABLE_EXTENSIONS:
        return True

    # For files without extension, check if they look like text
    if not filepath.suffix:
        return True

    return False


class Analyzer:
    """Analyzes files and directories for canary patterns.

    Handles:
    - Multiple file formats
    - Encoding issues
    - Binary file detection
    - Size limits
    """

    def __init__(
        self,
        scanner_type: str = "regex",
        scanner: Optional[ScannerInterface] = None,
    ):
        """Initialize the analyzer.

        Args:
            scanner_type: Type of scanner to use
            scanner: Optional pre-configured scanner instance
        """
        self.scanner = scanner or get_scanner(scanner_type)
        self._all_patterns = self._collect_patterns()

    def _collect_patterns(self) -> dict[str, list[DetectionPattern]]:
        """Collect all detection patterns from test cases, grouped by CWE."""
        patterns_by_cwe: dict[str, list[DetectionPattern]] = {}
        for tc in TEST_CASES:
            if tc.cwe not in patterns_by_cwe:
                patterns_by_cwe[tc.cwe] = []
            patterns_by_cwe[tc.cwe].extend(tc.detection_patterns)
        return patterns_by_cwe

    def scan_file(self, filepath: Path) -> list[Finding]:
        """Scan a single file for patterns.

        Args:
            filepath: Path to file to scan

        Returns:
            List of findings
        """
        content = read_file_safe(filepath)
        if content is None:
            return []

        all_findings: list[Finding] = []

        # Scan for each CWE's patterns
        for cwe, patterns in self._all_patterns.items():
            findings = self.scanner.scan_content(
                content=content,
                patterns=patterns,
                filepath=str(filepath),
                cwe=cwe,
            )
            all_findings.extend(findings)

        return all_findings

    def scan_directory(self, directory: Path) -> ScanResult:
        """Scan all files in a directory.

        Args:
            directory: Directory to scan

        Returns:
            ScanResult with all findings
        """
        all_findings: list[Finding] = []
        files_scanned = 0
        files_skipped = 0
        errors: list[str] = []

        if not directory.exists():
            return ScanResult(
                files_scanned=0,
                files_skipped=0,
                findings=[],
                errors=[f"Directory not found: {directory}"],
            )

        for filepath in directory.rglob("*"):
            if not filepath.is_file():
                continue

            if not should_scan(filepath):
                files_skipped += 1
                continue

            try:
                findings = self.scan_file(filepath)
                all_findings.extend(findings)
                files_scanned += 1
            except Exception as e:
                errors.append(f"Error scanning {filepath}: {e}")
                logger.exception(f"Error scanning {filepath}")

        return ScanResult(
            files_scanned=files_scanned,
            files_skipped=files_skipped,
            findings=all_findings,
            errors=errors,
        )

    def scan_content(
        self,
        content: str,
        filepath: str = "<unknown>",
    ) -> list[Finding]:
        """Scan content string directly.

        Args:
            content: Content to scan
            filepath: Path for reporting

        Returns:
            List of findings
        """
        all_findings: list[Finding] = []

        for cwe, patterns in self._all_patterns.items():
            findings = self.scanner.scan_content(
                content=content,
                patterns=patterns,
                filepath=filepath,
                cwe=cwe,
            )
            all_findings.extend(findings)

        return all_findings
