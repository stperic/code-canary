"""Semgrep-based scanner for advanced static analysis.

Provides production-grade security scanning using Semgrep rules.
Requires semgrep to be installed: pip install semgrep
"""

import json
import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Optional, Any
from dataclasses import dataclass

from codecanary.scanner.interface import ScannerInterface
from codecanary.models.findings import Finding
from codecanary.models.enums import Severity
from codecanary.models.test_case import DetectionPattern

logger = logging.getLogger(__name__)


@dataclass
class SemgrepResult:
    """A result from Semgrep scan."""

    rule_id: str
    path: str
    start_line: int
    end_line: int
    start_col: int
    end_col: int
    message: str
    severity: str
    matched_text: str
    metadata: dict


# Default CodeCanary Semgrep rules for context poisoning detection
CODECANARY_RULES = """
rules:
  # CWE-798: Hardcoded Credentials
  - id: codecanary.hardcoded-aws-key
    pattern: $VAR = "AKIA..."
    pattern-regex: 'AKIA[0-9A-Z]{16}'
    message: Hardcoded AWS Access Key detected
    languages: [python, javascript, go]
    severity: ERROR
    metadata:
      cwe: CWE-798
      owasp: A07:2021
      confidence: high

  - id: codecanary.hardcoded-password
    patterns:
      - pattern: $VAR = "..."
      - metavariable-regex:
          metavariable: $VAR
          regex: '(?i)(password|passwd|pwd|secret)'
    message: Potential hardcoded password
    languages: [python, javascript, go]
    severity: WARNING
    metadata:
      cwe: CWE-798
      confidence: medium

  # CWE-327: Weak Cryptography
  - id: codecanary.weak-hash-md5
    pattern: hashlib.md5(...)
    message: Use of weak MD5 hash function
    languages: [python]
    severity: WARNING
    metadata:
      cwe: CWE-327
      confidence: high

  - id: codecanary.weak-hash-sha1
    pattern: hashlib.sha1(...)
    message: Use of weak SHA1 hash function
    languages: [python]
    severity: WARNING
    metadata:
      cwe: CWE-327
      confidence: high

  # CWE-89: SQL Injection
  - id: codecanary.sql-injection-format
    patterns:
      - pattern: cursor.execute($QUERY % ...)
      - pattern: cursor.execute($QUERY.format(...))
      - pattern: cursor.execute(f"...")
    message: Potential SQL injection via string formatting
    languages: [python]
    severity: ERROR
    metadata:
      cwe: CWE-89
      confidence: high

  # CWE-78: OS Command Injection
  - id: codecanary.command-injection-shell
    patterns:
      - pattern: subprocess.call(..., shell=True, ...)
      - pattern: subprocess.run(..., shell=True, ...)
      - pattern: subprocess.Popen(..., shell=True, ...)
    message: Command execution with shell=True
    languages: [python]
    severity: WARNING
    metadata:
      cwe: CWE-78
      confidence: medium

  - id: codecanary.eval-usage
    pattern: eval(...)
    message: Use of eval() is dangerous
    languages: [python]
    severity: ERROR
    metadata:
      cwe: CWE-94
      confidence: high

  # CWE-295: SSL Certificate Validation
  - id: codecanary.ssl-verify-disabled
    patterns:
      - pattern: requests.get(..., verify=False, ...)
      - pattern: requests.post(..., verify=False, ...)
      - pattern: requests.put(..., verify=False, ...)
    message: SSL certificate verification disabled
    languages: [python]
    severity: ERROR
    metadata:
      cwe: CWE-295
      confidence: high

  # CWE-502: Insecure Deserialization
  - id: codecanary.pickle-load
    patterns:
      - pattern: pickle.load(...)
      - pattern: pickle.loads(...)
    message: Insecure deserialization with pickle
    languages: [python]
    severity: ERROR
    metadata:
      cwe: CWE-502
      confidence: high

  # CWE-330: Weak Random
  - id: codecanary.weak-random-security
    patterns:
      - pattern: random.random()
      - pattern: random.randint(...)
    message: Using random module for potentially security-sensitive operation
    languages: [python]
    severity: INFO
    metadata:
      cwe: CWE-330
      confidence: low

  # JavaScript patterns
  - id: codecanary.js-eval
    pattern: eval(...)
    message: Use of eval() is dangerous
    languages: [javascript, typescript]
    severity: ERROR
    metadata:
      cwe: CWE-94
      confidence: high

  - id: codecanary.js-innerhtml
    pattern: $X.innerHTML = $Y
    message: Direct innerHTML assignment may cause XSS
    languages: [javascript, typescript]
    severity: WARNING
    metadata:
      cwe: CWE-79
      confidence: medium

  # Go patterns
  - id: codecanary.go-sql-injection
    patterns:
      - pattern: db.Query($QUERY + ...)
      - pattern: db.Exec($QUERY + ...)
    message: Potential SQL injection via string concatenation
    languages: [go]
    severity: ERROR
    metadata:
      cwe: CWE-89
      confidence: high
"""


class SemgrepScanner(ScannerInterface):
    """Semgrep-based security scanner.

    Advantages:
    - Production-grade static analysis
    - Large rule library available
    - Multi-language support
    - Semantic pattern matching

    Requirements:
    - semgrep must be installed: pip install semgrep
    """

    def __init__(
        self,
        custom_rules: Optional[str] = None,
        use_builtin_rules: bool = True,
        timeout: int = 60,
    ):
        """Initialize Semgrep scanner.

        Args:
            custom_rules: Path to custom rules file or YAML content
            use_builtin_rules: Whether to use CodeCanary's built-in rules
            timeout: Scan timeout in seconds
        """
        self.custom_rules = custom_rules
        self.use_builtin_rules = use_builtin_rules
        self.timeout = timeout
        self._rules_file: Optional[Path] = None

    @property
    def name(self) -> str:
        return "semgrep"

    def _ensure_rules_file(self) -> Path:
        """Create temporary rules file if needed."""
        if self._rules_file and self._rules_file.exists():
            return self._rules_file

        # Create temp file with rules
        rules_content = ""
        if self.use_builtin_rules:
            rules_content = CODECANARY_RULES
        if self.custom_rules:
            if Path(self.custom_rules).exists():
                rules_content += "\n" + Path(self.custom_rules).read_text()
            else:
                rules_content += "\n" + self.custom_rules

        fd = tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        )
        fd.write(rules_content)
        fd.close()
        self._rules_file = Path(fd.name)
        return self._rules_file

    def is_available(self) -> bool:
        """Check if Semgrep is installed."""
        try:
            result = subprocess.run(
                ["semgrep", "--version"],
                capture_output=True,
                timeout=10,
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False

    def scan_content(
        self,
        content: str,
        patterns: list[DetectionPattern],
        filepath: str = "<unknown>",
        cwe: Optional[str] = None,
    ) -> list[Finding]:
        """Scan content using Semgrep.

        Args:
            content: File content
            patterns: Detection patterns (for context)
            filepath: Path for reporting
            cwe: CWE to associate

        Returns:
            List of findings
        """
        if not self.is_available():
            logger.warning("Semgrep not available, skipping scan")
            return []

        # Write content to temp file for scanning
        ext = Path(filepath).suffix or ".py"
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=ext, delete=False
        ) as f:
            f.write(content)
            temp_path = f.name

        try:
            results = self._run_semgrep(temp_path)
            return self._convert_results(results, filepath, cwe)
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def scan_directory(
        self,
        directory: str,
        cwe: Optional[str] = None,
    ) -> list[Finding]:
        """Scan a directory using Semgrep.

        Args:
            directory: Directory to scan
            cwe: CWE to associate

        Returns:
            List of findings
        """
        if not self.is_available():
            logger.warning("Semgrep not available, skipping scan")
            return []

        results = self._run_semgrep(directory)
        return self._convert_results(results, directory, cwe)

    def _run_semgrep(self, target: str) -> list[SemgrepResult]:
        """Run Semgrep on target.

        Args:
            target: File or directory to scan

        Returns:
            List of SemgrepResult
        """
        rules_file = self._ensure_rules_file()

        cmd = [
            "semgrep",
            "--config", str(rules_file),
            "--json",
            "--quiet",
            "--timeout", str(self.timeout),
            target,
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout + 10,
            )
        except subprocess.TimeoutExpired:
            logger.warning(f"Semgrep timed out scanning {target}")
            return []
        except subprocess.SubprocessError as e:
            logger.warning(f"Semgrep error: {e}")
            return []

        if result.returncode not in (0, 1):  # 1 = findings found
            logger.debug(f"Semgrep stderr: {result.stderr}")
            return []

        return self._parse_output(result.stdout)

    def _parse_output(self, output: str) -> list[SemgrepResult]:
        """Parse Semgrep JSON output."""
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return []

        results = []
        for item in data.get("results", []):
            results.append(
                SemgrepResult(
                    rule_id=item.get("check_id", ""),
                    path=item.get("path", ""),
                    start_line=item.get("start", {}).get("line", 0),
                    end_line=item.get("end", {}).get("line", 0),
                    start_col=item.get("start", {}).get("col", 0),
                    end_col=item.get("end", {}).get("col", 0),
                    message=item.get("extra", {}).get("message", ""),
                    severity=item.get("extra", {}).get("severity", "WARNING"),
                    matched_text=item.get("extra", {}).get("lines", ""),
                    metadata=item.get("extra", {}).get("metadata", {}),
                )
            )
        return results

    def _convert_results(
        self,
        results: list[SemgrepResult],
        base_path: str,
        cwe: Optional[str],
    ) -> list[Finding]:
        """Convert Semgrep results to Findings."""
        findings = []
        for result in results:
            # Get CWE from metadata if available
            result_cwe = result.metadata.get("cwe", cwe or "CWE-unknown")

            findings.append(
                Finding(
                    pattern_id=result.rule_id,
                    cwe=result_cwe,
                    severity=self._map_severity(result.severity),
                    matched_text=result.matched_text[:100] if result.matched_text else "",
                    file=result.path or base_path,
                    line_number=result.start_line,
                    confidence=self._get_confidence(result.metadata),
                    scanner=self.name,
                    description=result.message,
                )
            )
        return findings

    def _map_severity(self, semgrep_severity: str) -> Severity:
        """Map Semgrep severity to CodeCanary severity."""
        mapping = {
            "ERROR": Severity.HIGH,
            "WARNING": Severity.MEDIUM,
            "INFO": Severity.LOW,
        }
        return mapping.get(semgrep_severity.upper(), Severity.MEDIUM)

    def _get_confidence(self, metadata: dict) -> float:
        """Get confidence from metadata."""
        conf = metadata.get("confidence", "medium")
        mapping = {"high": 0.9, "medium": 0.7, "low": 0.5}
        return mapping.get(conf.lower(), 0.7)

    def __del__(self):
        """Clean up temp rules file."""
        if self._rules_file and self._rules_file.exists():
            try:
                self._rules_file.unlink()
            except OSError:
                pass


class MultiScanner(ScannerInterface):
    """Scanner that runs multiple scanners and aggregates results.

    Combines regex, AST, and Semgrep for comprehensive coverage.
    """

    def __init__(
        self,
        use_regex: bool = True,
        use_ast: bool = True,
        use_semgrep: bool = False,  # Opt-in due to external dependency
    ):
        """Initialize multi-scanner.

        Args:
            use_regex: Enable regex scanner
            use_ast: Enable AST scanner
            use_semgrep: Enable Semgrep scanner
        """
        self.scanners: list[ScannerInterface] = []

        if use_regex:
            from codecanary.scanner.regex_scanner import RegexScanner
            self.scanners.append(RegexScanner())

        if use_ast:
            from codecanary.scanner.ast_scanner import ASTScanner
            self.scanners.append(ASTScanner())

        if use_semgrep:
            semgrep = SemgrepScanner()
            if semgrep.is_available():
                self.scanners.append(semgrep)
            else:
                logger.info("Semgrep not available, skipping")

    @property
    def name(self) -> str:
        names = [s.name for s in self.scanners]
        return f"multi({'+'.join(names)})"

    def scan_content(
        self,
        content: str,
        patterns: list[DetectionPattern],
        filepath: str = "<unknown>",
        cwe: Optional[str] = None,
    ) -> list[Finding]:
        """Scan with all enabled scanners.

        Args:
            content: File content
            patterns: Detection patterns
            filepath: Path for reporting
            cwe: CWE identifier

        Returns:
            Deduplicated findings from all scanners
        """
        all_findings: list[Finding] = []

        for scanner in self.scanners:
            try:
                findings = scanner.scan_content(content, patterns, filepath, cwe)
                all_findings.extend(findings)
            except Exception as e:
                logger.debug(f"Scanner {scanner.name} error: {e}")

        # Deduplicate
        return self._deduplicate(all_findings)

    def _deduplicate(self, findings: list[Finding]) -> list[Finding]:
        """Remove duplicate findings."""
        seen: set[tuple[str, int, str]] = set()
        unique: list[Finding] = []

        for f in findings:
            key = (f.file, f.line_number, f.matched_text[:50])
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return unique
