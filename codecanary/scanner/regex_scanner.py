"""Regex-based scanner implementation.

This is the default scanner for CodeCanary MVP.
"""

import re
import logging
from typing import Optional

from codecanary.scanner.interface import ScannerInterface
from codecanary.models.findings import Finding
from codecanary.models.enums import Severity
from codecanary.models.test_case import DetectionPattern

logger = logging.getLogger(__name__)


class RegexScanner(ScannerInterface):
    """Regex-based pattern scanner.

    Strengths:
    - Fast and lightweight
    - Perfect for canary token detection (exact matches)
    - No external dependencies

    Limitations:
    - May have false positives for context-dependent patterns
    - Cannot understand code semantics
    - May miss obfuscated patterns

    For production use with SQLi/XSS/SSRF, consider ASTScanner or SemgrepScanner.
    """

    @property
    def name(self) -> str:
        return "regex"

    def scan_content(
        self,
        content: str,
        patterns: list[DetectionPattern],
        filepath: str = "<unknown>",
        cwe: Optional[str] = None,
    ) -> list[Finding]:
        """Scan content for patterns using regex.

        Args:
            content: File content to scan
            patterns: Detection patterns to look for
            filepath: Path for reporting
            cwe: CWE to associate with findings

        Returns:
            List of findings
        """
        findings: list[Finding] = []

        for pattern in patterns:
            try:
                regex = re.compile(pattern.regex, re.MULTILINE)
                for match in regex.finditer(content):
                    # Calculate line number
                    line_number = content[: match.start()].count("\n") + 1

                    # Get matched text (limit length for reporting)
                    matched_text = match.group()
                    if len(matched_text) > 100:
                        matched_text = matched_text[:100] + "..."

                    findings.append(
                        Finding(
                            pattern_id=pattern.id,
                            cwe=cwe or "CWE-unknown",
                            severity=self._get_severity_from_confidence(pattern.confidence),
                            matched_text=matched_text,
                            file=filepath,
                            line_number=line_number,
                            confidence=pattern.confidence,
                            scanner=self.name,
                            description=pattern.description,
                        )
                    )
            except re.error as e:
                # Log invalid regex but continue
                logger.warning(f"Invalid regex in pattern {pattern.id}: {e}")

        return findings

    def _get_severity_from_confidence(self, confidence: float) -> Severity:
        """Infer severity from pattern confidence.

        Higher confidence patterns typically indicate more severe issues.
        """
        if confidence >= 0.9:
            return Severity.CRITICAL
        elif confidence >= 0.7:
            return Severity.HIGH
        elif confidence >= 0.5:
            return Severity.MEDIUM
        else:
            return Severity.LOW
