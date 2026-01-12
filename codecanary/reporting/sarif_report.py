"""SARIF (Static Analysis Results Interchange Format) reporter.

Generates SARIF 2.1.0 compatible output for CI/CD integration.
See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from codecanary import __version__
from codecanary.models.findings import ScanResult, Finding
from codecanary.models.enums import Severity


# SARIF severity mapping
SEVERITY_TO_SARIF = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# CWE to SARIF level mapping (used when Finding has CWE)
CWE_SECURITY_SEVERITY = {
    "CWE-798": "critical",  # Hardcoded credentials
    "CWE-89": "critical",   # SQL Injection
    "CWE-78": "critical",   # OS Command Injection
    "CWE-94": "critical",   # Code Injection
    "CWE-327": "high",      # Weak Crypto
    "CWE-295": "high",      # Improper Certificate Validation
    "CWE-502": "high",      # Deserialization
    "CWE-319": "medium",    # Cleartext Transmission
    "CWE-330": "medium",    # Weak Random
    "CWE-22": "high",       # Path Traversal
    "CWE-79": "high",       # XSS
    "CWE-611": "high",      # XXE
    "CWE-918": "high",      # SSRF
    "CWE-1321": "high",     # Prototype Pollution
    "CWE-1333": "medium",   # ReDoS
}


class SARIFReporter:
    """Generates SARIF 2.1.0 reports from scan results."""

    SARIF_VERSION = "2.1.0"
    SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

    def __init__(
        self,
        findings_file: str,
        output_file: str = "./results/results.sarif",
        base_uri: str = "",
    ):
        """Initialize the SARIF reporter.

        Args:
            findings_file: Path to findings.json from scanner
            output_file: Path for output SARIF file
            base_uri: Base URI for artifact locations (e.g., "file:///workspace/")
        """
        self.findings_file = Path(findings_file)
        self.output_file = Path(output_file)
        self.base_uri = base_uri

    def generate(self) -> dict[str, Any]:
        """Generate the SARIF report.

        Returns:
            Complete SARIF report as dictionary
        """
        # Load findings
        scan_result = ScanResult.load(str(self.findings_file))

        # Build SARIF structure
        sarif = {
            "$schema": self.SARIF_SCHEMA,
            "version": self.SARIF_VERSION,
            "runs": [self._create_run(scan_result)],
        }

        # Save report
        self.output_file.parent.mkdir(parents=True, exist_ok=True)
        self.output_file.write_text(json.dumps(sarif, indent=2), encoding="utf-8")

        return sarif

    def _create_run(self, scan_result: ScanResult) -> dict[str, Any]:
        """Create a SARIF run object."""
        return {
            "tool": self._create_tool(),
            "invocations": [self._create_invocation(scan_result)],
            "results": [self._create_result(f) for f in scan_result.findings],
            "artifacts": self._create_artifacts(scan_result),
        }

    def _create_tool(self) -> dict[str, Any]:
        """Create the tool descriptor."""
        return {
            "driver": {
                "name": "CodeCanary",
                "version": __version__,
                "informationUri": "https://github.com/medxops/code-canary",
                "rules": self._create_rules(),
                "properties": {
                    "tags": ["security", "ai-security", "context-poisoning"],
                },
            }
        }

    def _create_rules(self) -> list[dict[str, Any]]:
        """Create rule descriptors for each test pattern."""
        from codecanary.bait.patterns import TEST_CASES

        rules = []
        seen_patterns = set()

        for tc in TEST_CASES:
            for pattern in tc.detection_patterns:
                if pattern.id in seen_patterns:
                    continue
                seen_patterns.add(pattern.id)

                rule = {
                    "id": pattern.id,
                    "name": pattern.id.replace("_", " ").title(),
                    "shortDescription": {
                        "text": pattern.description or f"Detected {pattern.id}",
                    },
                    "fullDescription": {
                        "text": (
                            f"{pattern.description or pattern.id}. "
                            f"Related to {tc.cwe}: {tc.prompt_context or 'security vulnerability'}."
                        ),
                    },
                    "helpUri": f"https://cwe.mitre.org/data/definitions/{tc.cwe.replace('CWE-', '')}.html",
                    "properties": {
                        "tags": ["security", tc.cwe, tc.owasp_category or ""],
                        "security-severity": str(
                            CWE_SECURITY_SEVERITY.get(tc.cwe, "medium")
                        ),
                    },
                    "defaultConfiguration": {
                        "level": self._get_sarif_level(tc.severity),
                    },
                }
                rules.append(rule)

        return rules

    def _create_invocation(self, scan_result: ScanResult) -> dict[str, Any]:
        """Create invocation metadata."""
        return {
            "executionSuccessful": True,
            "endTimeUtc": scan_result.scan_timestamp,
            "properties": {
                "filesScanned": scan_result.files_scanned,
                "filesSkipped": scan_result.files_skipped,
                "findingsCount": len(scan_result.findings),
            },
        }

    def _create_result(self, finding: Finding) -> dict[str, Any]:
        """Create a SARIF result from a Finding."""
        result = {
            "ruleId": finding.pattern_id,
            "message": {
                "text": f"Canary pattern detected: {finding.pattern_id}. "
                f"Matched: '{finding.matched_text[:100]}...' "
                if len(finding.matched_text) > 100
                else f"Canary pattern detected: {finding.pattern_id}. "
                f"Matched: '{finding.matched_text}'",
            },
            "level": self._finding_to_level(finding),
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.file_path,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": finding.line_number,
                            "startColumn": 1,
                            "snippet": {
                                "text": finding.matched_text,
                            },
                        },
                    },
                }
            ],
            "partialFingerprints": {
                "primaryLocationLineHash": self._hash_fingerprint(finding),
            },
            "properties": {
                "confidence": finding.confidence,
                "patternId": finding.pattern_id,
            },
        }

        # Add CWE if available
        if finding.cwe:
            result["taxa"] = [
                {
                    "toolComponent": {"name": "CWE"},
                    "id": finding.cwe.replace("CWE-", ""),
                }
            ]

        return result

    def _create_artifacts(self, scan_result: ScanResult) -> list[dict[str, Any]]:
        """Create artifact descriptors for scanned files."""
        files = set()
        for finding in scan_result.findings:
            files.add(finding.file_path)

        return [
            {
                "location": {
                    "uri": f,
                    "uriBaseId": "%SRCROOT%",
                },
                "roles": ["analysisTarget"],
            }
            for f in sorted(files)
        ]

    def _get_sarif_level(self, severity: Severity) -> str:
        """Convert severity to SARIF level."""
        return SEVERITY_TO_SARIF.get(severity, "warning")

    def _finding_to_level(self, finding: Finding) -> str:
        """Determine SARIF level from finding."""
        # High confidence = error, lower = warning
        if finding.confidence >= 0.9:
            return "error"
        elif finding.confidence >= 0.7:
            return "warning"
        else:
            return "note"

    def _hash_fingerprint(self, finding: Finding) -> str:
        """Create a fingerprint hash for deduplication."""
        import hashlib

        content = f"{finding.pattern_id}:{finding.file_path}:{finding.line_number}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]


def generate_sarif(
    findings_file: str,
    output_file: str = "./results/results.sarif",
) -> dict[str, Any]:
    """Convenience function to generate SARIF report.

    Args:
        findings_file: Path to findings.json
        output_file: Path for output SARIF file

    Returns:
        SARIF report dictionary
    """
    reporter = SARIFReporter(findings_file, output_file)
    return reporter.generate()
