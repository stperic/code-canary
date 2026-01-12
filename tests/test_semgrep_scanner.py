"""Tests for Semgrep-based scanner."""

import pytest
import subprocess
from unittest.mock import patch, MagicMock
from pathlib import Path

from codecanary.scanner.semgrep_scanner import (
    SemgrepScanner,
    SemgrepResult,
    MultiScanner,
    CODECANARY_RULES,
)
from codecanary.models.enums import Severity


class TestSemgrepResult:
    """Tests for SemgrepResult dataclass."""

    def test_creation(self):
        """Should create result with all fields."""
        result = SemgrepResult(
            rule_id="codecanary.test-rule",
            path="test.py",
            start_line=10,
            end_line=10,
            start_col=1,
            end_col=20,
            message="Test finding",
            severity="ERROR",
            matched_text="password = 'secret'",
            metadata={"cwe": "CWE-798", "confidence": "high"},
        )
        assert result.rule_id == "codecanary.test-rule"
        assert result.start_line == 10
        assert result.metadata["cwe"] == "CWE-798"


class TestSemgrepScanner:
    """Tests for SemgrepScanner."""

    @pytest.fixture
    def scanner(self):
        """Create Semgrep scanner."""
        return SemgrepScanner()

    def test_name(self, scanner):
        """Scanner should have correct name."""
        assert scanner.name == "semgrep"

    def test_builtin_rules_exist(self):
        """Built-in rules should be valid YAML."""
        assert "rules:" in CODECANARY_RULES
        assert "codecanary." in CODECANARY_RULES
        assert "CWE-798" in CODECANARY_RULES
        assert "CWE-89" in CODECANARY_RULES

    def test_severity_mapping(self, scanner):
        """Should map severity correctly."""
        assert scanner._map_severity("ERROR") == Severity.HIGH
        assert scanner._map_severity("WARNING") == Severity.MEDIUM
        assert scanner._map_severity("INFO") == Severity.LOW

    def test_get_confidence(self, scanner):
        """Should get confidence from metadata."""
        assert scanner._get_confidence({"confidence": "high"}) == 0.9
        assert scanner._get_confidence({"confidence": "medium"}) == 0.7
        assert scanner._get_confidence({"confidence": "low"}) == 0.5
        assert scanner._get_confidence({}) == 0.7

    def test_is_available_when_installed(self, scanner):
        """Should detect if semgrep is installed."""
        # This test will pass/fail based on actual semgrep installation
        # Mock it for consistent testing
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            assert scanner.is_available() is True

    def test_is_available_when_not_installed(self, scanner):
        """Should detect if semgrep is not installed."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError()
            assert scanner.is_available() is False

    def test_scan_content_when_unavailable(self, scanner):
        """Should return empty when semgrep unavailable."""
        with patch.object(scanner, "is_available", return_value=False):
            findings = scanner.scan_content("code", [], "test.py")
            assert findings == []

    def test_parse_output_valid(self, scanner):
        """Should parse valid Semgrep JSON output."""
        output = '''
{
    "results": [
        {
            "check_id": "codecanary.test",
            "path": "test.py",
            "start": {"line": 10, "col": 1},
            "end": {"line": 10, "col": 20},
            "extra": {
                "message": "Test finding",
                "severity": "ERROR",
                "lines": "password = 'secret'",
                "metadata": {"cwe": "CWE-798"}
            }
        }
    ]
}
'''
        results = scanner._parse_output(output)
        assert len(results) == 1
        assert results[0].rule_id == "codecanary.test"
        assert results[0].start_line == 10

    def test_parse_output_invalid_json(self, scanner):
        """Should handle invalid JSON."""
        results = scanner._parse_output("not json")
        assert results == []

    def test_parse_output_empty_results(self, scanner):
        """Should handle empty results."""
        output = '{"results": []}'
        results = scanner._parse_output(output)
        assert results == []

    def test_convert_results(self, scanner):
        """Should convert SemgrepResult to Finding."""
        semgrep_results = [
            SemgrepResult(
                rule_id="codecanary.test",
                path="test.py",
                start_line=10,
                end_line=10,
                start_col=1,
                end_col=20,
                message="Test finding",
                severity="ERROR",
                matched_text="password = 'secret'",
                metadata={"cwe": "CWE-798", "confidence": "high"},
            )
        ]
        
        findings = scanner._convert_results(semgrep_results, "test.py", None)
        
        assert len(findings) == 1
        assert findings[0].pattern_id == "codecanary.test"
        assert findings[0].cwe == "CWE-798"
        assert findings[0].scanner == "semgrep"

    def test_ensures_rules_file(self, scanner):
        """Should create temp rules file."""
        rules_file = scanner._ensure_rules_file()
        assert rules_file.exists()
        content = rules_file.read_text()
        assert "codecanary." in content


class TestMultiScanner:
    """Tests for MultiScanner."""

    def test_regex_only(self):
        """Should work with regex only."""
        scanner = MultiScanner(use_regex=True, use_ast=False, use_semgrep=False)
        assert len(scanner.scanners) == 1
        assert scanner.scanners[0].name == "regex"

    def test_ast_only(self):
        """Should work with AST only."""
        scanner = MultiScanner(use_regex=False, use_ast=True, use_semgrep=False)
        assert len(scanner.scanners) == 1
        assert scanner.scanners[0].name == "ast"

    def test_combined_name(self):
        """Should have combined name."""
        scanner = MultiScanner(use_regex=True, use_ast=True, use_semgrep=False)
        assert "multi" in scanner.name
        assert "regex" in scanner.name
        assert "ast" in scanner.name

    def test_deduplicates_findings(self):
        """Should deduplicate findings."""
        scanner = MultiScanner(use_regex=True, use_ast=True, use_semgrep=False)
        
        code = 'password = "secret123"'
        findings = scanner.scan_content(code, [], "test.py")
        
        # Check no exact duplicates
        keys = [(f.file, f.line_number, f.matched_text[:50]) for f in findings]
        assert len(keys) == len(set(keys))

    def test_handles_scanner_errors(self):
        """Should handle individual scanner errors."""
        scanner = MultiScanner(use_regex=True, use_ast=True, use_semgrep=False)
        
        # Invalid Python won't break the whole scan
        code = "this is not valid python {"
        findings = scanner.scan_content(code, [], "test.py")
        # Should return empty or regex-only findings
        assert isinstance(findings, list)


class TestBuiltinRules:
    """Tests for built-in Semgrep rules."""

    def test_has_credential_rules(self):
        """Should have credential detection rules."""
        assert "hardcoded-aws-key" in CODECANARY_RULES
        assert "hardcoded-password" in CODECANARY_RULES

    def test_has_crypto_rules(self):
        """Should have weak crypto detection rules."""
        assert "weak-hash-md5" in CODECANARY_RULES
        assert "weak-hash-sha1" in CODECANARY_RULES

    def test_has_injection_rules(self):
        """Should have injection detection rules."""
        assert "sql-injection" in CODECANARY_RULES
        assert "command-injection" in CODECANARY_RULES

    def test_has_javascript_rules(self):
        """Should have JavaScript rules."""
        assert "js-eval" in CODECANARY_RULES
        assert "js-innerhtml" in CODECANARY_RULES

    def test_has_go_rules(self):
        """Should have Go rules."""
        assert "go-sql-injection" in CODECANARY_RULES

    def test_rules_have_metadata(self):
        """Rules should have CWE metadata."""
        assert "cwe: CWE-" in CODECANARY_RULES
        assert "confidence:" in CODECANARY_RULES
