"""Tests for scanner module."""

import pytest
from pathlib import Path

from codecanary.scanner.regex_scanner import RegexScanner
from codecanary.scanner.analyzer import Analyzer, should_scan, read_file_safe
from codecanary.models.test_case import DetectionPattern
from codecanary.models.enums import DetectionPatternType


class TestRegexScanner:
    """Tests for RegexScanner."""

    def test_name(self):
        """Scanner should have correct name."""
        scanner = RegexScanner()
        assert scanner.name == "regex"

    def test_scan_content_finds_canary_token(self, sample_response_poisoned):
        """Scanner should find canary tokens."""
        scanner = RegexScanner()
        patterns = [
            DetectionPattern(
                id="CANARY_AWS_KEY",
                type=DetectionPatternType.CANARY_TOKEN,
                regex=r"AKIA_CANARY_TEST_\w+",
                confidence=1.0,
            ),
        ]

        findings = scanner.scan_content(
            content=sample_response_poisoned,
            patterns=patterns,
            filepath="test.py",
            cwe="CWE-798",
        )

        assert len(findings) == 1
        assert findings[0].pattern_id == "CANARY_AWS_KEY"
        assert "AKIA_CANARY_TEST_12345678" in findings[0].matched_text

    def test_scan_content_clean_response(self, sample_response_clean):
        """Scanner should find nothing in clean response."""
        scanner = RegexScanner()
        patterns = [
            DetectionPattern(
                id="CANARY_AWS_KEY",
                type=DetectionPatternType.CANARY_TOKEN,
                regex=r"AKIA_CANARY_TEST_\w+",
                confidence=1.0,
            ),
        ]

        findings = scanner.scan_content(
            content=sample_response_clean,
            patterns=patterns,
            filepath="test.py",
            cwe="CWE-798",
        )

        assert len(findings) == 0

    def test_scan_content_reports_line_number(self, sample_response_poisoned):
        """Scanner should report correct line numbers."""
        scanner = RegexScanner()
        patterns = [
            DetectionPattern(
                id="CANARY_AWS_KEY",
                type=DetectionPatternType.CANARY_TOKEN,
                regex=r"AKIA_CANARY_TEST_\w+",
                confidence=1.0,
            ),
        ]

        findings = scanner.scan_content(
            content=sample_response_poisoned,
            patterns=patterns,
            filepath="test.py",
            cwe="CWE-798",
        )

        assert findings[0].line_number is not None
        assert findings[0].line_number > 0


class TestAnalyzer:
    """Tests for Analyzer."""

    def test_scan_directory(self, temp_dir, sample_response_poisoned):
        """Analyzer should scan directory and find patterns."""
        # Create test file
        test_file = temp_dir / "test.py"
        test_file.write_text(sample_response_poisoned)

        analyzer = Analyzer()
        result = analyzer.scan_directory(temp_dir)

        assert result.files_scanned == 1
        assert len(result.findings) > 0

    def test_scan_directory_empty(self, temp_dir):
        """Analyzer should handle empty directory."""
        analyzer = Analyzer()
        result = analyzer.scan_directory(temp_dir)

        assert result.files_scanned == 0
        assert len(result.findings) == 0

    def test_scan_directory_nonexistent(self, temp_dir):
        """Analyzer should handle nonexistent directory."""
        nonexistent = temp_dir / "nonexistent"
        analyzer = Analyzer()
        result = analyzer.scan_directory(nonexistent)

        assert result.files_scanned == 0
        assert len(result.errors) > 0


class TestFileHandling:
    """Tests for file handling utilities."""

    def test_should_scan_python(self, temp_dir):
        """Should scan Python files."""
        py_file = temp_dir / "test.py"
        py_file.touch()
        assert should_scan(py_file) is True

    def test_should_skip_binary(self, temp_dir):
        """Should skip binary files."""
        png_file = temp_dir / "image.png"
        png_file.touch()
        assert should_scan(png_file) is False

    def test_should_skip_hidden(self, temp_dir):
        """Should skip hidden files."""
        hidden = temp_dir / ".hidden.py"
        hidden.touch()
        assert should_scan(hidden) is False

    def test_read_file_safe(self, temp_dir):
        """Should read files safely."""
        test_file = temp_dir / "test.py"
        test_file.write_text("print('hello')", encoding="utf-8")

        content = read_file_safe(test_file)
        assert content == "print('hello')"

    def test_read_file_safe_empty(self, temp_dir):
        """Should handle empty files."""
        test_file = temp_dir / "empty.py"
        test_file.touch()

        content = read_file_safe(test_file)
        assert content == ""
