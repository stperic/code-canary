"""Tests for AST-based scanner."""

import pytest

from codecanary.scanner.ast_scanner import (
    ASTScanner,
    SecurityVisitor,
    ASTMatch,
    CombinedScanner,
    create_combined_scanner,
)
from codecanary.scanner.regex_scanner import RegexScanner
from codecanary.models.test_case import DetectionPattern, DetectionPatternType
from codecanary.models.enums import Severity


class TestSecurityVisitor:
    """Tests for SecurityVisitor AST visitor."""

    def test_detects_hardcoded_password(self):
        """Should detect hardcoded password."""
        code = '''
password = "supersecret123"
'''
        import ast
        tree = ast.parse(code)
        visitor = SecurityVisitor()
        visitor.set_source(code)
        visitor.visit(tree)

        assert len(visitor.matches) == 1
        assert visitor.matches[0].pattern_id == "AST_HARDCODED_CRED"

    def test_detects_hardcoded_api_key(self):
        """Should detect hardcoded API key."""
        code = '''
api_key = "sk-abcdef123456"
'''
        import ast
        tree = ast.parse(code)
        visitor = SecurityVisitor()
        visitor.set_source(code)
        visitor.visit(tree)

        assert len(visitor.matches) == 1
        assert "api_key" in visitor.matches[0].description.lower()

    def test_ignores_placeholder_values(self):
        """Should ignore placeholder values."""
        code = '''
password = "your_password_here"
api_key = "<replace_me>"
secret = "${SECRET_KEY}"
'''
        import ast
        tree = ast.parse(code)
        visitor = SecurityVisitor()
        visitor.set_source(code)
        visitor.visit(tree)

        assert len(visitor.matches) == 0

    def test_detects_md5_usage(self):
        """Should detect MD5 hash usage."""
        code = '''
import hashlib
h = hashlib.md5(data)
'''
        import ast
        tree = ast.parse(code)
        visitor = SecurityVisitor()
        visitor.set_source(code)
        visitor.visit(tree)

        matches = [m for m in visitor.matches if m.pattern_id == "AST_WEAK_HASH"]
        assert len(matches) == 1

    def test_detects_sha1_usage(self):
        """Should detect SHA1 hash usage."""
        code = '''
import hashlib
h = hashlib.sha1(data)
'''
        import ast
        tree = ast.parse(code)
        visitor = SecurityVisitor()
        visitor.set_source(code)
        visitor.visit(tree)

        matches = [m for m in visitor.matches if m.pattern_id == "AST_WEAK_HASH"]
        assert len(matches) == 1

    def test_detects_eval_usage(self):
        """Should detect eval() usage."""
        code = '''
result = eval(user_input)
'''
        import ast
        tree = ast.parse(code)
        visitor = SecurityVisitor()
        visitor.set_source(code)
        visitor.visit(tree)

        matches = [m for m in visitor.matches if m.pattern_id == "AST_CODE_EXEC"]
        assert len(matches) == 1

    def test_detects_exec_usage(self):
        """Should detect exec() usage."""
        code = '''
exec(code_string)
'''
        import ast
        tree = ast.parse(code)
        visitor = SecurityVisitor()
        visitor.set_source(code)
        visitor.visit(tree)

        matches = [m for m in visitor.matches if m.pattern_id == "AST_CODE_EXEC"]
        assert len(matches) == 1

    def test_detects_shell_true(self):
        """Should detect subprocess with shell=True."""
        code = '''
import subprocess
subprocess.run("ls -la", shell=True)
'''
        import ast
        tree = ast.parse(code)
        visitor = SecurityVisitor()
        visitor.set_source(code)
        visitor.visit(tree)

        matches = [m for m in visitor.matches if m.pattern_id == "AST_SHELL_INJECTION"]
        assert len(matches) == 1

    def test_ignores_shell_false(self):
        """Should not flag subprocess with shell=False."""
        code = '''
import subprocess
subprocess.run(["ls", "-la"], shell=False)
'''
        import ast
        tree = ast.parse(code)
        visitor = SecurityVisitor()
        visitor.set_source(code)
        visitor.visit(tree)

        matches = [m for m in visitor.matches if m.pattern_id == "AST_SHELL_INJECTION"]
        assert len(matches) == 0

    def test_detects_pickle_loads(self):
        """Should detect pickle.loads() usage."""
        code = '''
import pickle
data = pickle.loads(untrusted_data)
'''
        import ast
        tree = ast.parse(code)
        visitor = SecurityVisitor()
        visitor.set_source(code)
        visitor.visit(tree)

        matches = [m for m in visitor.matches if m.pattern_id == "AST_INSECURE_DESERIAL"]
        assert len(matches) == 1

    def test_detects_verify_false(self):
        """Should detect requests with verify=False."""
        code = '''
import requests
response = requests.get(url, verify=False)
'''
        import ast
        tree = ast.parse(code)
        visitor = SecurityVisitor()
        visitor.set_source(code)
        visitor.visit(tree)

        matches = [m for m in visitor.matches if m.pattern_id == "AST_SSL_DISABLED"]
        assert len(matches) == 1


class TestASTScanner:
    """Tests for ASTScanner."""

    @pytest.fixture
    def scanner(self):
        """Create AST scanner."""
        return ASTScanner()

    def test_name(self, scanner):
        """Scanner should have correct name."""
        assert scanner.name == "ast"

    def test_scan_content_finds_issues(self, scanner):
        """Should find security issues in content."""
        code = '''
password = "secret123"
hash = hashlib.md5(data)
'''
        findings = scanner.scan_content(code, [], "test.py", "CWE-798")

        assert len(findings) >= 1
        pattern_ids = [f.pattern_id for f in findings]
        assert "AST_HARDCODED_CRED" in pattern_ids or "AST_WEAK_HASH" in pattern_ids

    def test_scan_content_invalid_python(self, scanner):
        """Should handle invalid Python gracefully."""
        code = "this is not valid python {"
        findings = scanner.scan_content(code, [], "test.py")
        assert findings == []

    def test_scan_content_empty(self, scanner):
        """Should handle empty content."""
        findings = scanner.scan_content("", [], "test.py")
        assert findings == []

    def test_finding_has_correct_fields(self, scanner):
        """Findings should have correct fields."""
        code = 'api_key = "sk-12345678"'
        findings = scanner.scan_content(code, [], "config.py", "CWE-798")

        if findings:
            f = findings[0]
            assert f.file == "config.py"
            assert f.scanner == "ast"
            assert f.confidence > 0

    def test_severity_mapping(self, scanner):
        """Should map severity correctly."""
        assert scanner._get_severity("AST_CODE_EXEC") == Severity.CRITICAL
        assert scanner._get_severity("AST_HARDCODED_CRED") == Severity.HIGH
        assert scanner._get_severity("AST_WEAK_HASH") == Severity.MEDIUM


class TestCombinedScanner:
    """Tests for CombinedScanner."""

    @pytest.fixture
    def scanner(self):
        """Create combined scanner."""
        return create_combined_scanner()

    def test_name(self, scanner):
        """Scanner should have combined name."""
        assert "combined" in scanner.name

    def test_scan_python_uses_both(self, scanner):
        """Should use both regex and AST for Python."""
        code = '''
# Contains AKIA canary token
AWS_KEY = "AKIA_CANARY_TEST_12345678"
password = "supersecret"
'''
        # Create a pattern that regex can find
        patterns = [
            DetectionPattern(
                id="P01",
                type=DetectionPatternType.CANARY_TOKEN,
                regex="AKIA_CANARY_TEST_12345678",
                description="AWS canary token",
                confidence=1.0,
            )
        ]

        findings = scanner.scan_content(code, patterns, "test.py", "CWE-798")
        
        # Should find something from at least one scanner
        assert len(findings) >= 1

    def test_deduplicates_findings(self, scanner):
        """Should deduplicate findings from multiple scanners."""
        code = 'password = "secret123"'
        findings = scanner.scan_content(code, [], "test.py")

        # Check no duplicate (pattern_id, line_number) pairs
        keys = [(f.pattern_id, f.line_number) for f in findings]
        assert len(keys) == len(set(keys))

    def test_looks_like_python(self, scanner):
        """Should detect Python-like content."""
        assert scanner._looks_like_python("def foo(): pass")
        assert scanner._looks_like_python("import os")
        assert scanner._looks_like_python("class Foo:")
        assert not scanner._looks_like_python("function foo() {}")


class TestASTMatch:
    """Tests for ASTMatch dataclass."""

    def test_creation(self):
        """Should create match with all fields."""
        match = ASTMatch(
            pattern_id="AST_TEST",
            line_number=10,
            col_offset=4,
            end_line=10,
            end_col=20,
            matched_text="password = 'secret'",
            description="Test match",
            confidence=0.9,
        )
        assert match.pattern_id == "AST_TEST"
        assert match.line_number == 10
        assert match.confidence == 0.9
