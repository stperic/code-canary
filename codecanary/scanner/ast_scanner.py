"""AST-based scanner for Python code analysis.

Provides more accurate detection than regex by understanding code structure.
"""

import ast
import logging
from typing import Optional
from dataclasses import dataclass

from codecanary.scanner.interface import ScannerInterface
from codecanary.models.findings import Finding
from codecanary.models.enums import Severity
from codecanary.models.test_case import DetectionPattern, DetectionPatternType

logger = logging.getLogger(__name__)


@dataclass
class ASTMatch:
    """A match found by AST analysis."""

    pattern_id: str
    line_number: int
    col_offset: int
    end_line: int
    end_col: int
    matched_text: str
    description: str
    confidence: float


class SecurityVisitor(ast.NodeVisitor):
    """AST visitor that detects security issues."""

    def __init__(self):
        self.matches: list[ASTMatch] = []
        self._source_lines: list[str] = []

    def set_source(self, source: str) -> None:
        """Set source code for snippet extraction."""
        self._source_lines = source.split("\n")

    def _get_source_line(self, lineno: int) -> str:
        """Get source line by line number (1-indexed)."""
        if 1 <= lineno <= len(self._source_lines):
            return self._source_lines[lineno - 1]
        return ""

    def _add_match(
        self,
        node: ast.AST,
        pattern_id: str,
        description: str,
        confidence: float = 0.8,
    ) -> None:
        """Add a security match."""
        lineno = getattr(node, "lineno", 0)
        col_offset = getattr(node, "col_offset", 0)
        end_lineno = getattr(node, "end_lineno", lineno)
        end_col = getattr(node, "end_col_offset", col_offset)

        matched_text = self._get_source_line(lineno)

        self.matches.append(
            ASTMatch(
                pattern_id=pattern_id,
                line_number=lineno,
                col_offset=col_offset,
                end_line=end_lineno,
                end_col=end_col,
                matched_text=matched_text,
                description=description,
                confidence=confidence,
            )
        )

    # =========================================================================
    # Credential Hardcoding Detection (CWE-798)
    # =========================================================================

    def visit_Assign(self, node: ast.Assign) -> None:
        """Check for hardcoded credentials in assignments."""
        for target in node.targets:
            if isinstance(target, ast.Name):
                name_lower = target.id.lower()
                if self._is_credential_name(name_lower):
                    # Check if assigned to a string literal
                    if isinstance(node.value, ast.Constant) and isinstance(
                        node.value.value, str
                    ):
                        value = node.value.value
                        if len(value) > 5 and not self._is_placeholder(value):
                            self._add_match(
                                node,
                                "AST_HARDCODED_CRED",
                                f"Hardcoded credential: {target.id}",
                                confidence=0.9,
                            )
        self.generic_visit(node)

    def _is_credential_name(self, name: str) -> bool:
        """Check if variable name suggests credentials."""
        sensitive = [
            "password", "passwd", "pwd", "secret", "api_key", "apikey",
            "token", "auth", "credential", "private_key", "access_key",
            "secret_key", "aws_key", "db_password", "database_password",
        ]
        return any(s in name for s in sensitive)

    def _is_placeholder(self, value: str) -> bool:
        """Check if value is a placeholder."""
        placeholders = [
            "xxx", "your_", "placeholder", "changeme", "todo",
            "replace", "example", "<", ">", "${", "{{",
        ]
        value_lower = value.lower()
        return any(p in value_lower for p in placeholders)

    # =========================================================================
    # Weak Cryptography Detection (CWE-327, CWE-328)
    # =========================================================================

    def visit_Call(self, node: ast.Call) -> None:
        """Check for insecure function calls."""
        func_name = self._get_func_name(node.func)

        # Check for weak hash functions
        if func_name in ("hashlib.md5", "hashlib.sha1", "md5", "sha1"):
            self._add_match(
                node,
                "AST_WEAK_HASH",
                f"Weak hash function: {func_name}",
                confidence=0.95,
            )

        # Check for eval/exec
        if func_name in ("eval", "exec"):
            self._add_match(
                node,
                "AST_CODE_EXEC",
                f"Dangerous function: {func_name}",
                confidence=0.9,
            )

        # Check for shell=True in subprocess
        if func_name in (
            "subprocess.call", "subprocess.run", "subprocess.Popen",
            "os.system", "os.popen",
        ):
            if self._has_shell_true(node):
                self._add_match(
                    node,
                    "AST_SHELL_INJECTION",
                    "subprocess with shell=True",
                    confidence=0.85,
                )

        # Check for pickle.loads (insecure deserialization)
        if func_name in ("pickle.loads", "pickle.load", "cPickle.loads"):
            self._add_match(
                node,
                "AST_INSECURE_DESERIAL",
                f"Insecure deserialization: {func_name}",
                confidence=0.9,
            )

        # Check for insecure random
        if func_name in ("random.random", "random.randint", "random.choice"):
            # Check context - might be security-sensitive
            pass  # Would need context analysis

        # Check for requests without verify
        if func_name in ("requests.get", "requests.post", "requests.put"):
            if self._has_verify_false(node):
                self._add_match(
                    node,
                    "AST_SSL_DISABLED",
                    "SSL verification disabled",
                    confidence=0.95,
                )

        self.generic_visit(node)

    def _get_func_name(self, node: ast.expr) -> str:
        """Get full function name from Call node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            value_name = self._get_func_name(node.value)
            return f"{value_name}.{node.attr}" if value_name else node.attr
        return ""

    def _has_shell_true(self, node: ast.Call) -> bool:
        """Check if call has shell=True."""
        for keyword in node.keywords:
            if keyword.arg == "shell":
                if isinstance(keyword.value, ast.Constant):
                    return keyword.value.value is True
        return False

    def _has_verify_false(self, node: ast.Call) -> bool:
        """Check if call has verify=False."""
        for keyword in node.keywords:
            if keyword.arg == "verify":
                if isinstance(keyword.value, ast.Constant):
                    return keyword.value.value is False
        return False

    # =========================================================================
    # SQL Injection Detection (CWE-89)
    # =========================================================================

    def visit_BinOp(self, node: ast.BinOp) -> None:
        """Check for string concatenation in SQL queries."""
        if isinstance(node.op, (ast.Add, ast.Mod)):
            # Check if this looks like SQL
            if self._might_be_sql(node):
                self._add_match(
                    node,
                    "AST_SQL_INJECTION",
                    "Potential SQL injection via string concatenation",
                    confidence=0.7,  # Lower confidence - needs context
                )
        self.generic_visit(node)

    def _might_be_sql(self, node: ast.BinOp) -> bool:
        """Check if binary operation might be SQL query building."""
        # Check left side for SQL keywords
        if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
            sql_keywords = ["SELECT", "INSERT", "UPDATE", "DELETE", "WHERE", "FROM"]
            value_upper = node.left.value.upper()
            return any(kw in value_upper for kw in sql_keywords)
        return False


class ASTScanner(ScannerInterface):
    """AST-based scanner for Python code.

    Advantages over regex:
    - Understands code structure
    - Fewer false positives
    - Can detect obfuscated patterns
    - Semantic analysis possible

    Limitations:
    - Python only
    - Cannot scan invalid Python
    - May miss dynamically constructed patterns
    """

    @property
    def name(self) -> str:
        return "ast"

    def scan_content(
        self,
        content: str,
        patterns: list[DetectionPattern],
        filepath: str = "<unknown>",
        cwe: Optional[str] = None,
    ) -> list[Finding]:
        """Scan Python content using AST analysis.

        Args:
            content: Python source code
            patterns: Detection patterns (used for context/filtering)
            filepath: Path for reporting
            cwe: CWE to associate with findings

        Returns:
            List of findings
        """
        findings: list[Finding] = []

        # Parse AST
        try:
            tree = ast.parse(content, filename=filepath)
        except SyntaxError as e:
            logger.debug(f"Cannot parse {filepath}: {e}")
            return findings  # Return empty - can't analyze invalid Python

        # Run security visitor
        visitor = SecurityVisitor()
        visitor.set_source(content)
        visitor.visit(tree)

        # Convert AST matches to Findings
        for match in visitor.matches:
            # Check if this match is relevant to any of our patterns
            relevant = self._is_relevant_match(match, patterns)
            if relevant or not patterns:  # If no patterns, report all
                findings.append(
                    Finding(
                        pattern_id=match.pattern_id,
                        cwe=cwe or "CWE-unknown",
                        severity=self._get_severity(match.pattern_id),
                        matched_text=match.matched_text[:100],
                        file=filepath,
                        line_number=match.line_number,
                        confidence=match.confidence,
                        scanner=self.name,
                        description=match.description,
                    )
                )

        return findings

    def _is_relevant_match(
        self, match: ASTMatch, patterns: list[DetectionPattern]
    ) -> bool:
        """Check if AST match is relevant to detection patterns."""
        # Map AST pattern IDs to categories
        category_map = {
            "AST_HARDCODED_CRED": ["credential", "secret", "password", "key"],
            "AST_WEAK_HASH": ["md5", "sha1", "hash", "crypto"],
            "AST_CODE_EXEC": ["eval", "exec", "injection"],
            "AST_SHELL_INJECTION": ["shell", "command", "subprocess"],
            "AST_INSECURE_DESERIAL": ["pickle", "deserial", "marshal"],
            "AST_SSL_DISABLED": ["ssl", "verify", "tls", "certificate"],
            "AST_SQL_INJECTION": ["sql", "query", "database"],
        }

        keywords = category_map.get(match.pattern_id, [])
        if not keywords:
            return True  # Unknown pattern - include it

        for pattern in patterns:
            pattern_text = (pattern.id + pattern.description).lower()
            if any(kw in pattern_text for kw in keywords):
                return True

        return False

    def _get_severity(self, pattern_id: str) -> Severity:
        """Get severity for an AST pattern ID."""
        severity_map = {
            "AST_HARDCODED_CRED": Severity.HIGH,
            "AST_WEAK_HASH": Severity.MEDIUM,
            "AST_CODE_EXEC": Severity.CRITICAL,
            "AST_SHELL_INJECTION": Severity.HIGH,
            "AST_INSECURE_DESERIAL": Severity.HIGH,
            "AST_SSL_DISABLED": Severity.HIGH,
            "AST_SQL_INJECTION": Severity.HIGH,
        }
        return severity_map.get(pattern_id, Severity.MEDIUM)

    def scan_file(self, filepath: str, patterns: list[DetectionPattern]) -> list[Finding]:
        """Scan a Python file.

        Args:
            filepath: Path to Python file
            patterns: Detection patterns

        Returns:
            List of findings
        """
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
        except (OSError, UnicodeDecodeError) as e:
            logger.debug(f"Cannot read {filepath}: {e}")
            return []

        # Infer CWE from patterns if available
        cwe = None
        if patterns:
            cwe = patterns[0].id.split("_")[0] if "_" in patterns[0].id else None

        return self.scan_content(content, patterns, filepath, cwe)


def create_combined_scanner() -> "CombinedScanner":
    """Create a scanner that combines regex and AST analysis."""
    from codecanary.scanner.regex_scanner import RegexScanner

    return CombinedScanner(regex=RegexScanner(), ast=ASTScanner())


class CombinedScanner(ScannerInterface):
    """Scanner that combines regex and AST analysis.

    Uses AST for Python files, regex for everything else.
    Deduplicates findings from both scanners.
    """

    def __init__(self, regex: ScannerInterface, ast: ScannerInterface):
        """Initialize combined scanner.

        Args:
            regex: Regex scanner instance
            ast: AST scanner instance
        """
        self.regex = regex
        self.ast = ast

    @property
    def name(self) -> str:
        return "combined"

    def scan_content(
        self,
        content: str,
        patterns: list[DetectionPattern],
        filepath: str = "<unknown>",
        cwe: Optional[str] = None,
    ) -> list[Finding]:
        """Scan content with both regex and AST.

        Args:
            content: File content
            patterns: Detection patterns
            filepath: Path for reporting
            cwe: CWE identifier

        Returns:
            Deduplicated findings from both scanners
        """
        findings: list[Finding] = []

        # Always run regex
        regex_findings = self.regex.scan_content(content, patterns, filepath, cwe)
        findings.extend(regex_findings)

        # Run AST for Python files
        if filepath.endswith(".py") or self._looks_like_python(content):
            ast_findings = self.ast.scan_content(content, patterns, filepath, cwe)
            findings.extend(ast_findings)

        # Deduplicate by (pattern_id, line_number)
        seen: set[tuple[str, int]] = set()
        unique_findings: list[Finding] = []
        for f in findings:
            key = (f.pattern_id, f.line_number)
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        return unique_findings

    def _looks_like_python(self, content: str) -> bool:
        """Heuristic check if content looks like Python."""
        python_indicators = ["def ", "import ", "class ", "print(", "if __name__"]
        return any(indicator in content for indicator in python_indicators)
