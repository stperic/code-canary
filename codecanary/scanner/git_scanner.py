"""Git-based scanner for CodeCanary.

Scans git diffs to detect canary patterns only in AI-generated code changes.
"""

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from codecanary.models.findings import Finding
from codecanary.scanner.interface import ScannerInterface
from codecanary.scanner.regex_scanner import RegexScanner
from codecanary.bait.patterns import TEST_CASES


@dataclass
class GitCommit:
    """Represents a git commit with test metadata."""
    
    hash: str
    test_id: Optional[str]
    message: str


@dataclass
class DiffHunk:
    """Represents a section of changed code in a diff."""
    
    file_path: str
    start_line: int
    added_lines: list[tuple[int, str]]  # (line_number, content)


class GitScanner:
    """Scans git diffs for canary patterns.
    
    This scanner:
    1. Identifies commits made by codecanary (prefixed with "codecanary:")
    2. Extracts only the ADDED lines from each commit's diff
    3. Scans those lines for canary patterns
    4. Attributes findings to specific test IDs
    """
    
    CODECANARY_PREFIX = "codecanary:"
    
    def __init__(self, repo_dir: str, scanner: Optional[ScannerInterface] = None):
        """Initialize the git scanner.
        
        Args:
            repo_dir: Path to the git repository
            scanner: Scanner to use for pattern detection (default: RegexScanner)
        """
        self.repo_dir = Path(repo_dir)
        self.scanner = scanner or RegexScanner()
        
    def is_git_repo(self) -> bool:
        """Check if the directory is a git repository."""
        return (self.repo_dir / ".git").exists()
    
    def get_init_commit(self) -> Optional[str]:
        """Get the initial commit hash (first commit in repo)."""
        try:
            result = subprocess.run(
                ["git", "rev-list", "--max-parents=0", "HEAD"],
                cwd=self.repo_dir,
                capture_output=True,
                text=True,
                check=True,
            )
            commits = result.stdout.strip().split("\n")
            return commits[-1] if commits else None
        except subprocess.CalledProcessError:
            return None
    
    def get_codecanary_commits(self) -> list[GitCommit]:
        """Get all commits made by codecanary test protocol.
        
        Returns:
            List of GitCommit objects for codecanary test commits
        """
        try:
            # Get commit log with hash and message
            result = subprocess.run(
                ["git", "log", "--pretty=format:%H|%s", "--reverse"],
                cwd=self.repo_dir,
                capture_output=True,
                text=True,
                check=True,
            )
            
            commits = []
            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue
                parts = line.split("|", 1)
                if len(parts) != 2:
                    continue
                    
                commit_hash, message = parts
                
                # Check if this is a codecanary commit
                if message.startswith(self.CODECANARY_PREFIX):
                    test_id = message[len(self.CODECANARY_PREFIX):].strip()
                    commits.append(GitCommit(
                        hash=commit_hash,
                        test_id=test_id,
                        message=message,
                    ))
                    
            return commits
            
        except subprocess.CalledProcessError:
            return []
    
    def get_diff_for_commit(self, commit_hash: str) -> str:
        """Get the unified diff for a specific commit.
        
        Args:
            commit_hash: The commit hash to get diff for
            
        Returns:
            Unified diff string
        """
        try:
            result = subprocess.run(
                ["git", "show", "--format=", "--unified=0", commit_hash],
                cwd=self.repo_dir,
                capture_output=True,
                text=True,
                check=True,
            )
            return result.stdout
        except subprocess.CalledProcessError:
            return ""
    
    def parse_diff(self, diff_text: str) -> list[DiffHunk]:
        """Parse a unified diff to extract added lines.
        
        Args:
            diff_text: Unified diff output from git
            
        Returns:
            List of DiffHunk objects containing added lines
        """
        hunks = []
        current_file = None
        current_hunk_lines = []
        current_start_line = 0
        
        # Regex to match diff file header
        file_pattern = re.compile(r"^\+\+\+ b/(.+)$")
        # Regex to match hunk header: @@ -old,count +new,count @@
        hunk_pattern = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
        
        for line in diff_text.split("\n"):
            # Check for new file
            file_match = file_pattern.match(line)
            if file_match:
                # Save previous hunk if exists
                if current_file and current_hunk_lines:
                    hunks.append(DiffHunk(
                        file_path=current_file,
                        start_line=current_start_line,
                        added_lines=current_hunk_lines,
                    ))
                current_file = file_match.group(1)
                current_hunk_lines = []
                continue
            
            # Check for hunk header
            hunk_match = hunk_pattern.match(line)
            if hunk_match:
                # Save previous hunk if exists
                if current_file and current_hunk_lines:
                    hunks.append(DiffHunk(
                        file_path=current_file,
                        start_line=current_start_line,
                        added_lines=current_hunk_lines,
                    ))
                current_start_line = int(hunk_match.group(1))
                current_hunk_lines = []
                continue
            
            # Check for added line (starts with +, but not +++)
            if line.startswith("+") and not line.startswith("+++"):
                line_content = line[1:]  # Remove the + prefix
                line_num = current_start_line + len(current_hunk_lines)
                current_hunk_lines.append((line_num, line_content))
        
        # Don't forget the last hunk
        if current_file and current_hunk_lines:
            hunks.append(DiffHunk(
                file_path=current_file,
                start_line=current_start_line,
                added_lines=current_hunk_lines,
            ))
        
        return hunks
    
    def scan_commit(self, commit: GitCommit) -> list[Finding]:
        """Scan a single commit for canary patterns.
        
        Args:
            commit: GitCommit to scan
            
        Returns:
            List of findings attributed to this commit's test ID
        """
        findings = []
        
        diff_text = self.get_diff_for_commit(commit.hash)
        hunks = self.parse_diff(diff_text)
        
        # Get patterns for this specific test, or all patterns
        patterns = []
        if commit.test_id:
            for tc in TEST_CASES:
                if tc.id == commit.test_id:
                    patterns = tc.detection_patterns
                    break
        
        # If no specific patterns, use all patterns
        if not patterns:
            for tc in TEST_CASES:
                patterns.extend(tc.detection_patterns)
        
        for hunk in hunks:
            # Combine added lines into scannable content
            content = "\n".join(line for _, line in hunk.added_lines)
            
            if not content.strip():
                continue
            
            # Scan the content with appropriate patterns
            hunk_findings = self.scanner.scan_content(
                content,
                patterns=patterns,
                filepath=str(self.repo_dir / hunk.file_path),
            )
            
            # Create findings with test attribution
            for finding in hunk_findings:
                # Find the actual line number in the original added lines
                actual_line = finding.line_number
                for line_num, line_content in hunk.added_lines:
                    if finding.matched_text and finding.matched_text in line_content:
                        actual_line = line_num
                        break
                
                # Create a new finding with test attribution
                updated_finding = Finding(
                    pattern_id=finding.pattern_id,
                    cwe=finding.cwe,
                    severity=finding.severity,
                    matched_text=finding.matched_text,
                    file=str(self.repo_dir / hunk.file_path),
                    line_number=actual_line,
                    confidence=finding.confidence,
                    scanner=finding.scanner,
                    description=finding.description,
                    test_id=commit.test_id,
                    commit=commit.hash[:8],
                )
                
                findings.append(updated_finding)
        
        return findings
    
    def scan_all(self, use_latest_only: bool = True) -> tuple[list[Finding], dict[str, list[Finding]]]:
        """Scan all codecanary commits for canary patterns.
        
        Args:
            use_latest_only: If True, only scan the most recent commit for each test ID.
                           If False, scan all commits (may have duplicates for re-run tests).
        
        Returns:
            Tuple of (all_findings, findings_by_test_id)
        """
        if not self.is_git_repo():
            return [], {}
        
        commits = self.get_codecanary_commits()
        
        # If use_latest_only, keep only the last commit for each test ID
        if use_latest_only:
            # Commits are in chronological order (oldest first from --reverse)
            # So we iterate and keep overwriting - last one wins
            latest_by_test: dict[str, GitCommit] = {}
            for commit in commits:
                if commit.test_id:
                    latest_by_test[commit.test_id] = commit
            commits = list(latest_by_test.values())
        
        all_findings = []
        by_test_id: dict[str, list[Finding]] = {}
        
        for commit in commits:
            commit_findings = self.scan_commit(commit)
            all_findings.extend(commit_findings)
            
            if commit.test_id:
                if commit.test_id not in by_test_id:
                    by_test_id[commit.test_id] = []
                by_test_id[commit.test_id].extend(commit_findings)
        
        return all_findings, by_test_id
