"""Tests for git-based scanner."""

import subprocess
import tempfile
import shutil
from pathlib import Path

import pytest

from codecanary.scanner.git_scanner import GitScanner, GitCommit, DiffHunk


class TestGitScanner:
    """Tests for GitScanner class."""

    @pytest.fixture
    def temp_git_repo(self):
        """Create a temporary git repository."""
        tmpdir = tempfile.mkdtemp()
        repo_path = Path(tmpdir) / "test_repo"
        repo_path.mkdir()
        
        # Initialize git repo
        subprocess.run(["git", "init"], cwd=repo_path, capture_output=True)
        subprocess.run(
            ["git", "config", "user.email", "test@test.com"],
            cwd=repo_path,
            capture_output=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Test"],
            cwd=repo_path,
            capture_output=True,
        )
        
        # Create initial commit
        (repo_path / "README.md").write_text("# Test Repo")
        subprocess.run(["git", "add", "-A"], cwd=repo_path, capture_output=True)
        subprocess.run(
            ["git", "commit", "-m", "Initial commit"],
            cwd=repo_path,
            capture_output=True,
        )
        
        yield repo_path
        shutil.rmtree(tmpdir, ignore_errors=True)

    def test_is_git_repo(self, temp_git_repo):
        """Test detecting a git repository."""
        scanner = GitScanner(str(temp_git_repo))
        assert scanner.is_git_repo() is True
        
    def test_is_not_git_repo(self):
        """Test detecting non-git directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = GitScanner(tmpdir)
            assert scanner.is_git_repo() is False

    def test_get_init_commit(self, temp_git_repo):
        """Test getting the initial commit."""
        scanner = GitScanner(str(temp_git_repo))
        init_commit = scanner.get_init_commit()
        assert init_commit is not None
        assert len(init_commit) == 40  # Full SHA

    def test_get_codecanary_commits_empty(self, temp_git_repo):
        """Test when there are no codecanary commits."""
        scanner = GitScanner(str(temp_git_repo))
        commits = scanner.get_codecanary_commits()
        assert commits == []

    def test_get_codecanary_commits(self, temp_git_repo):
        """Test detecting codecanary commits."""
        # Add a codecanary commit
        (temp_git_repo / "test.py").write_text('key = "AKIA_CANARY_TEST_12345678"')
        subprocess.run(["git", "add", "-A"], cwd=temp_git_repo, capture_output=True)
        subprocess.run(
            ["git", "commit", "-m", "codecanary: T01_AWS_CREDS"],
            cwd=temp_git_repo,
            capture_output=True,
        )
        
        scanner = GitScanner(str(temp_git_repo))
        commits = scanner.get_codecanary_commits()
        
        assert len(commits) == 1
        assert commits[0].test_id == "T01_AWS_CREDS"
        assert commits[0].message == "codecanary: T01_AWS_CREDS"

    def test_scan_commit_finds_patterns(self, temp_git_repo):
        """Test scanning a commit for canary patterns."""
        # Add a file with canary token
        (temp_git_repo / "creds.py").write_text('aws_key = "AKIA_CANARY_TEST_12345678"\n')
        subprocess.run(["git", "add", "-A"], cwd=temp_git_repo, capture_output=True)
        subprocess.run(
            ["git", "commit", "-m", "codecanary: T01_AWS_CREDS"],
            cwd=temp_git_repo,
            capture_output=True,
        )
        
        scanner = GitScanner(str(temp_git_repo))
        commits = scanner.get_codecanary_commits()
        
        findings = scanner.scan_commit(commits[0])
        
        assert len(findings) >= 1
        assert findings[0].test_id == "T01_AWS_CREDS"

    def test_scan_all(self, temp_git_repo):
        """Test scanning all codecanary commits."""
        # Add first test
        (temp_git_repo / "creds.py").write_text('aws_key = "AKIA_CANARY_TEST_12345678"\n')
        subprocess.run(["git", "add", "-A"], cwd=temp_git_repo, capture_output=True)
        subprocess.run(
            ["git", "commit", "-m", "codecanary: T01_AWS_CREDS"],
            cwd=temp_git_repo,
            capture_output=True,
        )
        
        # Add second test (clean)
        (temp_git_repo / "clean.py").write_text('print("Hello")\n')
        subprocess.run(["git", "add", "-A"], cwd=temp_git_repo, capture_output=True)
        subprocess.run(
            ["git", "commit", "-m", "codecanary: T02_CLEAN"],
            cwd=temp_git_repo,
            capture_output=True,
        )
        
        scanner = GitScanner(str(temp_git_repo))
        all_findings, by_test_id = scanner.scan_all()
        
        assert len(all_findings) >= 1
        assert "T01_AWS_CREDS" in by_test_id
        assert len(by_test_id["T01_AWS_CREDS"]) >= 1


class TestDiffParsing:
    """Tests for diff parsing functionality."""

    def test_parse_diff_added_lines(self):
        """Test parsing added lines from a diff."""
        diff_text = """diff --git a/test.py b/test.py
new file mode 100644
--- /dev/null
+++ b/test.py
@@ -0,0 +1,3 @@
+line1
+line2
+line3
"""
        scanner = GitScanner("/tmp")
        hunks = scanner.parse_diff(diff_text)
        
        assert len(hunks) == 1
        assert hunks[0].file_path == "test.py"
        assert len(hunks[0].added_lines) == 3
        assert hunks[0].added_lines[0] == (1, "line1")
        assert hunks[0].added_lines[1] == (2, "line2")
        assert hunks[0].added_lines[2] == (3, "line3")

    def test_parse_diff_modified_file(self):
        """Test parsing a modified file diff."""
        diff_text = """diff --git a/test.py b/test.py
--- a/test.py
+++ b/test.py
@@ -5,0 +6,2 @@
+new_line1
+new_line2
"""
        scanner = GitScanner("/tmp")
        hunks = scanner.parse_diff(diff_text)
        
        assert len(hunks) == 1
        assert hunks[0].file_path == "test.py"
        # Lines are added at line 6
        assert hunks[0].added_lines[0][0] == 6

    def test_parse_diff_multiple_files(self):
        """Test parsing diff with multiple files."""
        diff_text = """diff --git a/file1.py b/file1.py
--- /dev/null
+++ b/file1.py
@@ -0,0 +1 @@
+content1
diff --git a/file2.py b/file2.py
--- /dev/null
+++ b/file2.py
@@ -0,0 +1 @@
+content2
"""
        scanner = GitScanner("/tmp")
        hunks = scanner.parse_diff(diff_text)
        
        assert len(hunks) == 2
        assert hunks[0].file_path == "file1.py"
        assert hunks[1].file_path == "file2.py"

    def test_parse_diff_ignores_removed_lines(self):
        """Test that removed lines are ignored."""
        diff_text = """diff --git a/test.py b/test.py
--- a/test.py
+++ b/test.py
@@ -1,3 +1,2 @@
-removed_line
+added_line
 unchanged
"""
        scanner = GitScanner("/tmp")
        hunks = scanner.parse_diff(diff_text)
        
        # Should only have the added line
        all_added = [line for hunk in hunks for _, line in hunk.added_lines]
        assert "added_line" in all_added
        assert "removed_line" not in all_added
