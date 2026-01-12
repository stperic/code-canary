"""End-to-end integration tests for CodeCanary."""

import os
import json
import tempfile
import shutil
from pathlib import Path

import pytest
from click.testing import CliRunner

from codecanary.cli import cli


class TestFullWorkflow:
    """Integration tests for complete CodeCanary workflow."""

    @pytest.fixture
    def temp_workspace(self):
        """Create a temporary workspace directory."""
        tmpdir = tempfile.mkdtemp()
        yield Path(tmpdir)
        shutil.rmtree(tmpdir, ignore_errors=True)

    @pytest.fixture
    def runner(self):
        """Create a CLI runner."""
        return CliRunner()

    def test_init_creates_bait_repo(self, runner, temp_workspace):
        """codecanary init should create a valid bait repository."""
        bait_dir = temp_workspace / "bait_repo"

        result = runner.invoke(cli, ["init", "--output", str(bait_dir)])

        assert result.exit_code == 0, f"Failed: {result.output}"
        assert bait_dir.exists()
        assert (bait_dir / "config" / "secrets.env.example").exists()
        assert (bait_dir / "prompts.yaml").exists()
        assert (bait_dir / "README.md").exists()

    def test_init_with_no_git(self, runner, temp_workspace):
        """codecanary init --no-git should skip Git initialization."""
        bait_dir = temp_workspace / "bait_no_git"

        result = runner.invoke(cli, ["init", "--output", str(bait_dir), "--no-git"])

        assert result.exit_code == 0, f"Failed: {result.output}"
        assert bait_dir.exists()
        # Should NOT have .git directory
        assert not (bait_dir / ".git").exists()

    def test_init_fails_if_exists(self, runner, temp_workspace):
        """codecanary init should fail if directory exists."""
        bait_dir = temp_workspace / "existing"
        bait_dir.mkdir()

        result = runner.invoke(cli, ["init", "--output", str(bait_dir)])

        assert result.exit_code == 1
        assert "Error" in result.output

    def test_init_force_overwrites(self, runner, temp_workspace):
        """codecanary init --force should overwrite existing directory."""
        bait_dir = temp_workspace / "overwrite"
        bait_dir.mkdir()
        (bait_dir / "old_file.txt").write_text("old content")

        result = runner.invoke(cli, ["init", "--output", str(bait_dir), "--force"])

        assert result.exit_code == 0, f"Failed: {result.output}"
        assert not (bait_dir / "old_file.txt").exists()
        assert (bait_dir / "prompts.yaml").exists()

    def test_scan_empty_directory(self, runner, temp_workspace):
        """codecanary scan on empty directory should succeed with no findings."""
        responses_dir = temp_workspace / "responses"
        responses_dir.mkdir()
        results_dir = temp_workspace / "results"

        result = runner.invoke(cli, [
            "scan",
            "--input", str(responses_dir),
            "--output", str(results_dir / "findings.json"),
        ])

        assert result.exit_code == 0, f"Failed: {result.output}"
        assert (results_dir / "findings.json").exists()

        # Verify findings JSON structure
        findings = json.loads((results_dir / "findings.json").read_text())
        assert "findings" in findings
        assert len(findings["findings"]) == 0

    def test_scan_detects_canary_token(self, runner, temp_workspace):
        """codecanary scan should detect canary tokens in responses."""
        responses_dir = temp_workspace / "responses"
        responses_dir.mkdir()
        results_dir = temp_workspace / "results"

        # Create a response file with a canary token
        (responses_dir / "test_response.py").write_text(
            'aws_key = "AKIA_CANARY_TEST_12345678"\n'
        )

        result = runner.invoke(cli, [
            "scan",
            "--input", str(responses_dir),
            "--output", str(results_dir / "findings.json"),
        ])

        assert result.exit_code == 0, f"Failed: {result.output}"

        findings = json.loads((results_dir / "findings.json").read_text())
        assert len(findings["findings"]) > 0
        assert any("AKIA_CANARY_TEST" in str(f) for f in findings["findings"])

    def test_scan_detects_multiple_patterns(self, runner, temp_workspace):
        """codecanary scan should detect multiple canary patterns."""
        responses_dir = temp_workspace / "responses"
        responses_dir.mkdir()
        results_dir = temp_workspace / "results"

        # Create a response file with multiple patterns
        (responses_dir / "multi_pattern.py").write_text(
            '''
import hashlib

aws_key = "AKIA_CANARY_TEST_12345678"
password_hash = hashlib.md5(password.encode()).hexdigest()
query = f"SELECT * FROM users WHERE id = {user_id}"
'''
        )

        result = runner.invoke(cli, [
            "scan",
            "--input", str(responses_dir),
            "--output", str(results_dir / "findings.json"),
        ])

        assert result.exit_code == 0, f"Failed: {result.output}"

        findings = json.loads((results_dir / "findings.json").read_text())
        assert len(findings["findings"]) >= 2  # At least AWS key and MD5

    def test_report_summary_format(self, runner, temp_workspace):
        """codecanary report --format summary should display human-readable output."""
        # Create findings file
        findings_dir = temp_workspace / "findings"
        findings_dir.mkdir()
        findings_file = findings_dir / "findings.json"
        findings_file.write_text(json.dumps({
            "scan_timestamp": "2026-01-12T00:00:00Z",
            "files_scanned": 1,
            "files_skipped": 0,
            "findings": [],
            "errors": [],
        }))

        result = runner.invoke(cli, [
            "report",
            "--input", str(findings_file),
            "--format", "summary",
        ])

        assert result.exit_code == 0, f"Failed: {result.output}"
        assert "CodeCanary" in result.output or "No findings" in result.output

    def test_full_workflow(self, runner, temp_workspace):
        """Test complete workflow: init -> simulate response -> scan -> report."""
        bait_dir = temp_workspace / "bait_repo"
        responses_dir = temp_workspace / "responses"
        results_dir = temp_workspace / "results"

        # Step 1: Initialize bait repository
        result = runner.invoke(cli, ["init", "--output", str(bait_dir), "--no-git"])
        assert result.exit_code == 0, f"Init failed: {result.output}"

        # Step 2: Simulate AI response (copy bait pattern)
        responses_dir.mkdir()
        (responses_dir / "t01_aws_creds.py").write_text(
            '''# AI-generated code that copied the bait
import os

# Using the hardcoded key from the legacy codebase
AWS_KEY = "AKIA_CANARY_TEST_12345678"

def get_credentials():
    return AWS_KEY
'''
        )

        # Step 3: Scan responses
        result = runner.invoke(cli, [
            "scan",
            "--input", str(responses_dir),
            "--output", str(results_dir / "findings.json"),
        ])
        assert result.exit_code == 0, f"Scan failed: {result.output}"

        # Verify findings
        findings = json.loads((results_dir / "findings.json").read_text())
        assert len(findings["findings"]) > 0

        # Step 4: Generate summary report
        result = runner.invoke(cli, [
            "report",
            "--input", str(results_dir / "findings.json"),
            "--format", "summary",
        ])
        assert result.exit_code == 0, f"Report failed: {result.output}"


class TestCLIHelp:
    """Tests for CLI help and usage."""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_main_help(self, runner):
        """Main CLI should show help."""
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "CodeCanary" in result.output
        assert "init" in result.output
        assert "scan" in result.output
        assert "report" in result.output

    def test_init_help(self, runner):
        """init command should show help."""
        result = runner.invoke(cli, ["init", "--help"])
        assert result.exit_code == 0
        assert "--output" in result.output
        assert "--no-git" in result.output

    def test_scan_help(self, runner):
        """scan command should show help."""
        result = runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--input" in result.output
        assert "--scanner" in result.output

    def test_report_help(self, runner):
        """report command should show help."""
        result = runner.invoke(cli, ["report", "--help"])
        assert result.exit_code == 0
        assert "--format" in result.output
        assert "json" in result.output
        assert "summary" in result.output

    def test_version(self, runner):
        """CLI should show version."""
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "codecanary, version" in result.output


class TestGuardrailsCommand:
    """Tests for guardrails CLI command."""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_guardrails_help(self, runner):
        """guardrails command should show help."""
        result = runner.invoke(cli, ["guardrails", "--help"])
        # Skip if command doesn't exist yet
        if result.exit_code == 2 and "No such command" in result.output:
            pytest.skip("guardrails command not yet implemented")
        assert result.exit_code == 0

    def test_guardrails_list(self, runner):
        """guardrails --list should show available templates."""
        result = runner.invoke(cli, ["guardrails", "--list"])
        if result.exit_code == 2 and "No such command" in result.output:
            pytest.skip("guardrails command not yet implemented")
        assert result.exit_code == 0
        assert "cursor" in result.output.lower() or "copilot" in result.output.lower()
