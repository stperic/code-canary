"""Tests for bait generation module."""

import pytest
from pathlib import Path

from codecanary.bait.generator import BaitGenerator
from codecanary.bait.patterns import TEST_CASES, get_test_cases, get_test_case_by_id


class TestBaitPatterns:
    """Tests for bait patterns."""

    def test_all_test_cases_present(self):
        """Should have at least 8 test cases (more with extended patterns)."""
        # Phase 1: 8 Python test cases
        # Phase 2: +12 extended Python, +8 JS, +8 Go = 36 total
        assert len(TEST_CASES) >= 8

    def test_test_case_ids_unique(self):
        """Test case IDs should be unique."""
        ids = [tc.id for tc in TEST_CASES]
        assert len(ids) == len(set(ids))

    def test_get_test_case_by_id(self):
        """Should retrieve test case by ID."""
        tc = get_test_case_by_id("T01_AWS_CREDS")
        assert tc is not None
        assert tc.cwe == "CWE-798"

    def test_get_test_case_by_id_not_found(self):
        """Should return None for unknown ID."""
        tc = get_test_case_by_id("UNKNOWN")
        assert tc is None

    def test_all_cases_have_bait_files(self):
        """All test cases should have at least one bait file."""
        for tc in TEST_CASES:
            assert len(tc.bait_files) >= 1
            for bf in tc.bait_files:
                assert bf.path
                assert bf.content

    def test_all_cases_have_detection_patterns(self):
        """All test cases should have detection patterns."""
        for tc in TEST_CASES:
            assert len(tc.detection_patterns) >= 1
            for dp in tc.detection_patterns:
                assert dp.id
                assert dp.regex


class TestBaitGenerator:
    """Tests for BaitGenerator."""

    def test_generate_creates_directory(self, temp_dir):
        """Generator should create output directory."""
        output = temp_dir / "bait"
        generator = BaitGenerator(output_dir=str(output), init_git=False)
        path = generator.generate()

        assert path.exists()
        assert path.is_dir()

    def test_generate_creates_bait_files(self, temp_dir):
        """Generator should create bait files."""
        output = temp_dir / "bait"
        generator = BaitGenerator(output_dir=str(output), init_git=False)
        generator.generate()

        # Check for config/secrets.env.example
        secrets_file = output / "config" / "secrets.env.example"
        assert secrets_file.exists()

        # Check content contains canary token
        content = secrets_file.read_text()
        assert "AKIA_CANARY_TEST" in content

    def test_generate_creates_prompts_yaml(self, temp_dir):
        """Generator should create prompts.yaml."""
        output = temp_dir / "bait"
        generator = BaitGenerator(output_dir=str(output), init_git=False)
        generator.generate()

        prompts_file = output / "prompts.yaml"
        assert prompts_file.exists()

    def test_generate_creates_readme(self, temp_dir):
        """Generator should create README."""
        output = temp_dir / "bait"
        generator = BaitGenerator(output_dir=str(output), init_git=False)
        generator.generate()

        readme = output / "README.md"
        assert readme.exists()

    def test_generate_creates_guardrails_template(self, temp_dir):
        """Generator should create guardrails templates."""
        output = temp_dir / "bait"
        generator = BaitGenerator(output_dir=str(output), init_git=False)
        generator.generate()

        guardrails_dir = output / ".codecanary"
        assert guardrails_dir.exists()
        assert (guardrails_dir / "cursorrules.txt").exists()

    def test_generate_fails_if_exists(self, temp_dir):
        """Generator should fail if directory exists."""
        output = temp_dir / "bait"
        output.mkdir()

        generator = BaitGenerator(output_dir=str(output), init_git=False)
        with pytest.raises(FileExistsError):
            generator.generate()

    def test_generate_force_overwrites(self, temp_dir):
        """Generator should overwrite with force=True."""
        output = temp_dir / "bait"
        output.mkdir()
        (output / "old_file.txt").touch()

        generator = BaitGenerator(output_dir=str(output), init_git=False)
        generator.generate(force=True)

        assert not (output / "old_file.txt").exists()
        assert (output / "README.md").exists()

    def test_test_case_ids_property(self, temp_dir):
        """Generator should expose test case IDs."""
        output = temp_dir / "bait"
        generator = BaitGenerator(output_dir=str(output), init_git=False)
        generator.generate()

        ids = generator.test_case_ids
        # Should have at least the 8 core Python test cases
        assert len(ids) >= 8
        assert "T01_AWS_CREDS" in ids
