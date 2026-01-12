"""Run manifest creation utilities."""

from pathlib import Path
import subprocess
from typing import Optional

from codecanary.models.run_manifest import (
    RunManifest,
    AssistantConfig,
    GuardrailsConfig,
    BaitConfig,
    ExecutionConfig,
    EnvironmentInfo,
)
from codecanary.bait.patterns import TEST_CASES


def create_manifest(
    assistant: str,
    model: Optional[str] = None,
    guardrails_enabled: bool = False,
    guardrails_file: Optional[str] = None,
    bait_dir: str = "./bait_repo",
    operator: Optional[str] = None,
) -> RunManifest:
    """Create a run manifest for a test run.

    Args:
        assistant: AI assistant name (cursor, copilot, windsurf, etc.)
        model: Model name (e.g., claude-3.5-sonnet)
        guardrails_enabled: Whether guardrails are enabled
        guardrails_file: Path to guardrails file (e.g., .cursorrules)
        bait_dir: Path to bait repository
        operator: Who is running the test

    Returns:
        RunManifest with all configuration
    """
    bait_path = Path(bait_dir)

    # Get git commit hash if available
    commit_hash = _get_commit_hash(bait_path)

    # Get test case IDs from bait repo
    test_case_ids = [tc.id for tc in TEST_CASES]

    # Build guardrails config
    if guardrails_enabled and guardrails_file:
        guardrails = GuardrailsConfig.from_file(guardrails_file)
    elif guardrails_enabled:
        # Look for guardrails file in bait repo
        for gf in [".cursorrules", ".github/copilot-instructions.md", ".windsurfrules"]:
            gf_path = bait_path / gf
            if gf_path.exists():
                guardrails = GuardrailsConfig.from_file(str(gf_path))
                break
        else:
            guardrails = GuardrailsConfig(enabled=True)
    else:
        guardrails = GuardrailsConfig.disabled()

    return RunManifest(
        environment=EnvironmentInfo.from_current(),
        assistant=AssistantConfig(
            name=assistant,
            model=model,
        ),
        guardrails=guardrails,
        bait=BaitConfig(
            commit_hash=commit_hash or "unknown",
            test_case_ids=test_case_ids,
        ),
        execution=ExecutionConfig(
            operator=operator,
        ),
    )


def _get_commit_hash(bait_path: Path) -> Optional[str]:
    """Get git commit hash of bait repo.

    Args:
        bait_path: Path to bait repository

    Returns:
        Commit hash or None if not a git repo
    """
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=bait_path,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    return None
