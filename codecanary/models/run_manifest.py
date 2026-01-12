"""Canonical RunManifest schema per PRD Section 7.

Every test run produces a manifest for reproducibility.
"""

from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime
import uuid
import hashlib
import platform
import sys

from codecanary.models.enums import PromptDelivery, ResponseCapture
from codecanary import __version__


class EnvironmentInfo(BaseModel):
    """Environment information for reproducibility."""

    os: str = Field(..., description="Operating system (e.g., 'darwin 25.2.0')")
    python_version: str = Field(..., description="Python version")

    @classmethod
    def from_current(cls) -> "EnvironmentInfo":
        """Create from current environment."""
        return cls(
            os=f"{platform.system().lower()} {platform.release()}",
            python_version=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        )


class AssistantConfig(BaseModel):
    """AI assistant configuration."""

    name: str = Field(..., description="Assistant name: cursor, copilot, windsurf, etc.")
    version: Optional[str] = Field(default=None, description="Assistant version")
    model: Optional[str] = Field(default=None, description="Model name (e.g., claude-3.5-sonnet)")
    model_version: Optional[str] = Field(default=None, description="Model version if available")
    settings: dict = Field(
        default_factory=dict,
        description="Relevant settings (temperature, context_window, etc.)",
    )


class GuardrailsConfig(BaseModel):
    """Guardrails configuration."""

    enabled: bool = Field(default=False, description="Whether guardrails are enabled")
    file: Optional[str] = Field(default=None, description="Guardrails file path")
    content_hash: Optional[str] = Field(
        default=None,
        description="SHA256 hash of guardrails content",
    )

    @classmethod
    def from_file(cls, filepath: str) -> "GuardrailsConfig":
        """Create config from guardrails file."""
        with open(filepath, "rb") as f:
            content_hash = hashlib.sha256(f.read()).hexdigest()
        return cls(enabled=True, file=filepath, content_hash=content_hash)

    @classmethod
    def disabled(cls) -> "GuardrailsConfig":
        """Create disabled guardrails config."""
        return cls(enabled=False)


class BaitConfig(BaseModel):
    """Bait repository configuration."""

    commit_hash: str = Field(..., description="Git commit hash of bait repo")
    test_case_ids: list[str] = Field(
        default_factory=list,
        description="Which test cases were executed",
    )
    canary_token_prefix: str = Field(
        default="CANARY",
        description="Prefix used for canary tokens",
    )


class ExecutionConfig(BaseModel):
    """Test execution details."""

    operator: Optional[str] = Field(default=None, description="Who ran the test")
    workspace_clean: bool = Field(
        default=True,
        description="Was workspace reset before test?",
    )
    prompt_delivery: PromptDelivery = Field(
        default=PromptDelivery.CHAT,
        description="How prompts were delivered",
    )
    response_capture: ResponseCapture = Field(
        default=ResponseCapture.MANUAL_COPY,
        description="How responses were captured",
    )


class ResultsSummary(BaseModel):
    """Results summary for the run manifest."""

    total_tests: int = Field(..., description="Total number of tests executed")
    by_status: dict[str, int] = Field(
        default_factory=dict,
        description="Count by status: {clean: 5, partial: 1, poisoned: 1, refused: 1}",
    )
    ctr: float = Field(..., description="Canary Trigger Rate")
    ctr_confidence_interval: tuple[float, float] = Field(
        ...,
        description="95% confidence interval for CTR",
    )
    refusal_rate: float = Field(..., description="Refusal rate")


class RunManifest(BaseModel):
    """Canonical run manifest for reproducibility.

    Per PRD Section 7, every test run produces a manifest that captures
    all metadata needed to reproduce the test.
    """

    # Run Identity
    run_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique run identifier",
    )
    timestamp: datetime = Field(
        default_factory=datetime.utcnow,
        description="When the test was run (ISO 8601)",
    )
    codecanary_version: str = Field(
        default=__version__,
        description="CodeCanary version used",
    )

    # Environment
    environment: EnvironmentInfo = Field(
        default_factory=EnvironmentInfo.from_current,
        description="Environment information",
    )

    # Configuration
    assistant: AssistantConfig = Field(..., description="AI assistant configuration")
    guardrails: GuardrailsConfig = Field(
        default_factory=GuardrailsConfig.disabled,
        description="Guardrails configuration",
    )
    bait: BaitConfig = Field(..., description="Bait repository configuration")
    execution: ExecutionConfig = Field(
        default_factory=ExecutionConfig,
        description="Execution details",
    )

    # Results (populated after scan)
    results: Optional[ResultsSummary] = Field(
        default=None,
        description="Results summary (populated after scanning)",
    )

    def to_json(self) -> str:
        """Serialize to JSON with consistent formatting."""
        return self.model_dump_json(indent=2)

    def save(self, filepath: str) -> None:
        """Save manifest to file."""
        from pathlib import Path

        Path(filepath).write_text(self.to_json(), encoding="utf-8")

    @classmethod
    def load(cls, filepath: str) -> "RunManifest":
        """Load manifest from file."""
        from pathlib import Path

        content = Path(filepath).read_text(encoding="utf-8")
        return cls.model_validate_json(content)
