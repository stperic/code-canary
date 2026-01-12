"""Report data models for CodeCanary output."""

from pydantic import BaseModel, Field
from typing import Optional

from codecanary.models.enums import ResultStatus, Severity
from codecanary.models.findings import Finding
from codecanary.models.run_manifest import RunManifest
from codecanary import __version__


class CaseResult(BaseModel):
    """Result of a single test case.

    Combines the test execution with scan findings
    to produce a classification.

    Note: Named 'CaseResult' instead of 'TestResult' to avoid
    conflicts with pytest's test collection.
    """

    test_id: str = Field(..., description="Test case ID")
    cwe: str = Field(..., description="CWE identifier")
    severity: Severity = Field(..., description="Severity level")
    prompt: str = Field(..., description="Prompt that was executed")
    response_file: str = Field(..., description="Path to AI response file")
    status: ResultStatus = Field(..., description="Classification status")
    findings: list[Finding] = Field(
        default_factory=list,
        description="Findings from scanning the response",
    )

    @property
    def ctr_weight(self) -> float:
        """Get CTR weight for this result."""
        return self.status.ctr_weight


class CTRByCategory(BaseModel):
    """CTR breakdown for a specific category (e.g., CWE)."""

    category: str = Field(..., description="Category identifier")
    ctr: float = Field(..., description="CTR for this category")
    total_tests: int = Field(..., description="Number of tests in category")
    passed: int = Field(..., description="Number of CLEAN results")
    partial: int = Field(..., description="Number of PARTIAL results")
    failed: int = Field(..., description="Number of POISONED results")
    refused: int = Field(..., description="Number of REFUSED results")


class ReportSummary(BaseModel):
    """Summary statistics for a CodeCanary report.

    Per PRD Section 6, includes:
    - CTR (with PARTIAL=0.5 weighting)
    - Refusal rate
    - Per-CWE breakdown
    """

    total_tests: int = Field(..., description="Total tests executed")
    passed: int = Field(..., description="CLEAN count")
    partial: int = Field(..., description="PARTIAL count")
    failed: int = Field(..., description="POISONED count")
    refused: int = Field(..., description="REFUSED count")
    ctr: float = Field(..., description="Canary Trigger Rate")
    ctr_confidence_interval: tuple[float, float] = Field(
        ...,
        description="95% confidence interval",
    )
    refusal_rate: float = Field(..., description="Refusal rate")
    ctr_by_cwe: dict[str, float] = Field(
        default_factory=dict,
        description="CTR broken down by CWE",
    )
    guardrail_efficacy: Optional[float] = Field(
        default=None,
        description="Guardrail efficacy (if comparison available)",
    )


class Report(BaseModel):
    """Complete CodeCanary report.

    Combines run manifest, test results, and summary
    into a single shareable report.
    """

    codecanary_version: str = Field(
        default=__version__,
        description="CodeCanary version",
    )
    run_manifest: RunManifest = Field(..., description="Run metadata for reproducibility")
    results: list[CaseResult] = Field(
        default_factory=list,
        description="Individual test results",
    )
    summary: ReportSummary = Field(..., description="Summary statistics")

    def to_json(self) -> str:
        """Serialize to JSON with consistent formatting."""
        return self.model_dump_json(indent=2)

    def save(self, filepath: str) -> None:
        """Save report to file."""
        from pathlib import Path

        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        Path(filepath).write_text(self.to_json(), encoding="utf-8")

    @classmethod
    def load(cls, filepath: str) -> "Report":
        """Load report from file."""
        from pathlib import Path

        content = Path(filepath).read_text(encoding="utf-8")
        return cls.model_validate_json(content)
