"""Finding data models for scanner output."""

from pydantic import BaseModel, Field
from typing import Optional

from codecanary.models.enums import Severity


class Finding(BaseModel):
    """A single detected pattern in an AI response.

    Represents one match of a detection pattern against
    the AI-generated code.
    """

    pattern_id: str = Field(..., description="ID of the matched pattern")
    cwe: str = Field(..., description="CWE identifier")
    severity: Severity = Field(..., description="Severity level")
    matched_text: str = Field(..., description="The text that matched the pattern")
    file: str = Field(..., description="File where the match was found")
    line_number: Optional[int] = Field(
        default=None,
        description="Line number of the match",
    )
    confidence: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Confidence level of the detection",
    )
    scanner: str = Field(
        default="regex",
        description="Scanner that produced this finding",
    )
    description: Optional[str] = Field(
        default=None,
        description="Human-readable description",
    )


class ScanResult(BaseModel):
    """Result of scanning a directory of AI responses."""

    files_scanned: int = Field(..., description="Number of files scanned")
    files_skipped: int = Field(
        default=0,
        description="Number of files skipped (binary, too large, etc.)",
    )
    findings: list[Finding] = Field(
        default_factory=list,
        description="All findings from the scan",
    )
    errors: list[str] = Field(
        default_factory=list,
        description="Any errors encountered during scanning",
    )

    def to_json(self) -> str:
        """Serialize to JSON with consistent formatting."""
        return self.model_dump_json(indent=2)

    def save(self, filepath: str) -> None:
        """Save scan result to file."""
        from pathlib import Path

        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        Path(filepath).write_text(self.to_json(), encoding="utf-8")

    @classmethod
    def load(cls, filepath: str) -> "ScanResult":
        """Load scan result from file."""
        from pathlib import Path

        content = Path(filepath).read_text(encoding="utf-8")
        return cls.model_validate_json(content)

    @property
    def finding_count(self) -> int:
        """Total number of findings."""
        return len(self.findings)

    def findings_by_cwe(self) -> dict[str, list[Finding]]:
        """Group findings by CWE."""
        result: dict[str, list[Finding]] = {}
        for finding in self.findings:
            if finding.cwe not in result:
                result[finding.cwe] = []
            result[finding.cwe].append(finding)
        return result

    def findings_by_file(self) -> dict[str, list[Finding]]:
        """Group findings by file."""
        result: dict[str, list[Finding]] = {}
        for finding in self.findings:
            if finding.file not in result:
                result[finding.file] = []
            result[finding.file].append(finding)
        return result
