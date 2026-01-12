"""Canonical TestCase schema per PRD Section 7."""

from pydantic import BaseModel, Field
from typing import Optional

from codecanary.models.enums import Severity, DetectionPatternType


class BaitFile(BaseModel):
    """A file to create in the bait repository."""

    path: str = Field(..., description="Relative path in bait repo")
    content: str = Field(..., description="File content with canary tokens")


class DetectionPattern(BaseModel):
    """Pattern for detecting vulnerabilities in AI responses."""

    id: str = Field(..., description="Unique pattern identifier")
    type: DetectionPatternType = Field(
        default=DetectionPatternType.BOTH,
        description="Pattern type: canary_token, bad_practice, or both",
    )
    regex: str = Field(..., description="Detection regex pattern")
    confidence: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Confidence level for this pattern (0.0-1.0)",
    )
    description: Optional[str] = Field(default=None, description="Human-readable description")


class ClassificationRule(BaseModel):
    """Rule for classifying test results."""

    pattern_id: str = Field(..., description="Pattern ID that triggers this rule")
    min_confidence: float = Field(
        default=0.8,
        ge=0.0,
        le=1.0,
        description="Minimum confidence to trigger this rule",
    )


class Classification(BaseModel):
    """Classification rules for a test case.

    Determines when a result is POISONED, PARTIAL, or CLEAN.
    """

    poisoned_if: list[ClassificationRule] = Field(
        default_factory=list,
        description="Conditions for POISONED status (exact canary match)",
    )
    partial_if: list[ClassificationRule] = Field(
        default_factory=list,
        description="Conditions for PARTIAL status (vulnerability without exact canary)",
    )
    clean_if: str = Field(
        default="no patterns match",
        description="Description of when result is CLEAN",
    )


class Reference(BaseModel):
    """External reference for a test case."""

    url: str
    description: Optional[str] = None


class TestCaseMetadata(BaseModel):
    """Metadata for a test case."""

    created: Optional[str] = None
    author: Optional[str] = None
    references: list[Reference] = Field(default_factory=list)


class TestCase(BaseModel):
    """Canonical test case definition per PRD Section 7.

    A complete test case includes:
    - Identity and classification
    - Bait files to create
    - Prompt to execute
    - Detection patterns to scan for
    - Classification rules
    - Expected secure behavior
    """

    # Identity
    id: str = Field(..., description="Unique identifier (e.g., 'T01_AWS_CREDS')")
    version: str = Field(default="1.0", description="Schema version")

    # Classification
    cwe: str = Field(..., description="CWE identifier (e.g., 'CWE-798')")
    severity: Severity = Field(..., description="Vulnerability severity")
    owasp_category: Optional[str] = Field(
        default=None,
        description="OWASP Top 10 mapping (e.g., 'A07:2021')",
    )

    # Bait Configuration
    bait_files: list[BaitFile] = Field(
        ...,
        min_length=1,
        description="Files to create in bait repository",
    )

    # Trap Configuration
    prompt: str = Field(..., description="Exact prompt text to execute")
    prompt_context: Optional[str] = Field(
        default=None,
        description="Additional context for human tester",
    )

    # Detection Configuration
    detection_patterns: list[DetectionPattern] = Field(
        ...,
        min_length=1,
        description="Patterns to scan for in AI response",
    )

    # Classification Rules
    classification: Classification = Field(
        default_factory=Classification,
        description="Rules for classifying results",
    )

    # Expected Secure Behavior
    expected_secure_properties: list[str] = Field(
        default_factory=list,
        description="What a secure response should do",
    )

    # Metadata
    metadata: TestCaseMetadata = Field(
        default_factory=TestCaseMetadata,
        description="Additional metadata",
    )

    def to_yaml(self) -> str:
        """Serialize to YAML format."""
        import yaml

        return yaml.dump(self.model_dump(), default_flow_style=False, sort_keys=False)
