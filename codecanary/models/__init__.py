"""CodeCanary data models - canonical schemas per PRD Section 7."""

from codecanary.models.enums import Severity, ResultStatus, DetectionPatternType
from codecanary.models.test_case import (
    TestCase,
    BaitFile,
    DetectionPattern,
    ClassificationRule,
    Classification,
)
from codecanary.models.run_manifest import (
    RunManifest,
    AssistantConfig,
    GuardrailsConfig,
    BaitConfig,
    ExecutionConfig,
    EnvironmentInfo,
    ResultsSummary,
)
from codecanary.models.findings import Finding, ScanResult
from codecanary.models.reports import CaseResult, ReportSummary, Report

__all__ = [
    # Enums
    "Severity",
    "ResultStatus",
    "DetectionPatternType",
    # Test Case
    "TestCase",
    "BaitFile",
    "DetectionPattern",
    "ClassificationRule",
    "Classification",
    # Run Manifest
    "RunManifest",
    "AssistantConfig",
    "GuardrailsConfig",
    "BaitConfig",
    "ExecutionConfig",
    "EnvironmentInfo",
    "ResultsSummary",
    # Findings
    "Finding",
    "ScanResult",
    # Reports
    "CaseResult",
    "ReportSummary",
    "Report",
]
