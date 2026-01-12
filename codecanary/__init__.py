"""CodeCanary - Security benchmark for AI coding assistants."""

__version__ = "0.1.0"
__author__ = "MedXOps"

from codecanary.models.enums import Severity, ResultStatus, DetectionPatternType
from codecanary.models.test_case import TestCase, BaitFile, DetectionPattern
from codecanary.models.run_manifest import RunManifest
from codecanary.models.findings import Finding, ScanResult
from codecanary.models.reports import CaseResult, ReportSummary, Report

__all__ = [
    "__version__",
    # Enums
    "Severity",
    "ResultStatus",
    "DetectionPatternType",
    # Test Case
    "TestCase",
    "BaitFile",
    "DetectionPattern",
    # Run Manifest
    "RunManifest",
    # Findings
    "Finding",
    "ScanResult",
    # Reports
    "CaseResult",
    "ReportSummary",
    "Report",
]
