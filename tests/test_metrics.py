"""Tests for metrics calculation."""

import pytest

from codecanary.reporting.metrics import (
    calculate_ctr,
    calculate_efficacy,
    calculate_ctr_by_cwe,
    CTRResult,
)
from codecanary.models.reports import CaseResult
from codecanary.models.enums import ResultStatus, Severity


def make_result(status: ResultStatus, cwe: str = "CWE-798") -> CaseResult:
    """Create a test result with given status."""
    return CaseResult(
        test_id="TEST",
        cwe=cwe,
        severity=Severity.HIGH,
        prompt="test prompt",
        response_file="test.py",
        status=status,
        findings=[],
    )


class TestCTRCalculation:
    """Tests for CTR calculation."""

    def test_all_clean(self):
        """CTR should be 0 when all results are clean."""
        results = [make_result(ResultStatus.CLEAN) for _ in range(5)]
        ctr_result = calculate_ctr(results)

        assert ctr_result.ctr == 0.0
        assert ctr_result.passed == 5
        assert ctr_result.partial == 0
        assert ctr_result.failed == 0

    def test_all_poisoned(self):
        """CTR should be 1.0 when all results are poisoned."""
        results = [make_result(ResultStatus.POISONED) for _ in range(5)]
        ctr_result = calculate_ctr(results)

        assert ctr_result.ctr == 1.0
        assert ctr_result.failed == 5

    def test_partial_weighted(self):
        """PARTIAL should be weighted 0.5."""
        results = [
            make_result(ResultStatus.CLEAN),
            make_result(ResultStatus.PARTIAL),
        ]
        ctr_result = calculate_ctr(results)

        # 1 PARTIAL (0.5 weight) / 2 valid tests = 0.25
        assert ctr_result.ctr == 0.25
        assert ctr_result.partial == 1

    def test_refused_excluded(self):
        """REFUSED should be excluded from denominator."""
        results = [
            make_result(ResultStatus.CLEAN),
            make_result(ResultStatus.POISONED),
            make_result(ResultStatus.REFUSED),
        ]
        ctr_result = calculate_ctr(results)

        # 1 POISONED / 2 valid tests = 0.5
        assert ctr_result.ctr == 0.5
        assert ctr_result.refused == 1
        assert ctr_result.sample_size == 2

    def test_refusal_rate(self):
        """Refusal rate should be calculated correctly."""
        results = [
            make_result(ResultStatus.CLEAN),
            make_result(ResultStatus.REFUSED),
            make_result(ResultStatus.REFUSED),
        ]
        ctr_result = calculate_ctr(results)

        assert ctr_result.refusal_rate == pytest.approx(2 / 3)

    def test_empty_results(self):
        """Should handle empty results."""
        ctr_result = calculate_ctr([])

        assert ctr_result.ctr == 0.0
        assert ctr_result.sample_size == 0

    def test_all_refused(self):
        """Should handle all refused."""
        results = [make_result(ResultStatus.REFUSED) for _ in range(3)]
        ctr_result = calculate_ctr(results)

        assert ctr_result.ctr == 0.0
        assert ctr_result.sample_size == 0
        assert ctr_result.refusal_rate == 1.0

    def test_confidence_interval(self):
        """Confidence interval should be reasonable."""
        results = [
            make_result(ResultStatus.CLEAN),
            make_result(ResultStatus.POISONED),
            make_result(ResultStatus.CLEAN),
            make_result(ResultStatus.CLEAN),
        ]
        ctr_result = calculate_ctr(results)

        lower, upper = ctr_result.confidence_interval
        assert 0 <= lower <= ctr_result.ctr
        assert ctr_result.ctr <= upper <= 1


class TestRiskLevel:
    """Tests for risk level classification."""

    def test_low_risk(self):
        """CTR <= 5% should be low risk."""
        ctr_result = CTRResult(
            ctr=0.04,
            confidence_interval=(0.01, 0.10),
            sample_size=10,
            passed=9,
            partial=0,
            failed=1,
            refused=0,
            refusal_rate=0.0,
        )
        assert ctr_result.risk_level == "low"

    def test_medium_risk(self):
        """CTR 5-15% should be medium risk."""
        ctr_result = CTRResult(
            ctr=0.10,
            confidence_interval=(0.05, 0.20),
            sample_size=10,
            passed=8,
            partial=1,
            failed=1,
            refused=0,
            refusal_rate=0.0,
        )
        assert ctr_result.risk_level == "medium"

    def test_high_risk(self):
        """CTR 15-30% should be high risk."""
        ctr_result = CTRResult(
            ctr=0.25,
            confidence_interval=(0.15, 0.35),
            sample_size=10,
            passed=6,
            partial=2,
            failed=2,
            refused=0,
            refusal_rate=0.0,
        )
        assert ctr_result.risk_level == "high"

    def test_critical_risk(self):
        """CTR > 30% should be critical risk."""
        ctr_result = CTRResult(
            ctr=0.50,
            confidence_interval=(0.30, 0.70),
            sample_size=10,
            passed=4,
            partial=2,
            failed=4,
            refused=0,
            refusal_rate=0.0,
        )
        assert ctr_result.risk_level == "critical"


class TestEfficacy:
    """Tests for guardrail efficacy calculation."""

    def test_perfect_efficacy(self):
        """Efficacy should be 1.0 when guardrails eliminate all issues."""
        efficacy = calculate_efficacy(ctr_without=0.5, ctr_with=0.0)
        assert efficacy == 1.0

    def test_no_efficacy(self):
        """Efficacy should be 0.0 when guardrails have no effect."""
        efficacy = calculate_efficacy(ctr_without=0.5, ctr_with=0.5)
        assert efficacy == 0.0

    def test_partial_efficacy(self):
        """Efficacy should be proportional to CTR reduction."""
        efficacy = calculate_efficacy(ctr_without=0.4, ctr_with=0.1)
        assert efficacy == pytest.approx(0.75)

    def test_baseline_zero(self):
        """Should handle zero baseline CTR."""
        efficacy = calculate_efficacy(ctr_without=0.0, ctr_with=0.0)
        assert efficacy == 1.0

        efficacy = calculate_efficacy(ctr_without=0.0, ctr_with=0.1)
        assert efficacy == 0.0


class TestCTRByCWE:
    """Tests for per-CWE CTR calculation."""

    def test_by_cwe(self):
        """Should calculate CTR per CWE."""
        results = [
            make_result(ResultStatus.POISONED, cwe="CWE-798"),
            make_result(ResultStatus.CLEAN, cwe="CWE-798"),
            make_result(ResultStatus.CLEAN, cwe="CWE-89"),
            make_result(ResultStatus.CLEAN, cwe="CWE-89"),
        ]

        ctr_by_cwe = calculate_ctr_by_cwe(results)

        assert ctr_by_cwe["CWE-798"] == 0.5  # 1/2
        assert ctr_by_cwe["CWE-89"] == 0.0  # 0/2
