"""Batch testing and regression support.

Provides:
- Batch test orchestration
- A/B testing (guardrails vs no guardrails)
- Regression testing across versions
- Result comparison and trends
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Callable
import json

from codecanary.automation.providers import ProviderInterface, ProviderConfig, get_provider
from codecanary.automation.context import BatchContextBuilder
from codecanary.automation.runner import AutoTestRunner, BatchResult


@dataclass
class ABTestConfig:
    """Configuration for A/B testing."""

    provider: str
    model: str
    api_key: Optional[str] = None
    languages: list[str] = field(default_factory=lambda: ["python"])
    cwes: Optional[list[str]] = None
    test_ids: Optional[list[str]] = None
    output_dir: str = "./ab_test_results"


@dataclass
class ABTestResult:
    """Result of an A/B test (guardrails vs no guardrails)."""

    run_id: str
    baseline: BatchResult  # Without guardrails
    guardrailed: BatchResult  # With guardrails
    
    @property
    def baseline_ctr(self) -> float:
        """Calculate CTR for baseline run."""
        return self._calculate_ctr(self.baseline)
    
    @property
    def guardrailed_ctr(self) -> float:
        """Calculate CTR for guardrailed run."""
        return self._calculate_ctr(self.guardrailed)
    
    @property
    def efficacy(self) -> float:
        """Calculate guardrail efficacy.
        
        Efficacy = (baseline_ctr - guardrailed_ctr) / baseline_ctr
        Returns 0 if baseline_ctr is 0.
        """
        if self.baseline_ctr == 0:
            return 0.0
        return (self.baseline_ctr - self.guardrailed_ctr) / self.baseline_ctr

    def _calculate_ctr(self, result: BatchResult) -> float:
        """Calculate rough CTR from batch result."""
        if result.completed_tests == 0:
            return 0.0
        tests_with_findings = sum(1 for t in result.tests if t.findings)
        return tests_with_findings / result.completed_tests

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "run_id": self.run_id,
            "baseline_ctr": self.baseline_ctr,
            "guardrailed_ctr": self.guardrailed_ctr,
            "efficacy": self.efficacy,
            "baseline": self.baseline.to_dict(),
            "guardrailed": self.guardrailed.to_dict(),
        }

    def save(self, filepath: str) -> None:
        """Save to JSON file."""
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        Path(filepath).write_text(
            json.dumps(self.to_dict(), indent=2),
            encoding="utf-8",
        )


class ABTester:
    """Runs A/B tests comparing guardrails vs no guardrails."""

    def __init__(
        self,
        config: ABTestConfig,
        progress_callback: Optional[Callable[[str, int, int, str], None]] = None,
    ):
        """Initialize A/B tester.
        
        Args:
            config: A/B test configuration
            progress_callback: Callback (phase, current, total, test_id)
        """
        self.config = config
        self.progress_callback = progress_callback

    def run(self, guardrail_template: Optional[str] = None) -> ABTestResult:
        """Run A/B test.
        
        Args:
            guardrail_template: Custom guardrail content
            
        Returns:
            ABTestResult with both runs
        """
        run_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        # Build contexts without guardrails
        baseline_builder = BatchContextBuilder(
            test_ids=self.config.test_ids,
            languages=self.config.languages,
            cwes=self.config.cwes,
            guardrails_enabled=False,
        )
        baseline_contexts = baseline_builder.build()

        # Build contexts with guardrails
        guardrailed_builder = BatchContextBuilder(
            test_ids=self.config.test_ids,
            languages=self.config.languages,
            cwes=self.config.cwes,
            guardrails_enabled=True,
            guardrail_template=guardrail_template,
        )
        guardrailed_contexts = guardrailed_builder.build()

        # Create provider
        provider_config = ProviderConfig(
            api_key=self.config.api_key,
            model=self.config.model,
        )
        provider = get_provider(self.config.provider, provider_config)

        # Run baseline
        baseline_runner = AutoTestRunner(
            provider=provider,
            output_dir=f"{self.config.output_dir}/baseline",
            guardrails_enabled=False,
            progress_callback=self._make_progress_callback("baseline"),
        )
        baseline_result = baseline_runner.run_batch(
            baseline_contexts, run_id=f"{run_id}_baseline"
        )

        # Run guardrailed
        guardrailed_runner = AutoTestRunner(
            provider=provider,
            output_dir=f"{self.config.output_dir}/guardrailed",
            guardrails_enabled=True,
            guardrail_template=guardrail_template,
            progress_callback=self._make_progress_callback("guardrailed"),
        )
        guardrailed_result = guardrailed_runner.run_batch(
            guardrailed_contexts, run_id=f"{run_id}_guardrailed"
        )

        return ABTestResult(
            run_id=run_id,
            baseline=baseline_result,
            guardrailed=guardrailed_result,
        )

    def _make_progress_callback(
        self, phase: str
    ) -> Callable[[int, int, str], None]:
        """Create a progress callback for a specific phase."""
        def callback(current: int, total: int, test_id: str) -> None:
            if self.progress_callback:
                self.progress_callback(phase, current, total, test_id)
        return callback


@dataclass
class RegressionRun:
    """A single regression test run."""

    timestamp: str
    version: str
    provider: str
    model: str
    ctr: float
    total_tests: int
    findings: int


@dataclass
class RegressionHistory:
    """History of regression test runs."""

    runs: list[RegressionRun] = field(default_factory=list)

    def add_run(self, run: RegressionRun) -> None:
        """Add a run to history."""
        self.runs.append(run)

    def get_trend(self) -> list[float]:
        """Get CTR trend over time."""
        return [r.ctr for r in self.runs]

    def get_latest(self) -> Optional[RegressionRun]:
        """Get the most recent run."""
        return self.runs[-1] if self.runs else None

    def has_regression(self, threshold: float = 0.1) -> bool:
        """Check if CTR has increased significantly.
        
        Args:
            threshold: Maximum acceptable CTR increase
            
        Returns:
            True if regression detected
        """
        if len(self.runs) < 2:
            return False
        latest = self.runs[-1].ctr
        previous = self.runs[-2].ctr
        return (latest - previous) > threshold

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "runs": [
                {
                    "timestamp": r.timestamp,
                    "version": r.version,
                    "provider": r.provider,
                    "model": r.model,
                    "ctr": r.ctr,
                    "total_tests": r.total_tests,
                    "findings": r.findings,
                }
                for r in self.runs
            ]
        }

    def save(self, filepath: str) -> None:
        """Save history to JSON."""
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        Path(filepath).write_text(
            json.dumps(self.to_dict(), indent=2),
            encoding="utf-8",
        )

    @classmethod
    def load(cls, filepath: str) -> "RegressionHistory":
        """Load history from JSON."""
        data = json.loads(Path(filepath).read_text(encoding="utf-8"))
        history = cls()
        for run_data in data.get("runs", []):
            history.add_run(RegressionRun(**run_data))
        return history


class RegressionTester:
    """Runs regression tests and tracks history."""

    def __init__(
        self,
        history_file: str = "./regression_history.json",
        version: str = "unknown",
    ):
        """Initialize regression tester.
        
        Args:
            history_file: Path to history JSON file
            version: Current version being tested
        """
        self.history_file = history_file
        self.version = version
        self._history: Optional[RegressionHistory] = None

    @property
    def history(self) -> RegressionHistory:
        """Get or load history."""
        if self._history is None:
            try:
                self._history = RegressionHistory.load(self.history_file)
            except FileNotFoundError:
                self._history = RegressionHistory()
        return self._history

    def record_run(self, result: BatchResult) -> RegressionRun:
        """Record a batch result as a regression run.
        
        Args:
            result: Batch result to record
            
        Returns:
            The created RegressionRun
        """
        tests_with_findings = sum(1 for t in result.tests if t.findings)
        ctr = tests_with_findings / result.completed_tests if result.completed_tests > 0 else 0.0

        run = RegressionRun(
            timestamp=result.start_time,
            version=self.version,
            provider=result.provider,
            model=result.model,
            ctr=ctr,
            total_tests=result.total_tests,
            findings=tests_with_findings,
        )

        self.history.add_run(run)
        self.history.save(self.history_file)

        return run

    def check_regression(self, threshold: float = 0.1) -> tuple[bool, Optional[str]]:
        """Check for regression.
        
        Args:
            threshold: Maximum acceptable CTR increase
            
        Returns:
            Tuple of (has_regression, message)
        """
        if self.history.has_regression(threshold):
            latest = self.history.get_latest()
            previous = self.history.runs[-2] if len(self.history.runs) >= 2 else None
            if latest and previous:
                delta = latest.ctr - previous.ctr
                return True, (
                    f"CTR increased from {previous.ctr:.1%} to {latest.ctr:.1%} "
                    f"(+{delta:.1%}), exceeding threshold of {threshold:.1%}"
                )
        return False, None
