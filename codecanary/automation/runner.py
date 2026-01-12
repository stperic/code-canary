"""Automated test runner for CodeCanary.

Orchestrates automated testing by:
1. Building contexts for each test case
2. Sending prompts to AI providers
3. Collecting and storing responses
4. Running scanner on responses
5. Generating reports
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Callable
import json
import time

from codecanary.automation.providers import (
    ProviderInterface,
    ProviderResponse,
    ProviderConfig,
    get_provider,
)
from codecanary.automation.context import (
    ContextInjector,
    InjectionContext,
    BatchContextBuilder,
)
from codecanary.models.test_case import TestCase
from codecanary.scanner.analyzer import Analyzer
from codecanary.scanner.regex_scanner import RegexScanner
from codecanary.models.findings import ScanResult


@dataclass
class SingleTestResult:
    """Result of a single test execution."""

    test_id: str
    prompt: str
    response: str
    provider: str
    model: str
    latency_ms: float
    tokens_used: int
    timestamp: str
    guardrails_enabled: bool
    findings: list[dict] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class BatchResult:
    """Result of a batch test run."""

    run_id: str
    provider: str
    model: str
    guardrails_enabled: bool
    start_time: str
    end_time: str
    total_tests: int
    completed_tests: int
    failed_tests: int
    total_tokens: int
    total_latency_ms: float
    tests: list[SingleTestResult] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "run_id": self.run_id,
            "provider": self.provider,
            "model": self.model,
            "guardrails_enabled": self.guardrails_enabled,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "total_tests": self.total_tests,
            "completed_tests": self.completed_tests,
            "failed_tests": self.failed_tests,
            "total_tokens": self.total_tokens,
            "total_latency_ms": self.total_latency_ms,
            "tests": [
                {
                    "test_id": t.test_id,
                    "prompt": t.prompt,
                    "response": t.response,
                    "provider": t.provider,
                    "model": t.model,
                    "latency_ms": t.latency_ms,
                    "tokens_used": t.tokens_used,
                    "timestamp": t.timestamp,
                    "guardrails_enabled": t.guardrails_enabled,
                    "findings": t.findings,
                    "error": t.error,
                }
                for t in self.tests
            ],
        }

    def save(self, filepath: str) -> None:
        """Save batch result to JSON file."""
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        Path(filepath).write_text(
            json.dumps(self.to_dict(), indent=2), encoding="utf-8"
        )


class AutoTestRunner:
    """Automated test runner for batch testing AI providers.

    Executes test cases against AI providers, collects responses,
    scans for vulnerabilities, and generates reports.
    """

    def __init__(
        self,
        provider: ProviderInterface,
        output_dir: str = "./autotest_results",
        guardrails_enabled: bool = False,
        guardrail_template: Optional[str] = None,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
    ):
        """Initialize the test runner.

        Args:
            provider: AI provider to test
            output_dir: Directory for saving results
            guardrails_enabled: Whether to include guardrail instructions
            guardrail_template: Custom guardrail content
            progress_callback: Callback for progress updates (current, total, test_id)
        """
        self.provider = provider
        self.output_dir = Path(output_dir)
        self.guardrails_enabled = guardrails_enabled
        self.guardrail_template = guardrail_template
        self.progress_callback = progress_callback
        self._scanner = RegexScanner()

    def run_single(self, context: InjectionContext) -> SingleTestResult:
        """Run a single test case.

        Args:
            context: Injection context with test case and files

        Returns:
            TestRun result
        """
        timestamp = datetime.now(timezone.utc).isoformat()

        try:
            # Call provider
            response = self.provider.complete(
                prompt=context.prompt,
                system_prompt=context.guardrail_content,
                context_files=context.files,
            )

            # Scan response for findings
            findings = self._scan_response(response.content, context.test_case)

            return SingleTestResult(
                test_id=context.test_id,
                prompt=context.prompt,
                response=response.content,
                provider=response.provider,
                model=response.model,
                latency_ms=response.latency_ms,
                tokens_used=response.total_tokens,
                timestamp=timestamp,
                guardrails_enabled=self.guardrails_enabled,
                findings=findings,
            )

        except Exception as e:
            return SingleTestResult(
                test_id=context.test_id,
                prompt=context.prompt,
                response="",
                provider=self.provider.name,
                model="",
                latency_ms=0,
                tokens_used=0,
                timestamp=timestamp,
                guardrails_enabled=self.guardrails_enabled,
                error=str(e),
            )

    def run_batch(
        self,
        contexts: list[InjectionContext],
        run_id: Optional[str] = None,
    ) -> BatchResult:
        """Run a batch of test cases.

        Args:
            contexts: List of injection contexts to test
            run_id: Optional run identifier

        Returns:
            BatchResult with all test results
        """
        if run_id is None:
            run_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        start_time = datetime.now(timezone.utc).isoformat()
        tests: list[SingleTestResult] = []
        total_tokens = 0
        total_latency = 0.0
        failed = 0

        for i, context in enumerate(contexts):
            # Progress callback
            if self.progress_callback:
                self.progress_callback(i + 1, len(contexts), context.test_id)

            # Run test
            result = self.run_single(context)
            tests.append(result)

            if result.error:
                failed += 1
            else:
                total_tokens += result.tokens_used
                total_latency += result.latency_ms

        end_time = datetime.now(timezone.utc).isoformat()

        return BatchResult(
            run_id=run_id,
            provider=self.provider.name,
            model=getattr(self.provider, "config", ProviderConfig()).model,
            guardrails_enabled=self.guardrails_enabled,
            start_time=start_time,
            end_time=end_time,
            total_tests=len(contexts),
            completed_tests=len(contexts) - failed,
            failed_tests=failed,
            total_tokens=total_tokens,
            total_latency_ms=total_latency,
            tests=tests,
        )

    def run_all(
        self,
        languages: Optional[list[str]] = None,
        cwes: Optional[list[str]] = None,
        test_ids: Optional[list[str]] = None,
    ) -> BatchResult:
        """Run all matching test cases.

        Args:
            languages: Filter by language
            cwes: Filter by CWE
            test_ids: Specific test IDs to run

        Returns:
            BatchResult with all test results
        """
        builder = BatchContextBuilder(
            test_ids=test_ids,
            languages=languages or ["python"],
            cwes=cwes,
            guardrails_enabled=self.guardrails_enabled,
            guardrail_template=self.guardrail_template,
        )

        contexts = builder.build()
        return self.run_batch(contexts)

    def save_responses(
        self,
        batch_result: BatchResult,
        output_dir: Optional[str] = None,
    ) -> Path:
        """Save responses to files for scanning.

        Args:
            batch_result: Batch result to save
            output_dir: Override output directory

        Returns:
            Path to responses directory
        """
        responses_dir = Path(output_dir or self.output_dir) / "responses"
        responses_dir.mkdir(parents=True, exist_ok=True)

        for test in batch_result.tests:
            if not test.error:
                # Determine file extension based on test case
                ext = self._get_extension(test.test_id)
                filename = f"{test.test_id.lower()}{ext}"
                filepath = responses_dir / filename
                filepath.write_text(test.response, encoding="utf-8")

        return responses_dir

    def _scan_response(
        self, content: str, test_case: TestCase
    ) -> list[dict]:
        """Scan a response for findings.

        Args:
            content: Response content
            test_case: Test case with detection patterns

        Returns:
            List of findings as dicts
        """
        matches = self._scanner.scan_content(
            content=content,
            patterns=test_case.detection_patterns,
            filepath=f"{test_case.id}_response",
            cwe=test_case.cwe,
        )
        findings = []
        for match in matches:
            findings.append({
                "pattern_id": match.pattern_id,
                "matched_text": match.matched_text[:100] if len(match.matched_text) > 100 else match.matched_text,
                "line_number": match.line_number,
                "confidence": match.confidence,
            })
        return findings

    def _get_extension(self, test_id: str) -> str:
        """Get file extension based on test ID prefix."""
        if test_id.startswith("JS"):
            return ".js"
        elif test_id.startswith("GO"):
            return ".go"
        else:
            return ".py"


def create_runner(
    provider_name: str,
    model: Optional[str] = None,
    api_key: Optional[str] = None,
    guardrails_enabled: bool = False,
    output_dir: str = "./autotest_results",
) -> AutoTestRunner:
    """Convenience function to create a test runner.

    Args:
        provider_name: Provider name ('openai', 'anthropic', 'ollama')
        model: Model to use
        api_key: API key (uses environment if not provided)
        guardrails_enabled: Enable guardrails
        output_dir: Output directory

    Returns:
        Configured AutoTestRunner
    """
    config = ProviderConfig(
        api_key=api_key,
        model=model or "",
    )
    provider = get_provider(provider_name, config)

    return AutoTestRunner(
        provider=provider,
        output_dir=output_dir,
        guardrails_enabled=guardrails_enabled,
    )
