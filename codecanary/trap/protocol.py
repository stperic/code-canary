"""Human-in-loop test protocol for CodeCanary."""

from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm

from codecanary.models.run_manifest import RunManifest
from codecanary.bait.patterns import TEST_CASES, get_test_case_by_id


class TestProtocol:
    """Guides human tester through the test protocol.

    Per PRD Section 10, the protocol ensures:
    - Consistent prompt delivery
    - Proper response capture
    - Complete documentation
    """

    def __init__(
        self,
        bait_dir: str = "./bait_repo",
        responses_dir: str = "./responses",
        manifest: Optional[RunManifest] = None,
        test_cases: Optional[list] = None,
    ):
        """Initialize the test protocol.

        Args:
            bait_dir: Path to bait repository
            responses_dir: Directory to save AI responses
            manifest: Run manifest for this test run
            test_cases: Optional list of specific test cases to run
        """
        self.bait_dir = Path(bait_dir)
        self.responses_dir = Path(responses_dir)
        self.manifest = manifest
        self._test_cases = test_cases  # User-specified test cases
        self.console = Console()

    def run(self) -> None:
        """Run the interactive test protocol."""
        self._print_header()
        self._print_instructions()

        # Create responses directory
        self.responses_dir.mkdir(parents=True, exist_ok=True)

        # Get test cases to run (priority: user-specified > manifest > all)
        if self._test_cases is not None:
            test_cases = self._test_cases
        elif self.manifest:
            test_cases = [
                tc for tc in TEST_CASES if tc.id in self.manifest.bait.test_case_ids
            ]
        else:
            test_cases = TEST_CASES

        # Run each test
        for i, tc in enumerate(test_cases, 1):
            self._run_test(tc, i, len(test_cases))

        self._print_completion()

    def _print_header(self) -> None:
        """Print protocol header."""
        self.console.print()
        self.console.print(
            Panel.fit(
                "[bold cyan]CodeCanary Test Protocol[/bold cyan]\n"
                "Human-in-loop testing for AI coding assistant security",
                border_style="cyan",
            )
        )
        self.console.print()

    def _print_instructions(self) -> None:
        """Print test instructions."""
        instructions = """
[bold]INSTRUCTIONS[/bold]

1. Open the bait repository in your AI assistant:
   [dim]{bait_dir}[/dim]

2. Wait for the assistant to finish indexing

3. For each test prompt:
   - Copy the prompt and paste into your AI assistant
   - Let the AI generate code (it will create files in the bait repo)
   - Press [bold]done[/bold] when complete

4. After all tests, run:
   [dim]codecanary scan --dir {bait_dir}[/dim]
   [dim]codecanary report[/dim]
""".format(
            bait_dir=self.bait_dir.absolute()
        )

        self.console.print(instructions)

        if self.manifest:
            self.console.print(f"[dim]Run ID: {self.manifest.run_id}[/dim]")
            self.console.print(
                f"[dim]Assistant: {self.manifest.assistant.name}"
                + (f" ({self.manifest.assistant.model})" if self.manifest.assistant.model else "")
                + "[/dim]"
            )
            if self.manifest.guardrails.enabled:
                self.console.print(
                    f"[dim]Guardrails: Enabled ({self.manifest.guardrails.file})[/dim]"
                )
            else:
                self.console.print("[dim]Guardrails: Disabled[/dim]")

        self.console.print()

        # Wait for user to be ready
        Prompt.ask("[bold]Press Enter when ready to begin[/bold]")

    def _run_test(self, tc, current: int, total: int) -> None:
        """Run a single test case.

        Args:
            tc: TestCase to run
            current: Current test number
            total: Total number of tests
        """
        self.console.print()
        self.console.print(f"[bold cyan]═══ Test {current}/{total}: {tc.id} ═══[/bold cyan]")
        self.console.print(f"[dim]CWE: {tc.cwe} | Severity: {tc.severity.value.upper()}[/dim]")
        self.console.print()

        # Display prompt (no wrap for easy copying)
        self.console.print("[bold]PROMPT TO COPY:[/bold]")
        self.console.print()
        # Use plain print to avoid Rich's line wrapping
        print(f"\033[32m{tc.prompt}\033[0m")  # Green ANSI color
        self.console.print()

        if tc.prompt_context:
            self.console.print(f"[dim]Context: {tc.prompt_context}[/dim]")
            self.console.print()

        # Wait for user to complete this test
        while True:
            action = Prompt.ask(
                "[bold]Action[/bold] [dim](done=AI generated code, skip=skip test, quit=exit)[/dim]",
                choices=["done", "skip", "quit"],
                default="done",
            )

            if action == "done":
                self.console.print(f"[green]✓[/green] Completed: {tc.id}")
                break

            elif action == "skip":
                self.console.print(f"[yellow]⊘[/yellow] Skipped: {tc.id}")
                break

            elif action == "quit":
                if Confirm.ask("Are you sure you want to quit?", default=False):
                    self.console.print("[yellow]Test protocol interrupted[/yellow]")
                    raise SystemExit(0)

    def _print_completion(self) -> None:
        """Print completion message."""
        self.console.print()
        self.console.print(
            Panel.fit(
                "[bold green]Test Protocol Complete[/bold green]\n\n"
                "Next steps:\n"
                f"1. codecanary scan --dir {self.bait_dir}\n"
                "2. codecanary report --format summary",
                border_style="green",
            )
        )
        self.console.print()
