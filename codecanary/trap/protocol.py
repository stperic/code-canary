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
    ):
        """Initialize the test protocol.

        Args:
            bait_dir: Path to bait repository
            responses_dir: Directory to save AI responses
            manifest: Run manifest for this test run
        """
        self.bait_dir = Path(bait_dir)
        self.responses_dir = Path(responses_dir)
        self.manifest = manifest
        self.console = Console()

    def run(self) -> None:
        """Run the interactive test protocol."""
        self._print_header()
        self._print_instructions()

        # Create responses directory
        self.responses_dir.mkdir(parents=True, exist_ok=True)

        # Get test cases to run
        test_cases = TEST_CASES
        if self.manifest:
            test_cases = [
                tc for tc in TEST_CASES if tc.id in self.manifest.bait.test_case_ids
            ]

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
   - Copy the prompt exactly as shown
   - Paste it into the AI assistant
   - Wait for the complete response
   - Copy the FULL AI response
   - Save it to the specified file

4. After all tests, run:
   [dim]codecanary scan[/dim]
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

        # Display prompt (no box for easy copying)
        self.console.print("[bold]PROMPT TO COPY:[/bold]")
        self.console.print()
        self.console.print(f"[green]{tc.prompt}[/green]")
        self.console.print()

        if tc.prompt_context:
            self.console.print(f"[dim]Context: {tc.prompt_context}[/dim]")
            self.console.print()

        # Show expected response file
        response_file = self.responses_dir / f"{tc.id.lower()}.py"
        self.console.print(f"[bold]Save AI response to:[/bold] {response_file}")
        self.console.print()

        # Wait for user to complete this test
        while True:
            action = Prompt.ask(
                "[bold]Action[/bold]",
                choices=["done", "skip", "quit"],
                default="done",
            )

            if action == "done":
                if response_file.exists():
                    self.console.print(f"[green]✓[/green] Response saved: {response_file}")
                    break
                else:
                    # Create placeholder if user says done but file doesn't exist
                    if Confirm.ask(
                        f"File not found: {response_file}\nMark as completed anyway?",
                        default=False,
                    ):
                        break
                    self.console.print("[yellow]Please save the response and try again[/yellow]")

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
                f"1. codecanary scan --input {self.responses_dir}\n"
                "2. codecanary report --format summary",
                border_style="green",
            )
        )
        self.console.print()
