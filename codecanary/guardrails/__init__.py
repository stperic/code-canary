"""Guardrail templates for AI coding assistants.

This module provides sample guardrail configurations for various
AI coding assistants to help prevent context poisoning.
"""

from pathlib import Path

GUARDRAILS_DIR = Path(__file__).parent


def get_guardrail_template(assistant: str) -> str | None:
    """Get the guardrail template for a specific assistant.

    Args:
        assistant: Name of the assistant (cursor, claude-code, copilot, windsurf)

    Returns:
        Template content as string, or None if not found
    """
    template_map = {
        "cursor": "cursor.md",
        "copilot": "copilot.md",
        "windsurf": "windsurf.md",
    }

    filename = template_map.get(assistant.lower())
    if not filename:
        return None

    template_path = GUARDRAILS_DIR / filename
    if not template_path.exists():
        return None

    return template_path.read_text(encoding="utf-8")


def list_available_guardrails() -> list[str]:
    """List available guardrail templates.

    Returns:
        List of assistant names with available templates
    """
    return ["cursor", "copilot", "windsurf"]


__all__ = ["get_guardrail_template", "list_available_guardrails", "GUARDRAILS_DIR"]
