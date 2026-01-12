"""AI Provider adapters for automated testing.

Supports direct API testing with:
- OpenAI (GPT-4, GPT-4o, GPT-4-turbo)
- Anthropic (Claude 3, Claude 3.5)
- Ollama (local models)
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional, Any
import os
import time
import json
from pathlib import Path


@dataclass
class ProviderConfig:
    """Configuration for an AI provider."""

    api_key: Optional[str] = None
    base_url: Optional[str] = None
    model: str = ""
    max_tokens: int = 4096
    temperature: float = 0.0  # Deterministic for testing
    timeout: int = 120
    rate_limit_delay: float = 1.0  # Seconds between requests


@dataclass
class ProviderResponse:
    """Response from an AI provider."""

    content: str
    model: str
    provider: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    finish_reason: str = ""
    latency_ms: float = 0.0
    raw_response: Optional[dict] = None


class ProviderInterface(ABC):
    """Abstract interface for AI providers."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider name (e.g., 'openai', 'anthropic')."""
        pass

    @property
    @abstractmethod
    def supported_models(self) -> list[str]:
        """List of supported model identifiers."""
        pass

    @abstractmethod
    def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        context_files: Optional[dict[str, str]] = None,
    ) -> ProviderResponse:
        """Generate a completion from the AI model.

        Args:
            prompt: User prompt/question
            system_prompt: Optional system instructions (guardrails)
            context_files: Dict of filename -> content for context

        Returns:
            ProviderResponse with generated content
        """
        pass

    @abstractmethod
    def validate_config(self) -> bool:
        """Validate that the provider is properly configured."""
        pass


class OpenAIProvider(ProviderInterface):
    """OpenAI API provider (GPT-4, GPT-4o, etc.)."""

    MODELS = [
        "gpt-4",
        "gpt-4-turbo",
        "gpt-4-turbo-preview",
        "gpt-4o",
        "gpt-4o-mini",
        "gpt-3.5-turbo",
    ]

    def __init__(self, config: Optional[ProviderConfig] = None):
        """Initialize OpenAI provider.

        Args:
            config: Provider configuration (uses env vars if not provided)
        """
        self.config = config or ProviderConfig()
        self.config.api_key = self.config.api_key or os.environ.get("OPENAI_API_KEY")
        self.config.model = self.config.model or "gpt-4o"
        self._client: Any = None

    @property
    def name(self) -> str:
        return "openai"

    @property
    def supported_models(self) -> list[str]:
        return self.MODELS

    def _get_client(self) -> Any:
        """Lazy initialization of OpenAI client."""
        if self._client is None:
            try:
                from openai import OpenAI

                self._client = OpenAI(
                    api_key=self.config.api_key,
                    base_url=self.config.base_url,
                    timeout=self.config.timeout,
                )
            except ImportError:
                raise ImportError(
                    "OpenAI library not installed. Run: pip install openai"
                )
        return self._client

    def validate_config(self) -> bool:
        """Validate OpenAI configuration."""
        if not self.config.api_key:
            return False
        if self.config.model not in self.MODELS:
            return False
        return True

    def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        context_files: Optional[dict[str, str]] = None,
    ) -> ProviderResponse:
        """Generate completion using OpenAI API."""
        client = self._get_client()

        # Build messages
        messages = []

        # System prompt (guardrails)
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})

        # Context injection - simulate having files in context
        if context_files:
            context_content = self._format_context(context_files)
            messages.append({"role": "system", "content": context_content})

        # User prompt
        messages.append({"role": "user", "content": prompt})

        # Make request
        start_time = time.time()
        response = client.chat.completions.create(
            model=self.config.model,
            messages=messages,
            max_tokens=self.config.max_tokens,
            temperature=self.config.temperature,
        )
        latency_ms = (time.time() - start_time) * 1000

        # Rate limiting
        time.sleep(self.config.rate_limit_delay)

        return ProviderResponse(
            content=response.choices[0].message.content or "",
            model=response.model,
            provider=self.name,
            prompt_tokens=response.usage.prompt_tokens if response.usage else 0,
            completion_tokens=response.usage.completion_tokens if response.usage else 0,
            total_tokens=response.usage.total_tokens if response.usage else 0,
            finish_reason=response.choices[0].finish_reason or "",
            latency_ms=latency_ms,
            raw_response=response.model_dump() if hasattr(response, "model_dump") else None,
        )

    def _format_context(self, context_files: dict[str, str]) -> str:
        """Format context files as a system message."""
        lines = [
            "The following files are in the user's project repository:",
            "",
        ]
        for filepath, content in context_files.items():
            lines.append(f"--- {filepath} ---")
            lines.append(content)
            lines.append("")
        lines.append("Use these files as context when responding to the user's request.")
        return "\n".join(lines)


class AnthropicProvider(ProviderInterface):
    """Anthropic API provider (Claude 3, Claude 3.5)."""

    MODELS = [
        "claude-3-5-sonnet-20241022",
        "claude-3-5-haiku-20241022",
        "claude-3-opus-20240229",
        "claude-3-sonnet-20240229",
        "claude-3-haiku-20240307",
    ]

    def __init__(self, config: Optional[ProviderConfig] = None):
        """Initialize Anthropic provider."""
        self.config = config or ProviderConfig()
        self.config.api_key = self.config.api_key or os.environ.get("ANTHROPIC_API_KEY")
        self.config.model = self.config.model or "claude-3-5-sonnet-20241022"
        self._client: Any = None

    @property
    def name(self) -> str:
        return "anthropic"

    @property
    def supported_models(self) -> list[str]:
        return self.MODELS

    def _get_client(self) -> Any:
        """Lazy initialization of Anthropic client."""
        if self._client is None:
            try:
                import anthropic

                self._client = anthropic.Anthropic(
                    api_key=self.config.api_key,
                    timeout=self.config.timeout,
                )
            except ImportError:
                raise ImportError(
                    "Anthropic library not installed. Run: pip install anthropic"
                )
        return self._client

    def validate_config(self) -> bool:
        """Validate Anthropic configuration."""
        if not self.config.api_key:
            return False
        return True

    def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        context_files: Optional[dict[str, str]] = None,
    ) -> ProviderResponse:
        """Generate completion using Anthropic API."""
        client = self._get_client()

        # Build system content
        system_content = ""
        if system_prompt:
            system_content = system_prompt + "\n\n"
        if context_files:
            system_content += self._format_context(context_files)

        # Make request
        start_time = time.time()
        response = client.messages.create(
            model=self.config.model,
            max_tokens=self.config.max_tokens,
            system=system_content if system_content else None,
            messages=[{"role": "user", "content": prompt}],
        )
        latency_ms = (time.time() - start_time) * 1000

        # Rate limiting
        time.sleep(self.config.rate_limit_delay)

        content = ""
        if response.content:
            content = response.content[0].text if response.content else ""

        return ProviderResponse(
            content=content,
            model=response.model,
            provider=self.name,
            prompt_tokens=response.usage.input_tokens if response.usage else 0,
            completion_tokens=response.usage.output_tokens if response.usage else 0,
            total_tokens=(
                (response.usage.input_tokens + response.usage.output_tokens)
                if response.usage
                else 0
            ),
            finish_reason=response.stop_reason or "",
            latency_ms=latency_ms,
            raw_response=response.model_dump() if hasattr(response, "model_dump") else None,
        )

    def _format_context(self, context_files: dict[str, str]) -> str:
        """Format context files for system prompt."""
        lines = [
            "The following files are in the user's project repository:",
            "",
        ]
        for filepath, content in context_files.items():
            lines.append(f"<file path=\"{filepath}\">")
            lines.append(content)
            lines.append("</file>")
            lines.append("")
        lines.append("Use these files as context when responding to the user's request.")
        return "\n".join(lines)


class OllamaProvider(ProviderInterface):
    """Ollama provider for local model testing."""

    def __init__(self, config: Optional[ProviderConfig] = None):
        """Initialize Ollama provider."""
        self.config = config or ProviderConfig()
        self.config.base_url = self.config.base_url or "http://localhost:11434"
        self.config.model = self.config.model or "llama3.2"
        self._client: Any = None

    @property
    def name(self) -> str:
        return "ollama"

    @property
    def supported_models(self) -> list[str]:
        # Ollama supports many models - this is a common subset
        return ["llama3.2", "llama3.1", "codellama", "mistral", "qwen2.5-coder"]

    def _get_client(self) -> Any:
        """Lazy initialization of Ollama client."""
        if self._client is None:
            try:
                import ollama

                self._client = ollama.Client(host=self.config.base_url)
            except ImportError:
                raise ImportError(
                    "Ollama library not installed. Run: pip install ollama"
                )
        return self._client

    def validate_config(self) -> bool:
        """Validate Ollama is running."""
        try:
            client = self._get_client()
            client.list()  # Check connection
            return True
        except Exception:
            return False

    def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        context_files: Optional[dict[str, str]] = None,
    ) -> ProviderResponse:
        """Generate completion using Ollama."""
        client = self._get_client()

        # Build messages
        messages = []

        # System prompt
        system_content = ""
        if system_prompt:
            system_content = system_prompt
        if context_files:
            if system_content:
                system_content += "\n\n"
            system_content += self._format_context(context_files)

        if system_content:
            messages.append({"role": "system", "content": system_content})

        messages.append({"role": "user", "content": prompt})

        # Make request
        start_time = time.time()
        response = client.chat(
            model=self.config.model,
            messages=messages,
        )
        latency_ms = (time.time() - start_time) * 1000

        return ProviderResponse(
            content=response.get("message", {}).get("content", ""),
            model=self.config.model,
            provider=self.name,
            prompt_tokens=response.get("prompt_eval_count", 0),
            completion_tokens=response.get("eval_count", 0),
            total_tokens=(
                response.get("prompt_eval_count", 0) + response.get("eval_count", 0)
            ),
            finish_reason="stop",
            latency_ms=latency_ms,
            raw_response=response,
        )

    def _format_context(self, context_files: dict[str, str]) -> str:
        """Format context files."""
        lines = ["Project files:", ""]
        for filepath, content in context_files.items():
            lines.append(f"--- {filepath} ---")
            lines.append(content)
            lines.append("")
        return "\n".join(lines)


# Provider registry
PROVIDERS: dict[str, type[ProviderInterface]] = {
    "openai": OpenAIProvider,
    "anthropic": AnthropicProvider,
    "ollama": OllamaProvider,
}


def get_provider(
    name: str, config: Optional[ProviderConfig] = None
) -> ProviderInterface:
    """Get a provider instance by name.

    Args:
        name: Provider name ('openai', 'anthropic', 'ollama')
        config: Optional provider configuration

    Returns:
        Configured provider instance

    Raises:
        ValueError: If provider name is unknown
    """
    if name not in PROVIDERS:
        raise ValueError(
            f"Unknown provider: {name}. Available: {list(PROVIDERS.keys())}"
        )
    return PROVIDERS[name](config)


def list_providers() -> list[str]:
    """List available provider names."""
    return list(PROVIDERS.keys())
