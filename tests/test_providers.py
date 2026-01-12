"""Tests for AI provider adapters."""

import pytest
from unittest.mock import Mock, patch, MagicMock

from codecanary.automation.providers import (
    ProviderConfig,
    ProviderResponse,
    OpenAIProvider,
    AnthropicProvider,
    OllamaProvider,
    GeminiProvider,
    MistralProvider,
    get_provider,
    list_providers,
    PROVIDERS,
)


class TestGeminiProvider:
    """Tests for Google Gemini provider."""

    def test_name(self):
        """Provider should have correct name."""
        provider = GeminiProvider()
        assert provider.name == "gemini"

    def test_supported_models(self):
        """Should list Gemini models."""
        provider = GeminiProvider()
        models = provider.supported_models
        assert "gemini-1.5-pro" in models
        assert "gemini-1.5-flash" in models
        assert "gemini-2.0-flash-exp" in models

    def test_default_model(self):
        """Should default to gemini-1.5-flash."""
        provider = GeminiProvider()
        assert provider.config.model == "gemini-1.5-flash"

    def test_validate_config_no_key(self):
        """Should fail validation without API key."""
        config = ProviderConfig(api_key=None)
        provider = GeminiProvider(config)
        with patch.dict("os.environ", {}, clear=True):
            provider.config.api_key = None
            assert provider.validate_config() is False

    def test_validate_config_with_key(self):
        """Should pass validation with API key."""
        config = ProviderConfig(api_key="test-key")
        provider = GeminiProvider(config)
        assert provider.validate_config() is True

    def test_format_context(self):
        """Should format context correctly."""
        provider = GeminiProvider()
        context = provider._format_context({
            "config.py": "API_KEY = 'xxx'",
        })
        assert "config.py" in context
        assert "API_KEY" in context

    def test_uses_google_api_key_env(self):
        """Should use GOOGLE_API_KEY environment variable."""
        with patch.dict("os.environ", {"GOOGLE_API_KEY": "env-key"}):
            config = ProviderConfig()
            provider = GeminiProvider(config)
            assert provider.config.api_key == "env-key"


class TestMistralProvider:
    """Tests for Mistral provider."""

    def test_name(self):
        """Provider should have correct name."""
        provider = MistralProvider()
        assert provider.name == "mistral"

    def test_supported_models(self):
        """Should list Mistral models."""
        provider = MistralProvider()
        models = provider.supported_models
        assert "mistral-large-latest" in models
        assert "codestral-latest" in models
        assert "open-mistral-7b" in models

    def test_default_model(self):
        """Should default to mistral-small-latest."""
        provider = MistralProvider()
        assert provider.config.model == "mistral-small-latest"

    def test_validate_config_no_key(self):
        """Should fail validation without API key."""
        config = ProviderConfig(api_key=None)
        provider = MistralProvider(config)
        with patch.dict("os.environ", {}, clear=True):
            provider.config.api_key = None
            assert provider.validate_config() is False

    def test_validate_config_with_key(self):
        """Should pass validation with API key."""
        config = ProviderConfig(api_key="test-key")
        provider = MistralProvider(config)
        assert provider.validate_config() is True

    def test_format_context(self):
        """Should format context with code blocks."""
        provider = MistralProvider()
        context = provider._format_context({
            "main.py": "print('hello')",
        })
        assert "```main.py" in context
        assert "print('hello')" in context

    def test_uses_mistral_api_key_env(self):
        """Should use MISTRAL_API_KEY environment variable."""
        with patch.dict("os.environ", {"MISTRAL_API_KEY": "env-key"}):
            config = ProviderConfig()
            provider = MistralProvider(config)
            assert provider.config.api_key == "env-key"


class TestProviderRegistry:
    """Tests for provider registry."""

    def test_gemini_in_registry(self):
        """Gemini should be in provider registry."""
        assert "gemini" in PROVIDERS
        assert PROVIDERS["gemini"] == GeminiProvider

    def test_mistral_in_registry(self):
        """Mistral should be in provider registry."""
        assert "mistral" in PROVIDERS
        assert PROVIDERS["mistral"] == MistralProvider

    def test_get_gemini_provider(self):
        """Should return Gemini provider."""
        provider = get_provider("gemini")
        assert isinstance(provider, GeminiProvider)

    def test_get_mistral_provider(self):
        """Should return Mistral provider."""
        provider = get_provider("mistral")
        assert isinstance(provider, MistralProvider)

    def test_list_all_providers(self):
        """Should list all providers."""
        providers = list_providers()
        assert "openai" in providers
        assert "anthropic" in providers
        assert "ollama" in providers
        assert "gemini" in providers
        assert "mistral" in providers
        assert len(providers) == 5


class TestProviderIntegration:
    """Integration-style tests for providers."""

    @pytest.fixture
    def mock_gemini_response(self):
        """Create a mock Gemini response."""
        mock_response = MagicMock()
        mock_response.text = "def secure_function(): pass"
        mock_response.candidates = [MagicMock()]
        mock_response.candidates[0].finish_reason.name = "STOP"
        mock_response.usage_metadata = MagicMock()
        mock_response.usage_metadata.prompt_token_count = 100
        mock_response.usage_metadata.candidates_token_count = 50
        return mock_response

    @pytest.fixture
    def mock_mistral_response(self):
        """Create a mock Mistral response."""
        mock_response = MagicMock()
        mock_response.model = "mistral-small-latest"
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "def secure_function(): pass"
        mock_response.choices[0].finish_reason = "stop"
        mock_response.usage = MagicMock()
        mock_response.usage.prompt_tokens = 100
        mock_response.usage.completion_tokens = 50
        mock_response.usage.total_tokens = 150
        mock_response.model_dump.return_value = {}
        return mock_response

    def test_gemini_complete_mock(self, mock_gemini_response):
        """Should call Gemini API correctly."""
        with patch("codecanary.automation.providers.GeminiProvider._get_model") as mock_get:
            mock_model = MagicMock()
            mock_model.generate_content.return_value = mock_gemini_response
            mock_get.return_value = mock_model

            config = ProviderConfig(api_key="test", model="gemini-1.5-flash")
            provider = GeminiProvider(config)
            provider.config.rate_limit_delay = 0  # Skip delay in tests

            response = provider.complete(
                prompt="Write a secure function",
                system_prompt="Be secure",
                context_files={"main.py": "# code"},
            )

            assert response.content == "def secure_function(): pass"
            assert response.provider == "gemini"
            mock_model.generate_content.assert_called_once()

    def test_mistral_complete_mock(self, mock_mistral_response):
        """Should call Mistral API correctly."""
        with patch("codecanary.automation.providers.MistralProvider._get_client") as mock_get:
            mock_client = MagicMock()
            mock_client.chat.complete.return_value = mock_mistral_response
            mock_get.return_value = mock_client

            config = ProviderConfig(api_key="test", model="mistral-small-latest")
            provider = MistralProvider(config)
            provider.config.rate_limit_delay = 0  # Skip delay in tests

            response = provider.complete(
                prompt="Write a secure function",
                system_prompt="Be secure",
                context_files={"main.py": "# code"},
            )

            assert response.content == "def secure_function(): pass"
            assert response.provider == "mistral"
            mock_client.chat.complete.assert_called_once()
