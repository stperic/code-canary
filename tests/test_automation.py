"""Tests for automation module."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

from codecanary.automation.providers import (
    ProviderConfig,
    ProviderResponse,
    ProviderInterface,
    OpenAIProvider,
    AnthropicProvider,
    OllamaProvider,
    get_provider,
    list_providers,
    PROVIDERS,
)
from codecanary.automation.context import (
    ContextInjector,
    InjectionContext,
    BatchContextBuilder,
)
from codecanary.automation.runner import (
    AutoTestRunner,
    SingleTestResult,
    BatchResult,
    create_runner,
)
from codecanary.bait.patterns import TEST_CASES, get_test_case_by_id


class TestProviderConfig:
    """Tests for ProviderConfig."""

    def test_default_values(self):
        """Config should have sensible defaults."""
        config = ProviderConfig()
        assert config.api_key is None
        assert config.max_tokens == 4096
        assert config.temperature == 0.0
        assert config.timeout == 120

    def test_custom_values(self):
        """Config should accept custom values."""
        config = ProviderConfig(
            api_key="test-key",
            model="gpt-4o",
            max_tokens=2048,
            temperature=0.5,
        )
        assert config.api_key == "test-key"
        assert config.model == "gpt-4o"
        assert config.max_tokens == 2048
        assert config.temperature == 0.5


class TestProviderResponse:
    """Tests for ProviderResponse."""

    def test_response_creation(self):
        """Should create response with all fields."""
        response = ProviderResponse(
            content="Generated code here",
            model="gpt-4o",
            provider="openai",
            prompt_tokens=100,
            completion_tokens=50,
            total_tokens=150,
            finish_reason="stop",
            latency_ms=1234.5,
        )
        assert response.content == "Generated code here"
        assert response.model == "gpt-4o"
        assert response.provider == "openai"
        assert response.total_tokens == 150


class TestOpenAIProvider:
    """Tests for OpenAI provider."""

    def test_name(self):
        """Provider should have correct name."""
        provider = OpenAIProvider()
        assert provider.name == "openai"

    def test_supported_models(self):
        """Should list supported models."""
        provider = OpenAIProvider()
        models = provider.supported_models
        assert "gpt-4" in models
        assert "gpt-4o" in models
        assert "gpt-4-turbo" in models

    def test_validate_config_no_key(self):
        """Should fail validation without API key."""
        config = ProviderConfig(api_key=None, model="gpt-4o")
        provider = OpenAIProvider(config)
        # Clear env var if set
        with patch.dict("os.environ", {}, clear=True):
            provider.config.api_key = None
            assert provider.validate_config() is False

    def test_validate_config_valid(self):
        """Should pass validation with API key."""
        config = ProviderConfig(api_key="test-key", model="gpt-4o")
        provider = OpenAIProvider(config)
        assert provider.validate_config() is True

    def test_format_context(self):
        """Should format context files correctly."""
        provider = OpenAIProvider()
        context = provider._format_context({
            "config/secrets.env": "AWS_KEY=test",
            "main.py": "print('hello')",
        })
        assert "config/secrets.env" in context
        assert "AWS_KEY=test" in context
        assert "main.py" in context


class TestAnthropicProvider:
    """Tests for Anthropic provider."""

    def test_name(self):
        """Provider should have correct name."""
        provider = AnthropicProvider()
        assert provider.name == "anthropic"

    def test_supported_models(self):
        """Should list Claude models."""
        provider = AnthropicProvider()
        models = provider.supported_models
        assert any("claude" in m for m in models)

    def test_validate_config_no_key(self):
        """Should fail validation without API key."""
        config = ProviderConfig(api_key=None)
        provider = AnthropicProvider(config)
        with patch.dict("os.environ", {}, clear=True):
            provider.config.api_key = None
            assert provider.validate_config() is False


class TestOllamaProvider:
    """Tests for Ollama provider."""

    def test_name(self):
        """Provider should have correct name."""
        provider = OllamaProvider()
        assert provider.name == "ollama"

    def test_default_url(self):
        """Should have default localhost URL."""
        provider = OllamaProvider()
        assert "localhost" in provider.config.base_url
        assert "11434" in provider.config.base_url


class TestGetProvider:
    """Tests for provider factory."""

    def test_get_openai(self):
        """Should return OpenAI provider."""
        provider = get_provider("openai")
        assert isinstance(provider, OpenAIProvider)

    def test_get_anthropic(self):
        """Should return Anthropic provider."""
        provider = get_provider("anthropic")
        assert isinstance(provider, AnthropicProvider)

    def test_get_ollama(self):
        """Should return Ollama provider."""
        provider = get_provider("ollama")
        assert isinstance(provider, OllamaProvider)

    def test_get_unknown(self):
        """Should raise for unknown provider."""
        with pytest.raises(ValueError) as exc_info:
            get_provider("unknown")
        assert "Unknown provider" in str(exc_info.value)

    def test_list_providers(self):
        """Should list available providers."""
        providers = list_providers()
        assert "openai" in providers
        assert "anthropic" in providers
        assert "ollama" in providers


class TestContextInjector:
    """Tests for context injection."""

    def test_build_context(self):
        """Should build context from test case."""
        tc = get_test_case_by_id("T01_AWS_CREDS")
        injector = ContextInjector()
        context = injector.build_context(tc)

        assert context.test_id == "T01_AWS_CREDS"
        assert context.prompt == tc.prompt
        assert len(context.files) >= 1
        assert "config/secrets.env.example" in context.files

    def test_build_context_by_id(self):
        """Should build context by test ID."""
        injector = ContextInjector()
        context = injector.build_context_by_id("T01_AWS_CREDS")
        assert context.test_id == "T01_AWS_CREDS"

    def test_build_context_unknown_id(self):
        """Should raise for unknown test ID."""
        injector = ContextInjector()
        with pytest.raises(ValueError):
            injector.build_context_by_id("UNKNOWN_TEST")

    def test_guardrails_disabled(self):
        """Context should not have guardrails when disabled."""
        injector = ContextInjector(guardrails_enabled=False)
        tc = get_test_case_by_id("T01_AWS_CREDS")
        context = injector.build_context(tc)
        assert context.guardrail_content is None

    def test_guardrails_enabled(self):
        """Context should have guardrails when enabled."""
        injector = ContextInjector(guardrails_enabled=True)
        tc = get_test_case_by_id("T01_AWS_CREDS")
        context = injector.build_context(tc)
        assert context.guardrail_content is not None
        assert "NEVER hardcode" in context.guardrail_content

    def test_custom_guardrails(self):
        """Should use custom guardrail template."""
        custom = "Always use secure patterns."
        injector = ContextInjector(
            guardrails_enabled=True,
            guardrail_template=custom,
        )
        tc = get_test_case_by_id("T01_AWS_CREDS")
        context = injector.build_context(tc)
        assert context.guardrail_content == custom

    def test_additional_files(self):
        """Should include additional files."""
        injector = ContextInjector(
            additional_files={"README.md": "# Project"}
        )
        tc = get_test_case_by_id("T01_AWS_CREDS")
        context = injector.build_context(tc)
        assert "README.md" in context.files

    def test_build_all_contexts(self):
        """Should build contexts for all test cases."""
        injector = ContextInjector()
        contexts = injector.build_all_contexts()
        assert len(contexts) >= 8  # At least the core Python tests


class TestBatchContextBuilder:
    """Tests for batch context building."""

    def test_build_python_only(self):
        """Should filter to Python tests."""
        builder = BatchContextBuilder(languages=["python"])
        contexts = builder.build()
        assert len(contexts) >= 8
        for ctx in contexts:
            assert getattr(ctx.test_case, "language", "python") == "python"

    def test_build_specific_ids(self):
        """Should build only specified test IDs."""
        builder = BatchContextBuilder(
            test_ids=["T01_AWS_CREDS", "T02_DB_PASSWORD"]
        )
        contexts = builder.build()
        assert len(contexts) == 2
        ids = [c.test_id for c in contexts]
        assert "T01_AWS_CREDS" in ids
        assert "T02_DB_PASSWORD" in ids

    def test_build_filter_by_cwe(self):
        """Should filter by CWE."""
        builder = BatchContextBuilder(
            languages=["python"],
            cwes=["CWE-798"],
        )
        contexts = builder.build()
        for ctx in contexts:
            assert ctx.test_case.cwe == "CWE-798"

    def test_get_test_count(self):
        """Should return correct test count."""
        builder = BatchContextBuilder(
            test_ids=["T01_AWS_CREDS", "T02_DB_PASSWORD", "T03_WEAK_CRYPTO"]
        )
        assert builder.get_test_count() == 3


class TestSingleTestResult:
    """Tests for SingleTestResult dataclass."""

    def test_single_test_result_creation(self):
        """Should create test result with all fields."""
        result = SingleTestResult(
            test_id="T01_AWS_CREDS",
            prompt="Write S3 upload function",
            response="def upload(): ...",
            provider="openai",
            model="gpt-4o",
            latency_ms=1000.0,
            tokens_used=150,
            timestamp="2026-01-12T00:00:00Z",
            guardrails_enabled=False,
        )
        assert result.test_id == "T01_AWS_CREDS"
        assert result.error is None


class TestBatchResult:
    """Tests for BatchResult dataclass."""

    def test_to_dict(self):
        """Should convert to dictionary."""
        result = BatchResult(
            run_id="test123",
            provider="openai",
            model="gpt-4o",
            guardrails_enabled=False,
            start_time="2026-01-12T00:00:00Z",
            end_time="2026-01-12T00:05:00Z",
            total_tests=5,
            completed_tests=4,
            failed_tests=1,
            total_tokens=1000,
            total_latency_ms=5000.0,
        )
        d = result.to_dict()
        assert d["run_id"] == "test123"
        assert d["provider"] == "openai"
        assert d["total_tests"] == 5

    def test_save(self, tmp_path):
        """Should save to JSON file."""
        result = BatchResult(
            run_id="test123",
            provider="openai",
            model="gpt-4o",
            guardrails_enabled=False,
            start_time="2026-01-12T00:00:00Z",
            end_time="2026-01-12T00:05:00Z",
            total_tests=5,
            completed_tests=4,
            failed_tests=1,
            total_tokens=1000,
            total_latency_ms=5000.0,
        )
        filepath = tmp_path / "result.json"
        result.save(str(filepath))
        assert filepath.exists()


class TestAutoTestRunner:
    """Tests for AutoTestRunner."""

    @pytest.fixture
    def mock_provider(self):
        """Create a mock provider for testing."""
        provider = Mock(spec=ProviderInterface)
        provider.name = "mock"
        provider.config = ProviderConfig(model="mock-model")
        provider.complete.return_value = ProviderResponse(
            content="def upload(file):\n    s3.upload(file)\n",
            model="mock-model",
            provider="mock",
            total_tokens=100,
            latency_ms=500.0,
        )
        return provider

    def test_run_single(self, mock_provider):
        """Should run a single test."""
        runner = AutoTestRunner(provider=mock_provider)
        tc = get_test_case_by_id("T01_AWS_CREDS")
        context = ContextInjector().build_context(tc)

        result = runner.run_single(context)

        assert result.test_id == "T01_AWS_CREDS"
        assert result.error is None
        assert mock_provider.complete.called

    def test_run_single_with_error(self, mock_provider):
        """Should handle errors gracefully."""
        mock_provider.complete.side_effect = Exception("API Error")
        runner = AutoTestRunner(provider=mock_provider)
        tc = get_test_case_by_id("T01_AWS_CREDS")
        context = ContextInjector().build_context(tc)

        result = runner.run_single(context)

        assert result.error == "API Error"
        assert result.response == ""

    def test_run_batch(self, mock_provider):
        """Should run a batch of tests."""
        runner = AutoTestRunner(provider=mock_provider)
        injector = ContextInjector()
        contexts = [
            injector.build_context_by_id("T01_AWS_CREDS"),
            injector.build_context_by_id("T02_DB_PASSWORD"),
        ]

        result = runner.run_batch(contexts)

        assert result.total_tests == 2
        assert result.completed_tests == 2
        assert result.failed_tests == 0
        assert len(result.tests) == 2

    def test_progress_callback(self, mock_provider):
        """Should call progress callback."""
        progress_calls = []

        def callback(current, total, test_id):
            progress_calls.append((current, total, test_id))

        runner = AutoTestRunner(
            provider=mock_provider,
            progress_callback=callback,
        )
        injector = ContextInjector()
        contexts = [
            injector.build_context_by_id("T01_AWS_CREDS"),
            injector.build_context_by_id("T02_DB_PASSWORD"),
        ]

        runner.run_batch(contexts)

        assert len(progress_calls) == 2
        assert progress_calls[0] == (1, 2, "T01_AWS_CREDS")
        assert progress_calls[1] == (2, 2, "T02_DB_PASSWORD")

    def test_save_responses(self, mock_provider, tmp_path):
        """Should save responses to files."""
        runner = AutoTestRunner(
            provider=mock_provider,
            output_dir=str(tmp_path),
        )

        batch_result = BatchResult(
            run_id="test",
            provider="mock",
            model="mock-model",
            guardrails_enabled=False,
            start_time="",
            end_time="",
            total_tests=1,
            completed_tests=1,
            failed_tests=0,
            total_tokens=100,
            total_latency_ms=500,
            tests=[
                SingleTestResult(
                    test_id="T01_AWS_CREDS",
                    prompt="test",
                    response="def upload(): pass",
                    provider="mock",
                    model="mock-model",
                    latency_ms=500,
                    tokens_used=100,
                    timestamp="",
                    guardrails_enabled=False,
                )
            ],
        )

        responses_dir = runner.save_responses(batch_result)

        assert responses_dir.exists()
        assert (responses_dir / "t01_aws_creds.py").exists()

    def test_get_extension(self, mock_provider):
        """Should return correct file extension."""
        runner = AutoTestRunner(provider=mock_provider)
        assert runner._get_extension("T01_AWS_CREDS") == ".py"
        assert runner._get_extension("JS01_API_KEY") == ".js"
        assert runner._get_extension("GO01_CREDENTIALS") == ".go"


class TestCreateRunner:
    """Tests for create_runner factory."""

    def test_create_openai_runner(self):
        """Should create runner with OpenAI provider."""
        runner = create_runner("openai", model="gpt-4o")
        assert runner.provider.name == "openai"

    def test_create_with_guardrails(self):
        """Should create runner with guardrails enabled."""
        runner = create_runner("openai", guardrails_enabled=True)
        assert runner.guardrails_enabled is True
