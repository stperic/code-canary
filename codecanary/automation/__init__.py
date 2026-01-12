"""Automation module for CodeCanary.

Provides automated testing capabilities through:
- API-based testing (OpenAI, Anthropic, Ollama, Gemini, Mistral)
- Capture proxy for IDE responses (mitmproxy-based)
- Batch testing workflows
- A/B testing (guardrails vs no guardrails)
- Regression testing and tracking
"""

from codecanary.automation.providers import (
    ProviderInterface,
    ProviderConfig,
    ProviderResponse,
    OpenAIProvider,
    AnthropicProvider,
    OllamaProvider,
    GeminiProvider,
    MistralProvider,
    get_provider,
    list_providers,
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
from codecanary.automation.batch import (
    ABTester,
    ABTestConfig,
    ABTestResult,
    RegressionTester,
    RegressionHistory,
    RegressionRun,
)
from codecanary.automation.proxy import (
    CaptureProxy,
    CapturedResponse,
    ResponseStorage,
    ProxyConfig,
    detect_assistant,
    create_proxy_script,
)

__all__ = [
    # Providers
    "ProviderInterface",
    "ProviderConfig",
    "ProviderResponse",
    "OpenAIProvider",
    "AnthropicProvider",
    "OllamaProvider",
    "GeminiProvider",
    "MistralProvider",
    "get_provider",
    "list_providers",
    # Context
    "ContextInjector",
    "InjectionContext",
    "BatchContextBuilder",
    # Runner
    "AutoTestRunner",
    "SingleTestResult",
    "BatchResult",
    "create_runner",
    # Batch / A/B Testing
    "ABTester",
    "ABTestConfig",
    "ABTestResult",
    # Regression
    "RegressionTester",
    "RegressionHistory",
    "RegressionRun",
    # Proxy
    "CaptureProxy",
    "CapturedResponse",
    "ResponseStorage",
    "ProxyConfig",
    "detect_assistant",
    "create_proxy_script",
]
