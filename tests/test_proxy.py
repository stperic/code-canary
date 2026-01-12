"""Tests for capture proxy module."""

import pytest
import tempfile
from pathlib import Path

from codecanary.automation.proxy import (
    CapturedResponse,
    ResponseStorage,
    ProxyConfig,
    CaptureProxy,
    detect_assistant,
    create_proxy_script,
    ASSISTANT_PATTERNS,
)


class TestCapturedResponse:
    """Tests for CapturedResponse dataclass."""

    def test_creation(self):
        """Should create response with all fields."""
        resp = CapturedResponse(
            id="cap_1",
            timestamp="2026-01-12T00:00:00Z",
            assistant="cursor",
            url="https://api.cursor.sh/chat",
            request_body='{"prompt": "test"}',
            response_body='{"content": "response"}',
            latency_ms=500.0,
            content_type="application/json",
            status_code=200,
        )
        assert resp.id == "cap_1"
        assert resp.assistant == "cursor"
        assert resp.status_code == 200

    def test_to_dict(self):
        """Should convert to dictionary."""
        resp = CapturedResponse(
            id="cap_1",
            timestamp="2026-01-12T00:00:00Z",
            assistant="cursor",
            url="https://api.cursor.sh/chat",
            request_body=None,
            response_body="test",
            latency_ms=100.0,
            content_type="text/plain",
            status_code=200,
        )
        d = resp.to_dict()
        assert d["id"] == "cap_1"
        assert d["assistant"] == "cursor"


class TestResponseStorage:
    """Tests for ResponseStorage."""

    @pytest.fixture
    def storage(self, tmp_path):
        """Create a temporary storage."""
        db_path = tmp_path / "test.db"
        return ResponseStorage(str(db_path))

    @pytest.fixture
    def sample_response(self):
        """Create a sample response."""
        return CapturedResponse(
            id="cap_1",
            timestamp="2026-01-12T00:00:00Z",
            assistant="cursor",
            url="https://api.cursor.sh/chat",
            request_body='{"prompt": "test"}',
            response_body='def hello(): return "world"',
            latency_ms=500.0,
            content_type="application/json",
            status_code=200,
        )

    def test_save_and_get(self, storage, sample_response):
        """Should save and retrieve response."""
        storage.save(sample_response)
        
        retrieved = storage.get_by_id("cap_1")
        assert retrieved is not None
        assert retrieved.assistant == "cursor"
        assert retrieved.response_body == 'def hello(): return "world"'

    def test_get_all(self, storage, sample_response):
        """Should get all responses."""
        storage.save(sample_response)
        
        # Add another response
        resp2 = CapturedResponse(
            id="cap_2",
            timestamp="2026-01-12T00:01:00Z",
            assistant="copilot",
            url="https://api.github.com/copilot",
            request_body=None,
            response_body="test",
            latency_ms=100.0,
            content_type="text/plain",
            status_code=200,
        )
        storage.save(resp2)

        all_resp = storage.get_all()
        assert len(all_resp) == 2

    def test_get_all_filter_by_assistant(self, storage, sample_response):
        """Should filter by assistant."""
        storage.save(sample_response)
        
        resp2 = CapturedResponse(
            id="cap_2",
            timestamp="2026-01-12T00:01:00Z",
            assistant="copilot",
            url="https://api.github.com/copilot",
            request_body=None,
            response_body="test",
            latency_ms=100.0,
            content_type="text/plain",
            status_code=200,
        )
        storage.save(resp2)

        cursor_only = storage.get_all(assistant="cursor")
        assert len(cursor_only) == 1
        assert cursor_only[0].assistant == "cursor"

    def test_count(self, storage, sample_response):
        """Should count responses."""
        assert storage.count() == 0
        storage.save(sample_response)
        assert storage.count() == 1

    def test_clear(self, storage, sample_response):
        """Should clear all responses."""
        storage.save(sample_response)
        assert storage.count() == 1
        
        storage.clear()
        assert storage.count() == 0

    def test_export_to_files(self, storage, sample_response, tmp_path):
        """Should export responses to files."""
        storage.save(sample_response)
        
        output_dir = tmp_path / "export"
        count = storage.export_to_files(str(output_dir))
        
        assert count == 1
        assert output_dir.exists()
        files = list(output_dir.glob("*"))
        assert len(files) == 1


class TestDetectAssistant:
    """Tests for assistant detection."""

    def test_detect_cursor(self):
        """Should detect Cursor."""
        assert detect_assistant("https://api.cursor.sh/v1/chat") == "cursor"
        assert detect_assistant("https://cursorai.com/api") == "cursor"

    def test_detect_claude_code(self):
        """Should detect Claude Code."""
        assert detect_assistant("https://claude.ai/api/chat") == "claude-code"
        assert detect_assistant("https://anthropic.com/claude-code/v1") == "claude-code"

    def test_detect_copilot(self):
        """Should detect Copilot."""
        assert detect_assistant("https://api.github.com/copilot/chat") == "copilot"
        assert detect_assistant("https://copilot.github.com/v1") == "copilot"

    def test_detect_openai(self):
        """Should detect OpenAI."""
        assert detect_assistant("https://api.openai.com/v1/chat") == "openai"

    def test_detect_anthropic(self):
        """Should detect Anthropic."""
        assert detect_assistant("https://api.anthropic.com/v1/messages") == "anthropic"

    def test_detect_unknown(self):
        """Should return unknown for unrecognized URLs."""
        assert detect_assistant("https://example.com/api") == "unknown"


class TestProxyConfig:
    """Tests for ProxyConfig."""

    def test_defaults(self):
        """Should have sensible defaults."""
        config = ProxyConfig()
        assert config.listen_host == "127.0.0.1"
        assert config.listen_port == 8080
        assert config.capture_requests is True

    def test_custom_values(self):
        """Should accept custom values."""
        config = ProxyConfig(
            listen_host="0.0.0.0",
            listen_port=9090,
            filter_assistants=["cursor"],
        )
        assert config.listen_host == "0.0.0.0"
        assert config.listen_port == 9090
        assert config.filter_assistants == ["cursor"]


class TestCaptureProxy:
    """Tests for CaptureProxy."""

    @pytest.fixture
    def proxy(self, tmp_path):
        """Create a test proxy."""
        config = ProxyConfig(db_path=str(tmp_path / "test.db"))
        return CaptureProxy(config)

    def test_get_mitmproxy_options(self, proxy):
        """Should return mitmproxy options."""
        options = proxy.get_mitmproxy_options()
        assert "--listen-host" in options
        assert "--listen-port" in options
        assert "8080" in options

    def test_get_stats(self, proxy):
        """Should return stats."""
        stats = proxy.get_stats()
        assert "total_captured" in stats
        assert "by_assistant" in stats
        assert "session_captured" in stats

    def test_export_responses(self, proxy, tmp_path):
        """Should export responses."""
        # Add a response to storage
        resp = CapturedResponse(
            id="cap_1",
            timestamp="2026-01-12T00:00:00Z",
            assistant="cursor",
            url="https://api.cursor.sh/chat",
            request_body=None,
            response_body="def test(): pass",
            latency_ms=100.0,
            content_type="text/plain",
            status_code=200,
        )
        proxy.storage.save(resp)

        output_dir = tmp_path / "export"
        count = proxy.export_responses(str(output_dir))
        assert count == 1

    def test_clear_storage(self, proxy):
        """Should clear storage."""
        resp = CapturedResponse(
            id="cap_1",
            timestamp="2026-01-12T00:00:00Z",
            assistant="cursor",
            url="https://api.cursor.sh/chat",
            request_body=None,
            response_body="test",
            latency_ms=100.0,
            content_type="text/plain",
            status_code=200,
        )
        proxy.storage.save(resp)
        assert proxy.storage.count() == 1

        proxy.clear_storage()
        assert proxy.storage.count() == 0


class TestCreateProxyScript:
    """Tests for proxy script generation."""

    def test_creates_valid_script(self):
        """Should create a valid Python script."""
        script = create_proxy_script()
        assert "#!/usr/bin/env python3" in script
        assert "def response(" in script
        assert "sqlite3" in script
        assert "CodeCanary" in script

    def test_uses_config(self):
        """Should use config values in script."""
        config = ProxyConfig(db_path="/custom/path.db")
        script = create_proxy_script(config)
        assert "/custom/path.db" in script
