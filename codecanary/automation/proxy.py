"""Capture proxy for intercepting AI assistant responses.

Uses mitmproxy to capture responses from AI coding assistants
when testing through IDEs like Cursor, VS Code, etc.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Callable, Any
import json
import sqlite3
import re
import threading


@dataclass
class CapturedResponse:
    """A captured AI assistant response."""

    id: str
    timestamp: str
    assistant: str  # cursor, claude-code, copilot, windsurf
    url: str
    request_body: Optional[str]
    response_body: str
    latency_ms: float
    content_type: str
    status_code: int

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "assistant": self.assistant,
            "url": self.url,
            "request_body": self.request_body,
            "response_body": self.response_body,
            "latency_ms": self.latency_ms,
            "content_type": self.content_type,
            "status_code": self.status_code,
        }


class ResponseStorage:
    """SQLite storage for captured responses."""

    def __init__(self, db_path: str = "./captured_responses.db"):
        """Initialize storage.

        Args:
            db_path: Path to SQLite database
        """
        self.db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        """Initialize database schema."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS responses (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                assistant TEXT NOT NULL,
                url TEXT NOT NULL,
                request_body TEXT,
                response_body TEXT NOT NULL,
                latency_ms REAL,
                content_type TEXT,
                status_code INTEGER
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_timestamp ON responses(timestamp)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_assistant ON responses(assistant)
        """)
        conn.commit()
        conn.close()

    def save(self, response: CapturedResponse) -> None:
        """Save a captured response."""
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            """
            INSERT OR REPLACE INTO responses
            (id, timestamp, assistant, url, request_body, response_body,
             latency_ms, content_type, status_code)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                response.id,
                response.timestamp,
                response.assistant,
                response.url,
                response.request_body,
                response.response_body,
                response.latency_ms,
                response.content_type,
                response.status_code,
            ),
        )
        conn.commit()
        conn.close()

    def get_all(self, assistant: Optional[str] = None) -> list[CapturedResponse]:
        """Get all captured responses.

        Args:
            assistant: Filter by assistant name

        Returns:
            List of captured responses
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row

        if assistant:
            cursor = conn.execute(
                "SELECT * FROM responses WHERE assistant = ? ORDER BY timestamp DESC",
                (assistant,),
            )
        else:
            cursor = conn.execute(
                "SELECT * FROM responses ORDER BY timestamp DESC"
            )

        responses = [
            CapturedResponse(
                id=row["id"],
                timestamp=row["timestamp"],
                assistant=row["assistant"],
                url=row["url"],
                request_body=row["request_body"],
                response_body=row["response_body"],
                latency_ms=row["latency_ms"],
                content_type=row["content_type"],
                status_code=row["status_code"],
            )
            for row in cursor.fetchall()
        ]
        conn.close()
        return responses

    def get_by_id(self, response_id: str) -> Optional[CapturedResponse]:
        """Get a response by ID."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            "SELECT * FROM responses WHERE id = ?", (response_id,)
        )
        row = cursor.fetchone()
        conn.close()

        if row:
            return CapturedResponse(
                id=row["id"],
                timestamp=row["timestamp"],
                assistant=row["assistant"],
                url=row["url"],
                request_body=row["request_body"],
                response_body=row["response_body"],
                latency_ms=row["latency_ms"],
                content_type=row["content_type"],
                status_code=row["status_code"],
            )
        return None

    def count(self, assistant: Optional[str] = None) -> int:
        """Count captured responses."""
        conn = sqlite3.connect(self.db_path)
        if assistant:
            cursor = conn.execute(
                "SELECT COUNT(*) FROM responses WHERE assistant = ?",
                (assistant,),
            )
        else:
            cursor = conn.execute("SELECT COUNT(*) FROM responses")
        count = cursor.fetchone()[0]
        conn.close()
        return count

    def clear(self) -> None:
        """Clear all captured responses."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("DELETE FROM responses")
        conn.commit()
        conn.close()

    def export_to_files(
        self, output_dir: str, assistant: Optional[str] = None
    ) -> int:
        """Export responses to files for scanning.

        Args:
            output_dir: Directory to save response files
            assistant: Filter by assistant

        Returns:
            Number of files exported
        """
        responses = self.get_all(assistant)
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        for i, resp in enumerate(responses):
            # Extract code from response if possible
            content = self._extract_code(resp.response_body)
            ext = self._guess_extension(content)
            filename = f"response_{i:04d}_{resp.assistant}{ext}"
            (output_path / filename).write_text(content, encoding="utf-8")

        return len(responses)

    def _extract_code(self, response_body: str) -> str:
        """Extract code from response body."""
        # Try to parse as JSON first (API response)
        try:
            data = json.loads(response_body)
            # Handle OpenAI-style response
            if "choices" in data:
                return data["choices"][0].get("message", {}).get("content", "")
            # Handle Anthropic-style response
            if "content" in data:
                content = data["content"]
                if isinstance(content, list) and content:
                    return content[0].get("text", "")
                return str(content)
            return response_body
        except json.JSONDecodeError:
            return response_body

    def _guess_extension(self, content: str) -> str:
        """Guess file extension from content."""
        if "def " in content or "import " in content:
            return ".py"
        if "function " in content or "const " in content:
            return ".js"
        if "func " in content or "package " in content:
            return ".go"
        return ".txt"


# Assistant detection patterns
ASSISTANT_PATTERNS = {
    "cursor": [
        r"api\.cursor\.sh",
        r"cursor-ai",
        r"cursorai",
    ],
    "claude-code": [
        r"claude\.ai",
        r"anthropic.*claude",
        r"claude-code",
    ],
    "copilot": [
        r"copilot\.github",
        r"github\.copilot",
        r"api\.github\.com/copilot",
    ],
    "windsurf": [
        r"windsurf",
        r"codeium",
    ],
    "openai": [
        r"api\.openai\.com",
    ],
    "anthropic": [
        r"api\.anthropic\.com",
    ],
}


def detect_assistant(url: str) -> str:
    """Detect which AI assistant a request is for.

    Args:
        url: Request URL

    Returns:
        Assistant name or 'unknown'
    """
    for assistant, patterns in ASSISTANT_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return assistant
    return "unknown"


class ProxyConfig:
    """Configuration for the capture proxy."""

    def __init__(
        self,
        listen_host: str = "127.0.0.1",
        listen_port: int = 8080,
        db_path: str = "./captured_responses.db",
        capture_requests: bool = True,
        filter_assistants: Optional[list[str]] = None,
    ):
        """Initialize proxy configuration.

        Args:
            listen_host: Host to listen on
            listen_port: Port to listen on
            db_path: Path to SQLite database
            capture_requests: Whether to capture request bodies
            filter_assistants: Only capture these assistants (None = all)
        """
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.db_path = db_path
        self.capture_requests = capture_requests
        self.filter_assistants = filter_assistants


class CaptureProxy:
    """mitmproxy-based capture proxy for AI assistant responses.

    Usage:
        1. Install mitmproxy: pip install mitmproxy
        2. Start proxy: codecanary proxy start
        3. Configure IDE to use proxy (127.0.0.1:8080)
        4. Install mitmproxy CA certificate
        5. Use IDE normally - responses are captured
        6. Export responses: codecanary proxy export
    """

    def __init__(
        self,
        config: Optional[ProxyConfig] = None,
        on_response: Optional[Callable[[CapturedResponse], None]] = None,
    ):
        """Initialize capture proxy.

        Args:
            config: Proxy configuration
            on_response: Callback when response is captured
        """
        self.config = config or ProxyConfig()
        self.storage = ResponseStorage(self.config.db_path)
        self.on_response = on_response
        self._running = False
        self._response_count = 0

    def create_addon(self) -> Any:
        """Create mitmproxy addon for capturing responses.

        Returns:
            mitmproxy addon class instance
        """
        proxy = self

        class CaptureAddon:
            """mitmproxy addon that captures AI responses."""

            def response(self, flow: Any) -> None:
                """Called when a response is received."""
                import time
                from mitmproxy import http

                if not isinstance(flow, http.HTTPFlow):
                    return

                url = flow.request.pretty_url
                assistant = detect_assistant(url)

                # Filter by assistant if configured
                if (
                    proxy.config.filter_assistants
                    and assistant not in proxy.config.filter_assistants
                    and assistant != "unknown"
                ):
                    return

                # Skip non-AI traffic
                if assistant == "unknown":
                    return

                # Calculate latency
                latency_ms = 0.0
                if flow.response and flow.request:
                    if hasattr(flow, "timestamp_end") and hasattr(
                        flow, "timestamp_start"
                    ):
                        latency_ms = (
                            flow.timestamp_end - flow.timestamp_start
                        ) * 1000

                # Capture request body if configured
                request_body = None
                if proxy.config.capture_requests and flow.request.content:
                    try:
                        request_body = flow.request.content.decode("utf-8")
                    except UnicodeDecodeError:
                        request_body = None

                # Capture response body
                response_body = ""
                if flow.response and flow.response.content:
                    try:
                        response_body = flow.response.content.decode("utf-8")
                    except UnicodeDecodeError:
                        response_body = ""

                # Create captured response
                proxy._response_count += 1
                captured = CapturedResponse(
                    id=f"cap_{proxy._response_count}_{int(time.time())}",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    assistant=assistant,
                    url=url,
                    request_body=request_body,
                    response_body=response_body,
                    latency_ms=latency_ms,
                    content_type=flow.response.headers.get(
                        "content-type", ""
                    ) if flow.response else "",
                    status_code=flow.response.status_code if flow.response else 0,
                )

                # Save to storage
                proxy.storage.save(captured)

                # Call callback if provided
                if proxy.on_response:
                    proxy.on_response(captured)

        return CaptureAddon()

    def get_mitmproxy_options(self) -> list[str]:
        """Get mitmproxy command line options.

        Returns:
            List of command line arguments
        """
        return [
            "--listen-host",
            self.config.listen_host,
            "--listen-port",
            str(self.config.listen_port),
            "--set",
            "ssl_insecure=true",
        ]

    def export_responses(
        self, output_dir: str, assistant: Optional[str] = None
    ) -> int:
        """Export captured responses to files.

        Args:
            output_dir: Directory to save files
            assistant: Filter by assistant

        Returns:
            Number of files exported
        """
        return self.storage.export_to_files(output_dir, assistant)

    def get_stats(self) -> dict:
        """Get capture statistics.

        Returns:
            Dict with statistics
        """
        all_responses = self.storage.get_all()
        by_assistant: dict[str, int] = {}
        for resp in all_responses:
            by_assistant[resp.assistant] = by_assistant.get(resp.assistant, 0) + 1

        return {
            "total_captured": len(all_responses),
            "by_assistant": by_assistant,
            "session_captured": self._response_count,
        }

    def clear_storage(self) -> None:
        """Clear all captured responses."""
        self.storage.clear()
        self._response_count = 0


def create_proxy_script(config: Optional[ProxyConfig] = None) -> str:
    """Generate a mitmproxy script for standalone use.

    Args:
        config: Proxy configuration

    Returns:
        Python script content
    """
    config = config or ProxyConfig()
    return f'''#!/usr/bin/env python3
"""CodeCanary Capture Proxy Script.

Run with: mitmdump -s capture_proxy.py
"""

import sqlite3
import json
import re
import time
from datetime import datetime, timezone
from mitmproxy import http

DB_PATH = "{config.db_path}"

# Initialize database
conn = sqlite3.connect(DB_PATH)
conn.execute("""
    CREATE TABLE IF NOT EXISTS responses (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        assistant TEXT NOT NULL,
        url TEXT NOT NULL,
        request_body TEXT,
        response_body TEXT NOT NULL,
        latency_ms REAL,
        content_type TEXT,
        status_code INTEGER
    )
""")
conn.commit()
conn.close()

ASSISTANT_PATTERNS = {{
    "cursor": [r"api\\.cursor\\.sh", r"cursor-ai", r"cursorai"],
    "copilot": [r"copilot\\.github", r"github\\.copilot", r"api\\.github\\.com/copilot"],
    "windsurf": [r"windsurf", r"codeium"],
    "openai": [r"api\\.openai\\.com"],
    "anthropic": [r"api\\.anthropic\\.com"],
}}

response_count = 0

def detect_assistant(url: str) -> str:
    for assistant, patterns in ASSISTANT_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return assistant
    return "unknown"

def response(flow: http.HTTPFlow) -> None:
    global response_count
    
    url = flow.request.pretty_url
    assistant = detect_assistant(url)
    
    if assistant == "unknown":
        return
    
    response_count += 1
    
    request_body = None
    if flow.request.content:
        try:
            request_body = flow.request.content.decode("utf-8")
        except UnicodeDecodeError:
            pass
    
    response_body = ""
    if flow.response and flow.response.content:
        try:
            response_body = flow.response.content.decode("utf-8")
        except UnicodeDecodeError:
            pass
    
    captured_id = f"cap_{{response_count}}_{{int(time.time())}}"
    timestamp = datetime.now(timezone.utc).isoformat()
    content_type = flow.response.headers.get("content-type", "") if flow.response else ""
    status_code = flow.response.status_code if flow.response else 0
    
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """INSERT OR REPLACE INTO responses
           (id, timestamp, assistant, url, request_body, response_body, 
            latency_ms, content_type, status_code)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (captured_id, timestamp, assistant, url, request_body, response_body,
         0.0, content_type, status_code)
    )
    conn.commit()
    conn.close()
    
    print(f"[CodeCanary] Captured: {{assistant}} - {{len(response_body)}} bytes")
'''
