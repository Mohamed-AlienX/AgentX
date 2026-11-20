"""Coverage top-up tests: burp client, mcp client/manager, recon pipeline.

Hermetic: MockTransport for HTTP, monkeypatched transports for MCP,
mocked installer/tool_wrapper for the recon pipeline. No real network/process.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from agentx.config import MCPConfig
from agentx.integrations.burp import BurpClient
from agentx.mcp.client import session_scope
from agentx.mcp.manager import (
    MAX_TOOL_RESULT_CHARS,
    MCPManager,
    _ManagedConnection,
    _render_result,
)
from agentx.recon.pipeline import ReconPipeline
from agentx.skills.base import ToolResult

# ---------------------------------------------------------------------------
# burp.py - httpx.MockTransport helpers
# ---------------------------------------------------------------------------


def _patch_burp_http(monkeypatch: pytest.MonkeyPatch, handler) -> list[httpx.Request]:
    """Route every AsyncClient created by burp.py through a MockTransport."""
    seen: list[httpx.Request] = []

    def recording_handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    transport = httpx.MockTransport(recording_handler)
    real_client = httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs["transport"] = transport
        return real_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)
    return seen


def _burp_client() -> BurpClient:
    return BurpClient(host="127.0.0.1", port=9999, api_key="secret-key")


class TestBurpIsAlive:
    async def test_alive_on_2xx(self, monkeypatch: pytest.MonkeyPatch) -> None:
        seen = _patch_burp_http(monkeypatch, lambda req: httpx.Response(200, json={"status": "up"}))
        assert await _burp_client().is_alive() is True
        assert str(seen[0].url) == "http://127.0.0.1:9999/"
        assert seen[0].method == "GET"
        assert seen[0].headers["Authorization"] == "Bearer secret-key"
        assert seen[0].headers["Content-Type"] == "application/json"

    async def test_alive_false_on_5xx(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_burp_http(monkeypatch, lambda req: httpx.Response(503, text="down"))
        assert await _burp_client().is_alive() is False

    async def test_alive_false_on_connection_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def boom(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused", request=request)

        _patch_burp_http(monkeypatch, boom)
        assert await _burp_client().is_alive() is False


class TestBurpProxyHistory:
    async def test_get_proxy_history_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        payload = [{"request": "GET /", "status": 200}]
        seen = _patch_burp_http(monkeypatch, lambda req: httpx.Response(200, json=payload))
        result = await _burp_client().get_proxy_history()
        assert result == payload
        assert str(seen[0].url) == "http://127.0.0.1:9999/v0.1/proxy/history"
        assert seen[0].method == "GET"

    async def test_get_proxy_history_raises_on_http_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_burp_http(monkeypatch, lambda req: httpx.Response(500, text="err"))
        with pytest.raises(httpx.HTTPStatusError):
            await _burp_client().get_proxy_history()


class TestBurpRepeater:
    async def test_send_to_repeater_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        seen = _patch_burp_http(monkeypatch, lambda req: httpx.Response(200, json={}))
        ok = await _burp_client().send_to_repeater("GET / HTTP/1.1", "example.com", 443)
        assert ok is True
        assert str(seen[0].url) == "http://127.0.0.1:9999/v0.1/repeater"
        assert seen[0].method == "POST"
        body = seen[0].read()
        assert b'"targetHostname":"example.com"' in body
        assert b'"targetPort":443' in body
        assert b'"usesHttps":true' in body
        assert b'"request":"GET / HTTP/1.1"' in body

    async def test_send_to_repeater_false_on_4xx(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_burp_http(monkeypatch, lambda req: httpx.Response(400, json={}))
        ok = await _burp_client().send_to_repeater("req", "h", 80, https=False)
        assert ok is False


class TestBurpScope:
    async def test_get_scope_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        scope = {"target": {"include": [{"host": "example.com"}]}}
        seen = _patch_burp_http(monkeypatch, lambda req: httpx.Response(200, json=scope))
        assert await _burp_client().get_scope() == scope
        assert str(seen[0].url) == "http://127.0.0.1:9999/v0.1/target/scope"
        assert seen[0].method == "GET"

    async def test_get_scope_raises_on_http_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_burp_http(monkeypatch, lambda req: httpx.Response(404, text="nope"))
        with pytest.raises(httpx.HTTPStatusError):
            await _burp_client().get_scope()

    async def test_set_scope_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        new_scope = {"target": {"include": [{"host": "corp.example"}]}}
        seen = _patch_burp_http(monkeypatch, lambda req: httpx.Response(200, json={}))
        assert await _burp_client().set_scope(new_scope) is True
        assert str(seen[0].url) == "http://127.0.0.1:9999/v0.1/target/scope"
        assert seen[0].method == "PUT"
        assert seen[0].read() == b'{"target":{"include":[{"host":"corp.example"}]}}'

    async def test_set_scope_false_on_4xx(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_burp_http(monkeypatch, lambda req: httpx.Response(403, json={}))
        assert await _burp_client().set_scope({}) is False


# ---------------------------------------------------------------------------
# mcp/client.py - sse + http transport branches
# ---------------------------------------------------------------------------


class TestMCPClientSSETransport:
    async def test_sse_session_initialize_and_headers(self, monkeypatch) -> None:
        captured: dict = {}

        @asynccontextmanager
        async def fake_sse_client(url, headers=None):
            captured["url"] = url
            captured["headers"] = headers
            yield "fake-read", "fake-write"

        class FakeSession:
            def __init__(self, read, write):
                captured["read"] = read
                captured["write"] = write
                self.initialized = False

            async def initialize(self):
                self.initialized = True

        monkeypatch.setattr("agentx.mcp.client.sse_client", fake_sse_client)
        monkeypatch.setattr("agentx.mcp.client.ClientSession", FakeSession)

        cfg = MCPConfig(
            name="burp-mcp",
            transport="sse",
            url="http://127.0.0.1:1337/sse",
            headers={"X-Api-Key": "k"},
        )
        async with session_scope(cfg) as session:
            assert isinstance(session, FakeSession)
            assert session.initialized is True
        assert captured["url"] == "http://127.0.0.1:1337/sse"
        assert captured["headers"] == {"X-Api-Key": "k"}
        assert captured["read"] == "fake-read"
        assert captured["write"] == "fake-write"

    async def test_sse_headers_default_to_none(self, monkeypatch) -> None:
        captured: dict = {}

        @asynccontextmanager
        async def fake_sse_client(url, headers=None):
            captured["headers"] = headers
            yield "r", "w"

        class FakeSession:
            def __init__(self, read, write):
                pass

            async def initialize(self):
                pass

        monkeypatch.setattr("agentx.mcp.client.sse_client", fake_sse_client)
        monkeypatch.setattr("agentx.mcp.client.ClientSession", FakeSession)
        cfg = MCPConfig(name="s", transport="sse", url="http://x/sse")
        async with session_scope(cfg):
            pass
        assert captured["headers"] is None


class TestMCPClientHTTPTransport:
    async def test_http_transport_yields_client_for_url(self, monkeypatch) -> None:
        captured: dict = {}

        class FakeClient:
            def __init__(self, url):
                captured["url"] = url

            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

        monkeypatch.setattr("agentx.mcp.client.Client", FakeClient)
        cfg = MCPConfig(name="web", transport="http", url="https://mcp.example.com/mcp")
        async with session_scope(cfg) as impl:
            assert isinstance(impl, FakeClient)
        assert captured["url"] == "https://mcp.example.com/mcp"


# ---------------------------------------------------------------------------
# mcp/manager.py - _render_result branches
# ---------------------------------------------------------------------------


class TestRenderResult:
    def test_text_binary_and_str_fallback(self) -> None:
        res = SimpleNamespace(
            content=[
                SimpleNamespace(text="hello world"),
                SimpleNamespace(text="", mime_type="image/png", data=b"12345"),
                SimpleNamespace(text=None, mimeType="image/gif", data=[0, 1, 2]),
                SimpleNamespace(mime_type="application/pdf", data=42),
                SimpleNamespace(nothing=1),
            ],
            structured_content=None,
        )
        out = _render_result(res)
        assert "hello world" in out
        assert "[binary image/png 5 bytes]" in out
        assert "[binary image/gif 3 bytes]" in out
        assert "[binary application/pdf ? bytes]" in out
        assert "nothing=1" in out

    def test_structured_content_json(self) -> None:
        res = SimpleNamespace(content=[], structured_content={"k": [1, 2]})
        assert _render_result(res) == '{"k": [1, 2]}'

    def test_structured_content_unserializable_falls_back(self) -> None:
        circ: dict = {}
        circ["self"] = circ
        res = SimpleNamespace(content=None, structured_content=circ)
        out = _render_result(res)
        assert "self" in out

    def test_no_content_at_all(self) -> None:
        assert _render_result(SimpleNamespace(content=None)) == "<no content>"


# ---------------------------------------------------------------------------
# mcp/manager.py - connection lifecycle + call() error branches
# ---------------------------------------------------------------------------


def _tools_map(name: str = "echo") -> dict:
    return {name: {"description": "desc", "input_schema": {"type": "object"}}}


class TestManagedConnectionLifecycle:
    async def test_stop_without_task_returns(self) -> None:
        conn = _ManagedConnection(MCPConfig(name="idle", transport="stdio", command="x"))
        assert conn._task is None
        await conn.stop()  # must not raise
        assert conn._task is None

    async def test_stop_cancels_hung_task(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("agentx.mcp.manager.STOP_TIMEOUT", 0.05)
        conn = _ManagedConnection(MCPConfig(name="hung", transport="stdio", command="x"))

        async def hang_forever() -> None:
            await asyncio.Event().wait()

        conn._task = asyncio.create_task(hang_forever())
        await conn.stop()
        assert conn._task is None

    async def test_start_timeout_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("agentx.mcp.manager.CONNECT_TIMEOUT", 0.05)
        monkeypatch.setattr("agentx.mcp.manager.STOP_TIMEOUT", 0.05)

        @asynccontextmanager
        async def hanging_scope(cfg):
            await asyncio.sleep(3600)
            yield None

        monkeypatch.setattr("agentx.mcp.manager.session_scope", hanging_scope)
        conn = _ManagedConnection(MCPConfig(name="slow", transport="stdio", command="x"))
        with pytest.raises(TimeoutError, match="slow: connection timed out"):
            await conn.start()


class TestManagerCallErrorBranches:
    async def test_initialize_returns_early_when_already_connected(self) -> None:
        mgr = MCPManager()
        mgr._servers["x"] = SimpleNamespace(cfg=None, impl=None, tools={})
        assert await mgr.initialize() == 1

    def test_register_tool_name_collision_guard(self) -> None:
        mgr = MCPManager()
        mgr._register(
            MCPConfig(name="a", transport="stdio", command="x"),
            object(),
            _tools_map("b_c"),
        )
        mgr._register(
            MCPConfig(name="a_b", transport="stdio", command="x"),
            object(),
            _tools_map("c"),
        )
        assert mgr._by_full_name["mcp_a_b_c"] == ("a", "b_c")
        assert mgr._by_full_name["mcp_a_b_c_"] == ("a_b", "c")

    async def test_call_unknown_server_not_connected(self) -> None:
        mgr = MCPManager()
        mgr._by_full_name["mcp_ghost_tool"] = ("ghost", "tool")
        ok, text = await mgr.call("mcp_ghost_tool")
        assert ok is False
        assert "MCP server 'ghost' is not connected" in text

    async def test_call_impl_is_none_reports_not_connected(self) -> None:
        mgr = MCPManager()
        cfg = MCPConfig(name="dead", transport="stdio", command="x")
        mgr._register(cfg, object(), _tools_map())
        mgr._servers["dead"].impl = None
        ok, text = await mgr.call("mcp_dead_echo")
        assert ok is False
        assert "not connected" in text

    async def test_call_tool_exception_returns_error(self) -> None:
        class BoomImpl:
            async def call_tool(self, *args, **kwargs):
                raise RuntimeError("boom")

        mgr = MCPManager()
        cfg = MCPConfig(name="srv", transport="stdio", command="x")
        mgr._register(cfg, BoomImpl(), _tools_map())
        ok, text = await mgr.call("mcp_srv_echo", {"a": 1})
        assert ok is False
        assert "MCP tool mcp_srv_echo failed: boom" in text

    async def test_call_tool_result_truncated(self) -> None:
        big_text = "x" * (MAX_TOOL_RESULT_CHARS + 10)

        class BigImpl:
            async def call_tool(self, *args, **kwargs):
                return SimpleNamespace(content=[SimpleNamespace(text=big_text)], is_error=False)

        mgr = MCPManager()
        cfg = MCPConfig(name="big", transport="stdio", command="x")
        mgr._register(cfg, BigImpl(), _tools_map())
        ok, text = await mgr.call("mcp_big_echo")
        assert ok is True
        assert text.endswith("...[truncated]")
        assert len(text) == MAX_TOOL_RESULT_CHARS + len("\n...[truncated]")


# ---------------------------------------------------------------------------
# recon/pipeline.py - success paths + stage exception handling
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_installer():
    with patch("agentx.recon.pipeline.get_installer") as m:
        yield m


@pytest.fixture
def mock_tool_wrapper():
    with patch("agentx.recon.pipeline.tool_wrapper") as m:
        m.run = AsyncMock()
        yield m


def _pipeline(installer, wrapper) -> ReconPipeline:
    with (
        patch("agentx.recon.pipeline.get_installer", return_value=installer),
        patch("agentx.recon.pipeline.tool_wrapper", wrapper),
    ):
        return ReconPipeline()


class TestPipelineSubdomains:
    async def test_success(self, mock_installer, mock_tool_wrapper) -> None:
        mock_installer.is_installed.return_value = True
        mock_tool_wrapper.run.return_value = ToolResult(
            tool="subfinder",
            success=True,
            parsed_output=["a.example.com", "b.example.com"],
        )
        pipeline = _pipeline(mock_installer, mock_tool_wrapper)
        result = await pipeline._stage_subdomains("https://example.com/path")
        assert result.success is True
        assert result.data == ["a.example.com", "b.example.com"]
        assert result.count == 2
        assert result.error == ""
        mock_tool_wrapper.run.assert_awaited_once_with(
            "subfinder", ["-d", "example.com", "-silent"], parse=True
        )

    async def test_tool_failure_captures_stderr(self, mock_installer, mock_tool_wrapper) -> None:
        mock_installer.is_installed.return_value = True
        mock_tool_wrapper.run.return_value = ToolResult(
            tool="subfinder", success=False, stderr="rate limited"
        )
        pipeline = _pipeline(mock_installer, mock_tool_wrapper)
        result = await pipeline._stage_subdomains("example.com")
        assert result.success is False
        assert result.error == "rate limited"


class TestPipelineHttpProbe:
    async def test_success(self, mock_installer, mock_tool_wrapper) -> None:
        mock_installer.is_installed.return_value = True
        row = {"url": "https://example.com", "status-code": 200}
        mock_tool_wrapper.run.return_value = ToolResult(
            tool="httpx", success=True, parsed_output=[row]
        )
        pipeline = _pipeline(mock_installer, mock_tool_wrapper)
        result = await pipeline._stage_http_probe("example.com:8443")
        assert result.success is True
        assert result.data == [row]
        assert result.count == 1
        mock_tool_wrapper.run.assert_awaited_once_with(
            "httpx",
            ["-u", "example.com", "-silent", "-json", "-title", "-tech-detect", "-status-code"],
            parse=True,
        )


class TestPipelineUrls:
    async def test_prefers_gau(self, mock_installer, mock_tool_wrapper) -> None:
        def is_installed(tool: str) -> bool:
            return tool == "gau"

        mock_installer.is_installed.side_effect = is_installed
        mock_tool_wrapper.run.return_value = ToolResult(
            tool="gau", success=True, parsed_output=["https://example.com/1"]
        )
        pipeline = _pipeline(mock_installer, mock_tool_wrapper)
        result = await pipeline._stage_urls("example.com")
        assert result.success is True
        assert result.data == ["https://example.com/1"]
        mock_tool_wrapper.run.assert_awaited_once_with("gau", ["example.com"], parse=True)

    async def test_falls_back_to_waybackurls(self, mock_installer, mock_tool_wrapper) -> None:
        def is_installed(tool: str) -> bool:
            return tool == "waybackurls"

        mock_installer.is_installed.side_effect = is_installed
        mock_tool_wrapper.run.return_value = ToolResult(
            tool="waybackurls", success=True, parsed_output=["https://example.com/wb"]
        )
        pipeline = _pipeline(mock_installer, mock_tool_wrapper)
        result = await pipeline._stage_urls("example.com")
        assert result.success is True
        mock_tool_wrapper.run.assert_awaited_once_with("waybackurls", ["example.com"], parse=True)


class TestPipelineFingerprint:
    async def test_success_adds_https_scheme(self, mock_installer, mock_tool_wrapper) -> None:
        mock_installer.is_installed.return_value = True
        mock_tool_wrapper.run.return_value = ToolResult(
            tool="httpx", success=True, parsed_output=[{"tech": ["nginx"]}]
        )
        pipeline = _pipeline(mock_installer, mock_tool_wrapper)
        result = await pipeline._stage_fingerprint("example.com")
        assert result.success is True
        assert result.count == 1
        mock_tool_wrapper.run.assert_awaited_once_with(
            "httpx",
            [
                "-u",
                "https://example.com",
                "-silent",
                "-json",
                "-tech-detect",
                "-web-server",
                "-title",
            ],
            parse=True,
        )


class TestPipelineRunExceptionHandling:
    async def test_stage_exception_is_captured(self, mock_installer, mock_tool_wrapper) -> None:
        mock_installer.is_installed.return_value = True
        mock_tool_wrapper.run.side_effect = RuntimeError("kaboom")
        pipeline = _pipeline(mock_installer, mock_tool_wrapper)
        results = await pipeline.run("example.com", stages=["subdomains"])
        assert len(results) == 1
        assert results[0].success is False
        assert results[0].error == "kaboom"
        assert results[0].stage == "subdomains"
