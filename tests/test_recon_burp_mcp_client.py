"""Unit tests for recon pipeline, burp integration, and mcp client."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from agentx.integrations.burp import BurpClient
from agentx.mcp.client import MCPServerError, session_scope
from agentx.recon.pipeline import ReconPipeline, ReconResult, recon_pipeline


@pytest.fixture
def mock_installer():
    with patch("agentx.recon.pipeline.get_installer") as m:
        installer = MagicMock()
        m.return_value = installer
        yield installer


@pytest.fixture
def mock_tool_wrapper():
    with patch("agentx.recon.pipeline.tool_wrapper") as m:
        yield m


@pytest.fixture
def mock_settings_burp():
    with patch("agentx.integrations.burp.settings") as m:
        m.burp.host = "127.0.0.1"
        m.burp.port = 8080
        m.burp.api_key = "test-key"
        m.burp.use_https = False
        m.burp.enabled = True
        yield m


class TestReconPipelineInitAndStages:
    def test_available_stages(self, mock_installer):
        pipeline = ReconPipeline()
        assert pipeline.available_stages() == ["subdomains", "http_probe", "urls", "fingerprint"]

    def test_global_pipeline_exists(self):
        assert recon_pipeline is not None


class TestReconResult:
    def test_recon_result_defaults(self):
        r = ReconResult(stage="test", success=True)
        assert r.stage == "test"
        assert r.success is True
        assert r.data is None
        assert r.error == ""
        assert r.count == 0


class TestExtractDomain:
    def test_extract_domain_plain(self, mock_installer):
        pipeline = ReconPipeline()
        assert pipeline._extract_domain("example.com") == "example.com"

    def test_extract_domain_with_scheme(self, mock_installer):
        pipeline = ReconPipeline()
        assert pipeline._extract_domain("https://example.com") == "example.com"

    def test_extract_domain_with_path(self, mock_installer):
        pipeline = ReconPipeline()
        assert pipeline._extract_domain("https://example.com/path") == "example.com"

    def test_extract_domain_with_port(self, mock_installer):
        pipeline = ReconPipeline()
        assert pipeline._extract_domain("example.com:8080") == "example.com"


class TestReconPipelineMissingTools:
    async def test_stage_subdomains_missing(self, mock_installer):
        pipeline = ReconPipeline()
        mock_installer.is_installed.return_value = False
        result = await pipeline._stage_subdomains("example.com")
        assert result.success is False
        assert result.error == "subfinder not installed"

    async def test_stage_http_probe_missing(self, mock_installer):
        pipeline = ReconPipeline()
        mock_installer.is_installed.return_value = False
        result = await pipeline._stage_http_probe("example.com")
        assert result.success is False

    async def test_stage_urls_missing(self, mock_installer):
        pipeline = ReconPipeline()
        mock_installer.is_installed.return_value = False
        result = await pipeline._stage_urls("example.com")
        assert result.success is False

    async def test_stage_fingerprint_missing(self, mock_installer):
        pipeline = ReconPipeline()
        mock_installer.is_installed.return_value = False
        result = await pipeline._stage_fingerprint("example.com")
        assert result.success is False


class TestReconPipelineRunBasic:
    async def test_run_unknown_stage(self, mock_installer):
        pipeline = ReconPipeline()
        results = await pipeline.run("example.com", stages=["unknown"])
        assert len(results) == 1
        assert results[0].success is False
        assert results[0].error == "unknown stage"

    async def test_run_default_stages_structure(self, mock_installer):
        pipeline = ReconPipeline()
        mock_installer.is_installed.return_value = False
        results = await pipeline.run("example.com")
        assert len(results) == 4


class TestBurpClient:
    def test_init_uses_defaults(self, mock_settings_burp):
        client = BurpClient()
        assert client.host == "127.0.0.1"
        assert client.port == 8080
        assert client.api_key == "test-key"
        assert client.scheme == "http"
        assert client.enabled is True

    def test_headers_with_key(self, mock_settings_burp):
        client = BurpClient()
        headers = client._headers()
        assert headers["Authorization"] == "Bearer test-key"

    def test_headers_without_key(self, mock_settings_burp):
        from unittest.mock import patch

        with patch("agentx.integrations.burp.settings") as m:
            m.burp.host = "127.0.0.1"
            m.burp.port = 8080
            m.burp.api_key = None
            m.burp.use_https = False
            m.burp.enabled = True
            client = BurpClient()
            headers = client._headers()
            assert "Authorization" not in headers


class TestMCPClientBasics:
    @pytest.mark.asyncio
    async def test_session_scope_stdio_requires_command(self):
        cfg = MagicMock()
        cfg.transport = "stdio"
        cfg.command = None
        cfg.name = "t"
        with pytest.raises(MCPServerError):
            async with session_scope(cfg):
                pass

    @pytest.mark.asyncio
    async def test_session_scope_sse_requires_url(self):
        cfg = MagicMock()
        cfg.transport = "sse"
        cfg.url = None
        cfg.name = "t"
        with pytest.raises(MCPServerError):
            async with session_scope(cfg):
                pass

    @pytest.mark.asyncio
    async def test_session_scope_http_requires_url(self):
        cfg = MagicMock()
        cfg.transport = "http"
        cfg.url = None
        cfg.name = "t"
        with pytest.raises(MCPServerError):
            async with session_scope(cfg):
                pass


class TestMCPClientWithFakeServer:
    @pytest.mark.asyncio
    async def test_fake_server_basic(self):
        import sys
        from pathlib import Path

        from mcp import Client, StdioServerParameters

        fake_server = Path(__file__).parent / "fake_mcp_server.py"
        params = StdioServerParameters(command=sys.executable, args=["-u", str(fake_server)])
        async with Client(params) as client:
            tools = await client.list_tools()
            names = [t.name for t in tools.tools]
            assert "echo" in names
            assert "add" in names
            res = await client.call_tool("echo", {"msg": "hi"})
            text = getattr(res.content[0], "text", str(res.content[0]))
            assert text == "echo:hi"
