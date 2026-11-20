"""Comprehensive tests for AI providers and router."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from agentx.ai.providers import (
    AnthropicProvider,
    BaseProvider,
    CompletionResponse,
    CustomProvider,
    LMStudioProvider,
    Message,
    OllamaProvider,
    OpenAIProvider,
    create_provider,
    get_best_provider,
)
from agentx.ai.router import ModelRouter, close_ai, init_ai, router
from agentx.config import AIProviderConfig


def _cfg(type_: str, **kwargs: Any) -> AIProviderConfig:
    defaults = {
        "name": f"{type_}_test",
        "type": type_,
        "base_url": "https://api.test",
        "model": "test-model",
    }
    defaults.update(kwargs)
    return AIProviderConfig(**defaults)


async def test_base_provider_context_manager() -> None:
    cfg = _cfg("openai")
    p = OpenAIProvider(cfg)
    async with p:
        assert p.client is not None
    # client lifecycle varies


async def test_create_provider_variants() -> None:
    assert isinstance(create_provider(_cfg("openai")), OpenAIProvider)
    assert isinstance(create_provider(_cfg("anthropic")), AnthropicProvider)
    assert isinstance(create_provider(_cfg("ollama")), OllamaProvider)
    assert isinstance(create_provider(_cfg("lmstudio")), LMStudioProvider)
    assert isinstance(create_provider(_cfg("custom")), CustomProvider)
    with pytest.raises(ValueError):
        create_provider(_cfg("unknown"))


async def test_get_best_provider() -> None:
    from agentx.ai import providers as providers_mod
    from agentx.config import AgentXSettings

    settings = AgentXSettings()
    settings.ai_providers = [
        _cfg("openai", name="p1", model="m1", enabled=True),
        _cfg("ollama", name="p2", model="m2", enabled=True),
    ]
    settings.orchestrator_model = "m1"
    settings.skill_model = "m2"
    settings.local_model = "m3"
    original = providers_mod.settings
    try:
        providers_mod.settings = settings
        p = await get_best_provider(task_type="orchestrator")
        assert p.config.model == "m1"
        settings.orchestrator_model = "missing"
        p2 = await get_best_provider(task_type="skill")
        assert p2.config.model == "m2"
        p3 = await get_best_provider(task_type="local")
        # fallback to first enabled provider
        assert p3.config.model == "m1" or p3.config.model == "m2"
    finally:
        providers_mod.settings = original


async def test_get_best_provider_no_providers() -> None:
    from agentx.ai import providers as providers_mod
    from agentx.config import AgentXSettings

    settings = AgentXSettings()
    settings.ai_providers = []
    original = providers_mod.settings
    try:
        providers_mod.settings = settings
        with pytest.raises(RuntimeError):
            await get_best_provider()
    finally:
        providers_mod.settings = original


async def test_openai_complete_offline() -> None:
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "model": "test-model",
                "choices": [
                    {
                        "message": {
                            "content": "hello",
                            "tool_calls": [
                                {
                                    "id": "c1",
                                    "type": "function",
                                    "function": {
                                        "name": "tool_a",
                                        "arguments": '{"x":1}',
                                    },
                                }
                            ],
                        },
                        "finish_reason": "tool_calls",
                    }
                ],
                "usage": {"prompt_tokens": 1, "completion_tokens": 2},
            },
        )

    provider = OpenAIProvider(_cfg("openai"))
    provider.client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="https://api.test"
    )
    resp = await provider.complete(
        [Message(role="user", content="hi")],
        tools=[{"type": "function", "function": {"name": "tool_a", "parameters": {}}}],
    )
    assert resp.content == "hello"
    assert resp.tool_calls is not None
    assert resp.tool_calls[0]["function"]["name"] == "tool_a"
    assert captured["body"]["model"] == "test-model"
    await provider.client.aclose()


async def test_openai_stream_offline() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=(b'data: {"choices":[{"delta":{"content":"hi"}}]}\ndata: [DONE]\n'),
        )

    provider = OpenAIProvider(_cfg("openai"))
    provider.client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="https://api.test"
    )
    chunks = []
    async for c in provider.stream_complete(
        [Message(role="user", content="hi")],
        tools=[{"type": "function", "function": {"name": "t", "parameters": {}}}],
    ):
        chunks.append(c)
    assert "".join(chunks) == "hi"
    await provider.client.aclose()


async def test_openai_stream_invalid_json() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=(
                b"data: {invalid json}\n"
                b'data: {"choices":[{"delta":{"content":"ok"}}]}\n'
                b"data: [DONE]\n"
            ),
        )

    provider = OpenAIProvider(_cfg("openai"))
    provider.client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="https://api.test"
    )
    chunks = []
    async for c in provider.stream_complete([Message(role="user", content="hi")]):
        chunks.append(c)
    assert "".join(chunks) == "ok"
    await provider.client.aclose()


async def test_anthropic_complete_parses_and_converts() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "model": "claude",
                "content": [
                    {"type": "text", "text": "thought"},
                    {
                        "type": "tool_use",
                        "id": "c1",
                        "name": "tool_a",
                        "input": {"msg": "hi"},
                    },
                ],
                "usage": {"input_tokens": 1, "output_tokens": 1},
                "stop_reason": "tool_use",
            },
        )

    provider = AnthropicProvider(_cfg("anthropic"))
    provider.client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="https://api.test"
    )
    resp = await provider.complete(
        [Message(role="user", content="go")],
        tools=[{"type": "function", "function": {"name": "tool_a", "parameters": {}}}],
        tool_choice="auto",
    )
    assert resp.content == "thought"
    assert resp.tool_calls is not None
    assert resp.tool_calls[0]["function"]["arguments"] == '{"msg": "hi"}'
    assert resp.finish_reason == "tool_use"
    await provider.client.aclose()


async def test_anthropic_complete_no_tools() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "model": "claude",
                "content": [{"type": "text", "text": "done"}],
                "usage": {"input_tokens": 1, "output_tokens": 1},
                "stop_reason": "end_turn",
            },
        )

    provider = AnthropicProvider(_cfg("anthropic"))
    provider.client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="https://api.test"
    )
    resp = await provider.complete([Message(role="user", content="go")])
    assert resp.content == "done"
    assert resp.tool_calls is None
    await provider.client.aclose()


async def test_anthropic_convert_messages_variants() -> None:
    provider = AnthropicProvider(_cfg("anthropic"))
    messages = [
        Message(role="system", content="sys"),
        Message(role="assistant", content=""),
        Message(
            role="assistant",
            content="",
            tool_calls=[
                {"id": "c1", "type": "function", "function": {"name": "f", "arguments": "{bad}"}}
            ],
        ),
    ]
    system, converted = provider._convert_messages(messages)
    assert system == "sys"
    # bad json -> empty args
    assert converted[1]["content"][0]["input"] == {}


async def test_anthropic_convert_tool_choice() -> None:
    provider = AnthropicProvider(_cfg("anthropic"))
    assert provider._convert_tool_choice("auto") == "auto"
    assert provider._convert_tool_choice({"type": "function", "function": {"name": "f"}}) == {
        "type": "tool",
        "name": "f",
    }
    assert provider._convert_tool_choice({"type": "other"}) == "auto"


async def test_anthropic_stream_offline() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=(
                b'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"hi"}}\n'
                b'data: {"type":"other"}\n'
            ),
        )

    provider = AnthropicProvider(_cfg("anthropic"))
    provider.client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="https://api.test"
    )
    chunks = []
    async for c in provider.stream_complete(
        [Message(role="user", content="go")],
        tools=[{"type": "function", "function": {"name": "t", "parameters": {}}}],
    ):
        chunks.append(c)
    assert "".join(chunks) == "hi"
    await provider.client.aclose()


async def test_anthropic_stream_bad_json() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=(
                b"data: {bad}\n"
                b'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"ok"}}\n'
            ),
        )

    provider = AnthropicProvider(_cfg("anthropic"))
    provider.client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="https://api.test"
    )
    chunks = []
    async for c in provider.stream_complete([Message(role="user", content="go")]):
        chunks.append(c)
    assert "".join(chunks) == "ok"
    await provider.client.aclose()


async def test_ollama_complete_offline() -> None:
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "model": "m",
                "message": {
                    "content": "resp",
                    "tool_calls": [{"function": {"name": "echo", "arguments": {"msg": "hi"}}}],
                },
                "done_reason": "stop",
            },
        )

    provider = OllamaProvider(_cfg("ollama"))
    provider.client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="https://api.test"
    )
    # history with string args
    history = [
        Message(
            role="assistant",
            content="",
            tool_calls=[
                {
                    "id": "c1",
                    "type": "function",
                    "function": {"name": "echo", "arguments": json.dumps({"msg": "hi"})},
                }
            ],
        )
    ]
    resp = await provider.complete(
        history, tools=[{"type": "function", "function": {"name": "echo", "parameters": {}}}]
    )
    assert resp.content == "resp"
    assert resp.tool_calls is not None
    assert resp.tool_calls[0]["function"]["arguments"] == '{"msg": "hi"}'
    assert resp.finish_reason == "stop"
    await provider.client.aclose()


async def test_ollama_payload_bad_json() -> None:
    provider = OllamaProvider(_cfg("ollama"))
    msgs = [
        Message(
            role="assistant",
            content="",
            tool_calls=[
                {"id": "1", "type": "function", "function": {"name": "f", "arguments": "{bad}"}}
            ],
        )
    ]
    payload = provider._payload_messages(msgs)
    args = payload[0]["tool_calls"][0]["function"]["arguments"]
    assert args == {}


async def test_ollama_normalize() -> None:
    provider = OllamaProvider(_cfg("ollama"))
    norm = provider._normalize_tool_calls([{"function": {"name": "f", "arguments": "{}"}}])
    assert norm[0]["function"]["name"] == "f"
    # no tool calls
    assert provider._normalize_tool_calls(None) == []


async def test_ollama_stream_offline() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=b'{"message":{"content":"chunk"}}\n{bad}\n',
        )

    provider = OllamaProvider(_cfg("ollama"))
    provider.client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="https://api.test"
    )
    chunks = []
    async for c in provider.stream_complete(
        [Message(role="user", content="hi")],
        tools=[{"type": "function", "function": {"name": "t", "parameters": {}}}],
    ):
        chunks.append(c)
    assert "".join(chunks) == "chunk"
    await provider.client.aclose()


async def test_lmstudio_custom_inherit() -> None:
    p = LMStudioProvider(_cfg("lmstudio"))
    c = CustomProvider(_cfg("custom"))
    assert isinstance(p, OpenAIProvider)
    assert isinstance(c, OpenAIProvider)
    assert p._get_headers()["Content-Type"] == "application/json"
    assert "Authorization" not in p._get_headers()


async def test_openai_headers_with_key() -> None:
    p = OpenAIProvider(_cfg("openai", api_key="sk-test"))
    h = p._get_headers()
    assert h["Authorization"] == "Bearer sk-test"


async def test_anthropic_headers_key() -> None:
    p = AnthropicProvider(_cfg("anthropic", api_key="sk-a"))
    h = p._get_headers()
    assert h["x-api-key"] == "sk-a"
    assert h["anthropic-version"] == "2023-06-01"


async def test_openai_error_http_401() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "unauthorized"})

    p = OpenAIProvider(_cfg("openai"))
    p.client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="https://api.test"
    )
    with pytest.raises(httpx.HTTPStatusError):
        await p.complete([Message(role="user", content="hi")])
    await p.client.aclose()


async def test_openai_error_timeout() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("timeout")

    p = OpenAIProvider(_cfg("openai"))
    p.client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="https://api.test"
    )
    with pytest.raises(httpx.ConnectTimeout):
        await p.complete([Message(role="user", content="hi")])
    await p.client.aclose()


async def test_anthropic_error_429() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, json={})

    p = AnthropicProvider(_cfg("anthropic"))
    p.client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="https://api.test"
    )
    with pytest.raises(httpx.HTTPStatusError):
        await p.complete([Message(role="user", content="hi")])
    await p.client.aclose()


async def test_ollama_error_404() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={})

    p = OllamaProvider(_cfg("ollama"))
    p.client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="https://api.test"
    )
    with pytest.raises(httpx.HTTPStatusError):
        await p.complete([Message(role="user", content="hi")])
    await p.client.aclose()


async def test_router_initialize_and_close(monkeypatch) -> None:
    import importlib

    from agentx.config import AIProviderConfig

    router_mod = importlib.import_module("agentx.ai.router")

    class DummyProvider(OpenAIProvider):
        async def __aenter__(self):
            self.client = httpx.AsyncClient(base_url="https://api.test")
            return self

        async def __aexit__(self, *a):
            await self.client.aclose()

    class _Stub:
        def __init__(self, cfgs):
            self._cfgs = cfgs
            self.orchestrator_model = "x"
            self.skill_model = "x"
            self.local_model = "x"

        def get_enabled_providers(self):
            return list(self._cfgs)

    cfg = AIProviderConfig(name="p1", type="openai", model="m1", base_url="https://api.test")
    monkeypatch.setattr(router_mod, "settings", _Stub([cfg]))
    monkeypatch.setattr(router_mod, "create_provider", lambda c: DummyProvider(c))
    r = ModelRouter()
    await r.initialize()
    assert "p1" in r._providers
    await r.close()
    assert r._providers == {}


def _make_stub(cfgs, orchestrator="om", skill="sm", local="lm"):
    class _Stub:
        def __init__(self):
            self._cfgs = cfgs
            self.orchestrator_model = orchestrator
            self.skill_model = skill
            self.local_model = local

        def get_enabled_providers(self):
            return list(self._cfgs)

        def get_provider(self, name):
            for c in self._cfgs:
                if c.name == name:
                    return c
            return None

    return _Stub()


class _RecordingProvider:
    def __init__(self, name="rec"):
        self.name = name
        self.calls = []

    async def complete(self, messages, tools=None, tool_choice=None, **kwargs):
        self.calls.append(("complete", messages, tools, tool_choice, kwargs))
        return CompletionResponse(content=f"{self.name}-out", model=self.name)

    async def stream_complete(self, messages, tools=None, **kwargs):
        self.calls.append(("stream", messages, tools, kwargs))
        yield "a"
        yield "b"

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return None


async def test_router_get_provider_preferred(monkeypatch) -> None:
    p1 = _RecordingProvider("p1")
    p2 = _RecordingProvider("p2")
    r = ModelRouter()
    r._providers = {"p1": p1, "p2": p2}
    r._provider_configs = {}
    async with r.get_provider("skill", preferred_provider="p2") as got:
        assert got is p2


async def test_router_get_provider_model_match(monkeypatch) -> None:
    cfg = _cfg("openai", name="p1", model="special")
    p1 = _RecordingProvider("p1")
    r = ModelRouter()
    r._providers = {"p1": p1}
    r._provider_configs = {"p1": cfg}
    import importlib

    router_mod = importlib.import_module("agentx.ai.router")
    monkeypatch.setattr(router_mod, "settings", _make_stub([cfg], skill="special"))
    async with r.get_provider("skill") as got:
        assert got is p1


async def test_router_get_provider_fallback_any(monkeypatch) -> None:
    p1 = _RecordingProvider("p1")
    cfg = _cfg("openai", name="p1", model="other")
    r = ModelRouter()
    r._providers = {"p1": p1}
    r._provider_configs = {"p1": cfg}
    import importlib

    router_mod = importlib.import_module("agentx.ai.router")
    monkeypatch.setattr(router_mod, "settings", _make_stub([cfg], skill="nomatch"))
    async with r.get_provider("skill") as got:
        assert got is p1


async def test_router_get_provider_last_resort(monkeypatch) -> None:
    p1 = _RecordingProvider("last")
    r = ModelRouter()
    r._providers = {}
    r._provider_configs = {}
    import importlib

    router_mod = importlib.import_module("agentx.ai.router")

    async def fake_best(task_type="skill"):
        return p1

    monkeypatch.setattr(router_mod, "get_best_provider", fake_best)
    async with r.get_provider("local") as got:
        assert got is p1


async def test_router_complete_response_success(monkeypatch) -> None:
    p1 = _RecordingProvider("p1")
    r = ModelRouter()
    r._providers = {"p1": p1}
    r._provider_configs = {}
    resp = await r.complete_response([{"role": "user", "content": "hi"}], preferred_provider="p1")
    assert resp.content == "p1-out"
    assert p1.calls[0][0] == "complete"


async def test_router_complete_returns_text(monkeypatch) -> None:
    p1 = _RecordingProvider("p1")
    r = ModelRouter()
    r._providers = {"p1": p1}
    r._provider_configs = {}
    text = await r.complete([{"role": "user", "content": "hi"}], preferred_provider="p1")
    assert text == "p1-out"


async def test_router_stream_complete(monkeypatch) -> None:
    p1 = _RecordingProvider("p1")
    r = ModelRouter()
    r._providers = {"p1": p1}
    r._provider_configs = {}
    chunks = []
    async for c in r.stream_complete([{"role": "user", "content": "hi"}], preferred_provider="p1"):
        chunks.append(c)
    assert "".join(chunks) == "ab"


async def test_router_complete_response_no_provider(monkeypatch) -> None:
    r = ModelRouter()
    r._providers = {}
    r._provider_configs = {}
    import importlib

    router_mod = importlib.import_module("agentx.ai.router")

    async def boom(task_type="skill"):
        raise RuntimeError("No AI providers configured. Add at least one in config.")

    monkeypatch.setattr(router_mod, "get_best_provider", boom)
    with pytest.raises(RuntimeError):
        await r.complete_response([{"role": "user", "content": "hi"}])


async def test_router_init_ai_and_close_ai(monkeypatch) -> None:
    async def fake_init():
        return None

    monkeypatch.setattr(router, "initialize", fake_init)
    await init_ai()

    async def fake_close():
        return None

    monkeypatch.setattr(router, "close", fake_close)
    await close_ai()


async def test_openai_complete_tool_choice_param() -> None:
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "model": "m",
                "choices": [{"message": {"content": "x"}, "finish_reason": "stop"}],
                "usage": None,
            },
        )

    p = OpenAIProvider(_cfg("openai"))
    p.client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="https://api.test"
    )
    await p.complete([Message(role="user", content="hi")], tool_choice="auto")
    assert captured["body"]["tool_choice"] == "auto"
    await p.client.aclose()


async def test_anthropic_complete_with_system_and_tool_message() -> None:
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "model": "claude",
                "content": [{"type": "text", "text": "ok"}],
                "usage": {"input_tokens": 1, "output_tokens": 1},
                "stop_reason": "end_turn",
            },
        )

    p = AnthropicProvider(_cfg("anthropic"))
    p.client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="https://api.test"
    )
    msgs = [
        Message(role="system", content="be nice"),
        Message(role="user", content="go"),
        Message(role="tool", content="result", tool_call_id="c1"),
    ]
    resp = await p.complete(msgs)
    assert resp.content == "ok"
    assert captured["body"]["system"] == "be nice"
    roles = [m["role"] for m in captured["body"]["messages"]]
    assert roles == ["user", "user"]
    await p.client.aclose()


async def test_anthropic_stream_with_system() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=b'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"z"}}\n',
        )

    p = AnthropicProvider(_cfg("anthropic"))
    p.client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="https://api.test"
    )
    chunks = []
    async for c in p.stream_complete(
        [Message(role="system", content="s"), Message(role="user", content="g")]
    ):
        chunks.append(c)
    assert "".join(chunks) == "z"
    await p.client.aclose()


async def test_ollama_headers() -> None:
    p = OllamaProvider(_cfg("ollama"))
    assert p._get_headers() == {"Content-Type": "application/json"}


async def test_create_provider_unknown_type() -> None:
    class _Bad:
        type = "does-not-exist"

    with pytest.raises(ValueError):
        create_provider(_Bad())  # type: ignore[arg-type]


async def test_abstract_base_methods_execute() -> None:
    # Abstract stubs on the base class are trivial `pass` bodies; exercise them.
    assert BaseProvider._get_headers(object()) is None  # type: ignore[arg-type]
    assert await BaseProvider.complete(object(), []) is None  # type: ignore[arg-type]
    # stream_complete is a plain coroutine on the base class (no yield); await it.
    assert await BaseProvider.stream_complete(object(), []) is None  # type: ignore[arg-type]
