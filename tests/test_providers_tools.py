"""Tool-calling support in AI providers (OpenAI/Ollama/Anthropic) and router."""

from __future__ import annotations

import json

import httpx

from agentx.ai.providers import (
    AnthropicProvider,
    CompletionResponse,
    Message,
    OllamaProvider,
    OpenAIProvider,
)
from agentx.ai.router import router
from agentx.config import AIProviderConfig

TOOL = {
    "type": "function",
    "function": {
        "name": "mcp_burp_send_http_request",
        "description": "send request",
        "parameters": {"type": "object", "properties": {"url": {"type": "string"}}},
    },
}


def _cfg(type_: str) -> AIProviderConfig:
    return AIProviderConfig(name=type_, type=type_, base_url="https://api.test", model="m")  # type: ignore[call-overload]


async def test_openai_complete_parses_tool_calls() -> None:
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "model": "m",
                "choices": [
                    {
                        "message": {
                            "content": "",
                            "tool_calls": [
                                {
                                    "id": "c1",
                                    "type": "function",
                                    "function": {
                                        "name": "mcp_burp_send_http_request",
                                        "arguments": '{"url": "http://x"}',
                                    },
                                }
                            ],
                        },
                        "finish_reason": "tool_calls",
                    }
                ],
                "usage": None,
            },
        )

    provider = OpenAIProvider(_cfg("openai"))
    provider.client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="https://api.test"
    )
    resp = await provider.complete([Message(role="user", content="hi")], tools=[TOOL])
    assert resp.tool_calls is not None
    assert resp.tool_calls[0]["function"]["name"] == "mcp_burp_send_http_request"
    assert captured["body"]["tools"] == [TOOL]
    assert captured["body"]["messages"][0]["role"] == "user"
    await provider.client.aclose()


async def test_ollama_roundtrips_tool_call_arguments() -> None:
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "model": "m",
                "message": {
                    "content": "",
                    "tool_calls": [{"function": {"name": "echo", "arguments": {"msg": "hi"}}}],
                },
                "done_reason": "stop",
            },
        )

    provider = OllamaProvider(_cfg("ollama"))
    provider.client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="https://api.test"
    )
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
    resp = await provider.complete(history, tools=[TOOL])
    # Incoming: Ollama wants arguments as an object.
    args = captured["body"]["messages"][0]["tool_calls"][0]["function"]["arguments"]
    assert args == {"msg": "hi"}
    # Outgoing: keep the OpenAI-style JSON string for our own loop.
    assert resp.tool_calls is not None
    assert resp.tool_calls[0]["function"]["arguments"] == '{"msg": "hi"}'
    await provider.client.aclose()


async def test_anthropic_converts_tool_use_and_tool_result() -> None:
    provider = AnthropicProvider(_cfg("anthropic"))
    messages = [
        Message(role="system", content="sys"),
        Message(role="user", content="go"),
        Message(
            role="assistant",
            content="",
            tool_calls=[
                {
                    "id": "c1",
                    "type": "function",
                    "function": {"name": "mcp_echo", "arguments": json.dumps({"msg": "x"})},
                }
            ],
        ),
        Message(role="tool", content="echo:x", tool_call_id="c1"),
    ]
    system, converted = provider._convert_messages(messages)
    assert system == "sys"
    assert converted[0]["role"] == "user"
    tool_use = converted[1]["content"][0]
    assert tool_use["type"] == "tool_use"
    assert tool_use["input"] == {"msg": "x"}
    tool_result = converted[2]["content"][0]
    assert tool_result["type"] == "tool_result"
    assert tool_result["tool_use_id"] == "c1"
    assert tool_result["content"] == "echo:x"


async def test_anthropic_complete_parses_tool_use_blocks() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "model": "m",
                "content": [
                    {"type": "text", "text": "thinking"},
                    {
                        "type": "tool_use",
                        "id": "c1",
                        "name": "mcp_echo",
                        "input": {"msg": "x"},
                    },
                ],
                "usage": {"input_tokens": 5, "output_tokens": 5},
                "stop_reason": "tool_use",
            },
        )

    provider = AnthropicProvider(_cfg("anthropic"))
    provider.client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="https://api.test"
    )
    resp = await provider.complete([Message(role="user", content="go")], tools=[TOOL])
    assert resp.content == "thinking"
    assert resp.tool_calls is not None
    assert resp.tool_calls[0]["function"]["name"] == "mcp_echo"
    assert json.loads(resp.tool_calls[0]["function"]["arguments"]) == {"msg": "x"}
    await provider.client.aclose()


class _FakeProvider:
    async def complete(self, messages, tools=None, tool_choice=None, **kwargs):
        return CompletionResponse(
            content="",
            model="fake",
            tool_calls=[
                {
                    "id": "c1",
                    "type": "function",
                    "function": {"name": "mcp_echo", "arguments": "{}"},
                }
            ],
        )


async def test_router_complete_response_returns_tool_calls(monkeypatch) -> None:
    monkeypatch.setattr(router, "_providers", {"fake": _FakeProvider()})
    monkeypatch.setattr(router, "_provider_configs", {})
    resp = await router.complete_response(
        [{"role": "user", "content": "hi"}], tools=[TOOL], tool_choice="auto"
    )
    assert resp.tool_calls is not None
    assert resp.tool_calls[0]["function"]["name"] == "mcp_echo"

    text = await router.complete([{"role": "user", "content": "hi"}])
    assert text == ""
