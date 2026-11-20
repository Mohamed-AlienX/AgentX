"""AI Provider Abstraction Layer.

Supports OpenAI, Anthropic, Ollama, LM Studio, and custom OpenAI-compatible APIs.
"""

from __future__ import annotations

import abc
import json
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any, Literal

import httpx
from pydantic import BaseModel

from agentx.config import AIProviderConfig, settings


class Message(BaseModel):
    """Chat message."""

    role: Literal["system", "user", "assistant", "tool"]
    content: str | None = None
    tool_calls: list[dict[str, Any]] | None = None
    tool_call_id: str | None = None
    name: str | None = None


@dataclass
class CompletionResponse:
    """Completion response."""

    content: str
    model: str
    usage: dict[str, int] | None = None
    finish_reason: str | None = None
    tool_calls: list[dict[str, Any]] | None = None


class BaseProvider(abc.ABC):
    """Abstract base class for AI providers."""

    def __init__(self, config: AIProviderConfig):
        self.config = config
        self.client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> BaseProvider:
        self.client = httpx.AsyncClient(
            base_url=self.config.base_url,
            timeout=self.config.timeout,
            headers=self._get_headers(),
        )
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self.client:
            await self.client.aclose()

    @abc.abstractmethod
    def _get_headers(self) -> dict[str, str]:
        pass

    @abc.abstractmethod
    async def complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
        tool_choice: str | dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> CompletionResponse:
        pass

    @abc.abstractmethod
    async def stream_complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        pass


class OpenAIProvider(BaseProvider):
    """OpenAI and OpenAI-compatible API provider."""

    def _get_headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        return headers

    async def complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
        tool_choice: str | dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> CompletionResponse:
        payload = {
            "model": self.config.model,
            "messages": [m.model_dump(exclude_none=True) for m in messages],
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
            **kwargs,
        }
        if tools:
            payload["tools"] = tools
        if tool_choice:
            payload["tool_choice"] = tool_choice

        assert self.client is not None
        response = await self.client.post("/chat/completions", json=payload)
        response.raise_for_status()
        data = response.json()

        choice = data["choices"][0]
        return CompletionResponse(
            content=choice["message"].get("content", ""),
            model=data["model"],
            usage=data.get("usage"),
            finish_reason=choice.get("finish_reason"),
            tool_calls=choice["message"].get("tool_calls"),
        )

    async def stream_complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        payload = {
            "model": self.config.model,
            "messages": [m.model_dump(exclude_none=True) for m in messages],
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
            "stream": True,
            **kwargs,
        }
        if tools:
            payload["tools"] = tools

        assert self.client is not None
        async with self.client.stream("POST", "/chat/completions", json=payload) as response:
            response.raise_for_status()
            async for line in response.aiter_lines():
                if line.startswith("data: "):
                    data_str = line[6:]
                    if data_str.strip() == "[DONE]":
                        break
                    try:
                        data = json.loads(data_str)
                        delta = data["choices"][0]["delta"]
                        if content := delta.get("content"):
                            yield content
                    except json.JSONDecodeError:
                        continue


class AnthropicProvider(BaseProvider):
    """Anthropic Claude API provider."""

    def _get_headers(self) -> dict[str, str]:
        return {
            "Content-Type": "application/json",
            "x-api-key": self.config.api_key or "",
            "anthropic-version": "2023-06-01",
        }

    def _convert_messages(self, messages: list[Message]) -> tuple[str | None, list[dict[str, Any]]]:
        system = None
        converted = []
        for msg in messages:
            if msg.role == "system":
                system = msg.content
                continue
            if msg.role == "tool":
                converted.append(
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": msg.tool_call_id or "",
                                "content": msg.content or "",
                            }
                        ],
                    }
                )
                continue
            blocks: list[dict[str, Any]] = []
            if msg.content:
                blocks.append({"type": "text", "text": msg.content})
            for call in msg.tool_calls or []:
                fn = call.get("function", {})
                try:
                    args = json.loads(fn.get("arguments") or "{}")
                except json.JSONDecodeError:
                    args = {}
                blocks.append(
                    {
                        "type": "tool_use",
                        "id": call.get("id", ""),
                        "name": fn.get("name", ""),
                        "input": args,
                    }
                )
            if msg.role == "assistant":
                converted.append(
                    {"role": "assistant", "content": blocks or [{"type": "text", "text": ""}]}
                )
            else:
                converted.append({"role": msg.role, "content": blocks or msg.content or ""})
        return system, converted

    async def complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
        tool_choice: str | dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> CompletionResponse:
        system, converted_messages = self._convert_messages(messages)

        payload = {
            "model": self.config.model,
            "messages": converted_messages,
            "max_tokens": self.config.max_tokens,
            "temperature": self.config.temperature,
            **kwargs,
        }
        if system:
            payload["system"] = system
        if tools:
            payload["tools"] = self._convert_tools(tools)
        if tool_choice:
            payload["tool_choice"] = self._convert_tool_choice(tool_choice)

        assert self.client is not None
        response = await self.client.post("/v1/messages", json=payload)
        response.raise_for_status()
        data = response.json()

        content_parts = []
        tool_calls = []
        for block in data.get("content", []):
            if block["type"] == "text":
                content_parts.append(block["text"])
            elif block["type"] == "tool_use":
                tool_calls.append(
                    {
                        "id": block["id"],
                        "type": "function",
                        "function": {
                            "name": block["name"],
                            "arguments": json.dumps(block["input"]),
                        },
                    }
                )

        return CompletionResponse(
            content="".join(content_parts),
            model=data["model"],
            usage={
                "input_tokens": data["usage"]["input_tokens"],
                "output_tokens": data["usage"]["output_tokens"],
            },
            finish_reason=data.get("stop_reason"),
            tool_calls=tool_calls if tool_calls else None,
        )

    def _convert_tools(self, tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
        converted = []
        for tool in tools:
            if tool["type"] == "function":
                fn = tool["function"]
                converted.append(
                    {
                        "name": fn["name"],
                        "description": fn.get("description", ""),
                        "input_schema": fn.get("parameters", {"type": "object", "properties": {}}),
                    }
                )
        return converted

    def _convert_tool_choice(self, tool_choice: str | dict[str, Any]) -> dict[str, Any] | str:
        if isinstance(tool_choice, str):
            return tool_choice
        if tool_choice.get("type") == "function":
            return {"type": "tool", "name": tool_choice["function"]["name"]}
        return "auto"

    async def stream_complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        system, converted_messages = self._convert_messages(messages)

        payload = {
            "model": self.config.model,
            "messages": converted_messages,
            "max_tokens": self.config.max_tokens,
            "temperature": self.config.temperature,
            "stream": True,
            **kwargs,
        }
        if system:
            payload["system"] = system
        if tools:
            payload["tools"] = self._convert_tools(tools)

        assert self.client is not None
        async with self.client.stream("POST", "/v1/messages", json=payload) as response:
            response.raise_for_status()
            async for line in response.aiter_lines():
                if line.startswith("data: "):
                    data_str = line[6:]
                    try:
                        data = json.loads(data_str)
                        if (
                            data["type"] == "content_block_delta"
                            and data["delta"]["type"] == "text_delta"
                        ):
                            yield data["delta"]["text"]
                    except json.JSONDecodeError:
                        continue


class OllamaProvider(BaseProvider):
    """Ollama local LLM provider."""

    def _get_headers(self) -> dict[str, str]:
        return {"Content-Type": "application/json"}

    def _payload_messages(self, messages: list[Message]) -> list[dict[str, Any]]:
        """Ollama wants tool_calls arguments as objects (not JSON strings)."""
        converted = []
        for m in messages:
            d = m.model_dump(exclude_none=True)
            for call in d.get("tool_calls") or []:
                fn = call.get("function", {})
                if isinstance(fn.get("arguments"), str):
                    try:
                        fn["arguments"] = json.loads(fn["arguments"] or "{}")
                    except json.JSONDecodeError:
                        fn["arguments"] = {}
            converted.append(d)
        return converted

    @staticmethod
    def _normalize_tool_calls(tool_calls: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
        normalized = []
        for call in tool_calls or []:
            fn = call.get("function", {})
            args = fn.get("arguments")
            if isinstance(args, dict):
                args = json.dumps(args)
            normalized.append(
                {
                    "id": call.get("id", f"call_{len(normalized)}"),
                    "type": "function",
                    "function": {
                        "name": fn.get("name", ""),
                        "arguments": args or "{}",
                    },
                }
            )
        return normalized

    async def complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
        tool_choice: str | dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> CompletionResponse:
        payload = {
            "model": self.config.model,
            "messages": self._payload_messages(messages),
            "options": {
                "temperature": self.config.temperature,
                "num_predict": self.config.max_tokens,
            },
            "stream": False,
            **kwargs,
        }
        if tools:
            payload["tools"] = tools

        assert self.client is not None
        response = await self.client.post("/api/chat", json=payload)
        response.raise_for_status()
        data = response.json()

        tool_calls = self._normalize_tool_calls(data["message"].get("tool_calls"))

        return CompletionResponse(
            content=data["message"].get("content", ""),
            model=data["model"],
            finish_reason=data.get("done_reason"),
            tool_calls=tool_calls or None,
        )

    async def stream_complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        payload = {
            "model": self.config.model,
            "messages": self._payload_messages(messages),
            "options": {
                "temperature": self.config.temperature,
                "num_predict": self.config.max_tokens,
            },
            "stream": True,
            **kwargs,
        }
        if tools:
            payload["tools"] = tools

        assert self.client is not None
        async with self.client.stream("POST", "/api/chat", json=payload) as response:
            response.raise_for_status()
            async for line in response.aiter_lines():
                try:
                    data = json.loads(line)
                    if content := data.get("message", {}).get("content"):
                        yield content
                except json.JSONDecodeError:
                    continue


class LMStudioProvider(OpenAIProvider):
    """LM Studio provider (OpenAI-compatible)."""

    pass


class CustomProvider(OpenAIProvider):
    """Custom OpenAI-compatible provider."""

    pass


PROVIDER_MAP: dict[str, type[BaseProvider]] = {
    "openai": OpenAIProvider,
    "anthropic": AnthropicProvider,
    "ollama": OllamaProvider,
    "lmstudio": LMStudioProvider,
    "custom": CustomProvider,
}


def create_provider(config: AIProviderConfig) -> BaseProvider:
    """Factory function to create provider instance."""
    provider_class = PROVIDER_MAP.get(config.type)
    if not provider_class:
        raise ValueError(f"Unknown provider type: {config.type}")
    return provider_class(config)


async def get_best_provider(
    task_type: Literal["orchestrator", "skill", "local"] = "skill",
) -> BaseProvider:
    """Get the best available provider for a task type."""
    enabled = settings.get_enabled_providers()
    if not enabled:
        raise RuntimeError("No AI providers configured. Add at least one in config.")

    # Try to find preferred model
    if task_type == "orchestrator":
        preferred = settings.orchestrator_model
    elif task_type == "local":
        preferred = settings.local_model
    else:
        preferred = settings.skill_model

    # Find provider that has the preferred model
    for provider_config in enabled:
        if provider_config.model == preferred:
            return create_provider(provider_config)

    # Fallback to first enabled provider
    return create_provider(enabled[0])
