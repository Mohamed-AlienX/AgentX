"""AI Model Router for intelligent model selection."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Literal

from agentx.ai.providers import BaseProvider, create_provider, get_best_provider
from agentx.config import AIProviderConfig, settings


class ModelRouter:
    """Routes tasks to appropriate AI models based on complexity and availability."""

    def __init__(self):
        self._providers: dict[str, BaseProvider] = {}
        self._provider_configs: dict[str, AIProviderConfig] = {}

    async def initialize(self) -> None:
        """Initialize all enabled providers."""
        for config in settings.get_enabled_providers():
            self._provider_configs[config.name] = config
            self._providers[config.name] = create_provider(config)
            await self._providers[config.name].__aenter__()

    async def close(self) -> None:
        """Close all provider connections."""
        for provider in self._providers.values():
            await provider.__aexit__(None, None, None)
        self._providers.clear()

    @asynccontextmanager
    async def get_provider(
        self,
        task_type: Literal["orchestrator", "skill", "local", "fast"] = "skill",
        preferred_provider: str | None = None,
    ):
        """Get a provider for the given task type."""
        if preferred_provider and preferred_provider in self._providers:
            yield self._providers[preferred_provider]
            return

        # Map task type to preferred model
        model_map = {
            "orchestrator": settings.orchestrator_model,
            "skill": settings.skill_model,
            "local": settings.local_model,
            "fast": settings.skill_model,  # Use skill model for fast tasks too
        }

        preferred_model = model_map.get(task_type, settings.skill_model)

        # Find provider with preferred model
        for name, config in self._provider_configs.items():
            if config.model == preferred_model:
                yield self._providers[name]
                return

        # Fallback to any available provider
        if self._providers:
            yield next(iter(self._providers.values()))
        else:
            # Last resort: create new provider
            provider = await get_best_provider(task_type)
            async with provider:
                yield provider

    async def complete(
        self,
        messages: list[dict],
        task_type: Literal["orchestrator", "skill", "local", "fast"] = "skill",
        preferred_provider: str | None = None,
        **kwargs,
    ) -> str:
        """Complete a chat request with automatic provider selection."""
        response = await self.complete_response(messages, task_type, preferred_provider, **kwargs)
        return response.content

    async def complete_response(
        self,
        messages: list[dict],
        task_type: Literal["orchestrator", "skill", "local", "fast"] = "skill",
        preferred_provider: str | None = None,
        **kwargs,
    ):
        """Non-streaming completion; returns the full CompletionResponse.

        Used by the tool-calling agent loop, which needs ``tool_calls``.
        """
        from agentx.ai.providers import Message

        msg_objects = [Message(**m) for m in messages]

        async with self.get_provider(task_type, preferred_provider) as provider:
            return await provider.complete(msg_objects, **kwargs)

    async def stream_complete(
        self,
        messages: list[dict],
        task_type: Literal["orchestrator", "skill", "local", "fast"] = "skill",
        preferred_provider: str | None = None,
        **kwargs,
    ):
        """Stream completion with automatic provider selection."""
        from agentx.ai.providers import Message

        msg_objects = [Message(**m) for m in messages]

        async with self.get_provider(task_type, preferred_provider) as provider:
            async for chunk in provider.stream_complete(msg_objects, **kwargs):
                yield chunk


# Global router instance
router = ModelRouter()


async def init_ai() -> None:
    """Initialize AI subsystem."""
    await router.initialize()


async def close_ai() -> None:
    """Close AI subsystem."""
    await router.close()
