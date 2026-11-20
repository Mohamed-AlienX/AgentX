"""Burp Suite integration - REST API client."""

from __future__ import annotations

from typing import Any

import httpx

from agentx.config import settings


class BurpClient:
    """Client for the Burp Suite REST API (Burp Suite Professional)."""

    def __init__(
        self, host: str | None = None, port: int | None = None, api_key: str | None = None
    ):
        cfg = settings.burp
        self.host = host or cfg.host
        self.port = port or cfg.port
        self.api_key = api_key or cfg.api_key
        self.scheme = "https" if cfg.use_https else "http"
        self.base_url = f"{self.scheme}://{self.host}:{self.port}"

    @property
    def enabled(self) -> bool:
        return settings.burp.enabled

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    async def is_alive(self) -> bool:
        """Check if Burp's REST API is reachable."""
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get(f"{self.base_url}/", headers=self._headers())
                return resp.status_code < 500
        except Exception:
            return False

    async def get_proxy_history(self) -> list[dict[str, Any]]:
        """Fetch Burp proxy HTTP history."""
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"{self.base_url}/v0.1/proxy/history",
                headers=self._headers(),
            )
            resp.raise_for_status()
            return resp.json()

    async def send_to_repeater(
        self, request: str, hostname: str, port: int, https: bool = True
    ) -> bool:
        """Send a request to Burp Repeater."""
        payload = {
            "request": request,
            "targetHostname": hostname,
            "targetPort": port,
            "usesHttps": https,
        }
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{self.base_url}/v0.1/repeater",
                headers=self._headers(),
                json=payload,
            )
            return resp.status_code < 400

    async def get_scope(self) -> dict[str, Any]:
        """Get the current Burp target scope."""
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"{self.base_url}/v0.1/target/scope",
                headers=self._headers(),
            )
            resp.raise_for_status()
            return resp.json()

    async def set_scope(self, scope: dict[str, Any]) -> bool:
        """Set the Burp target scope."""
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.put(
                f"{self.base_url}/v0.1/target/scope",
                headers=self._headers(),
                json=scope,
            )
            return resp.status_code < 400


burp_client = BurpClient()
