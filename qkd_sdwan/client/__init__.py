"""Endpoint client components: BB84 QKD engine, WireGuard daemon, SD-WAN agent, and Client CLI Dashboard."""

from __future__ import annotations

from typing import Any

__all__ = [
    "SDWANEndpointAgent",
    "render_client_dashboard",
    "run_client_dashboard_interactive",
]


def __getattr__(name: str) -> Any:
    if name in __all__:
        from qkd_sdwan.client import agent

        return getattr(agent, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
