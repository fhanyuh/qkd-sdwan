"""Distributed P2P SD-WAN with BB84 QKD Simulation and ML Inference Controller."""

from __future__ import annotations

from typing import Any

from qkd_sdwan.common.models import (
    BB84SessionResult,
    EnrollmentToken,
    LinkStatus,
    LinkTelemetry,
    NodeRegistration,
    P2PDataMessage,
    RouteDirective,
    RouteMode,
)

__all__ = [
    "BB84SessionResult",
    "EnrollmentToken",
    "LinkStatus",
    "LinkTelemetry",
    "NodeRegistration",
    "P2PDataMessage",
    "RouteDirective",
    "RouteMode",
    "SDWANEndpointAgent",
    "render_client_dashboard",
    "render_controller_dashboard",
]
__version__ = "0.1.0"


def __getattr__(name: str) -> Any:
    if name in ("SDWANEndpointAgent", "render_client_dashboard"):
        from qkd_sdwan.client import agent

        return getattr(agent, name)
    if name == "render_controller_dashboard":
        from qkd_sdwan.controller import cli

        return getattr(cli, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
