"""Central controller components: ML inference engine, REST API server, and CLI Dashboard."""

from typing import Any

from qkd_sdwan.controller.ml_engine import IsolationForestDetector, OverlayRouteOptimizer
from qkd_sdwan.controller.server import SDWANControllerServer


def render_controller_dashboard(*args: Any, **kwargs: Any) -> str:
    from qkd_sdwan.controller.cli import render_controller_dashboard as _render

    return _render(*args, **kwargs)


__all__ = [
    "IsolationForestDetector",
    "OverlayRouteOptimizer",
    "SDWANControllerServer",
    "render_controller_dashboard",
]
