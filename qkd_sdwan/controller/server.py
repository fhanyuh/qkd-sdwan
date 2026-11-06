"""Central Controller REST API server for QKD-SDWAN node registry, ML telemetry evaluation, and P2P routing."""

from __future__ import annotations

import hmac
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import secrets
import threading
import time
from typing import Any
from urllib.parse import urlparse

from qkd_sdwan.common.models import (
    EnrollmentToken,
    LinkStatus,
    LinkTelemetry,
    NodeRegistration,
    RouteDirective,
    RouteMode,
)
from qkd_sdwan.controller.ml_engine import IsolationForestDetector, OverlayRouteOptimizer


class SDWANControllerServer:
    """Thread-safe Central Controller managing node registrations, Join Tokens, ML anomaly scoring, and P2P RouteDirectives."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 0,
        detector: IsolationForestDetector | None = None,
        optimizer: OverlayRouteOptimizer | None = None,
        overlay_subnet_prefix: str = "10.200.0.",
        cluster_hmac_secret_hex: str | None = None,
        bootstrap_join_token: str | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.detector = detector or IsolationForestDetector()
        self.optimizer = optimizer or OverlayRouteOptimizer()
        self.overlay_subnet_prefix = overlay_subnet_prefix
        self.cluster_hmac_secret_hex = cluster_hmac_secret_hex or secrets.token_hex(32)

        self._lock = threading.RLock()
        self._nodes: dict[str, NodeRegistration] = {}
        self._latest_metrics: dict[tuple[str, str], tuple[LinkTelemetry, float, LinkStatus, str]] = {}
        self._telemetry_history: list[dict[str, Any]] = []
        self._directives: dict[tuple[str, str], RouteDirective] = {}
        self._tokens: dict[str, EnrollmentToken] = {}
        self._allocated_ips: dict[str, str] = {}

        self._httpd: ThreadingHTTPServer | None = None
        self._server_thread: threading.Thread | None = None

        bootstrap_tok = self.create_enrollment_token(
            label="bootstrap-default",
            max_uses=100,
            ttl_seconds=86400.0,
            custom_token=bootstrap_join_token,
        )
        self.bootstrap_token: str = bootstrap_tok.secret_token

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def create_enrollment_token(
        self,
        label: str = "default",
        max_uses: int = 10,
        ttl_seconds: float = 86400.0,
        custom_token: str | None = None,
    ) -> EnrollmentToken:
        """Create and store a new Join Token for client node auto-enrollment."""
        if max_uses <= 0:
            raise ValueError("max_uses must be > 0")
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be > 0")
        now = time.time()
        with self._lock:
            token_id = f"tok-{secrets.token_hex(4)}"
            while token_id in self._tokens:
                token_id = f"tok-{secrets.token_hex(4)}"
            secret_token = (custom_token.strip() if custom_token and custom_token.strip() else f"qkd-join-{secrets.token_hex(12)}")
            token = EnrollmentToken(
                token_id=token_id,
                secret_token=secret_token,
                label=label.strip() or "default",
                max_uses=int(max_uses),
                used_count=0,
                expires_at=now + float(ttl_seconds),
                revoked=False,
                created_at=now,
            )
            self._tokens[token_id] = token
            return token

    def list_enrollment_tokens(self, redact_secret: bool = False) -> list[dict[str, Any]]:
        """Return all enrollment tokens ordered by creation timestamp."""
        with self._lock:
            ordered = sorted(self._tokens.values(), key=lambda t: (t.created_at, t.token_id))
            return [t.to_dict(redact_secret=redact_secret) for t in ordered]

    def revoke_enrollment_token(self, token_id: str) -> bool:
        """Revoke an enrollment token by token_id (or matching secret_token)."""
        with self._lock:
            tok = self._tokens.get(token_id)
            if tok is None:
                for candidate in self._tokens.values():
                    if hmac.compare_digest(candidate.secret_token, token_id):
                        tok = candidate
                        break
            if tok is None:
                return False
            tok.revoked = True
            return True

    def enroll_node_with_token(
        self,
        join_token: str,
        node_id: str,
        underlay_host: str,
        wg_port: int,
        qkd_port: int,
        wg_public_key: str,
        requested_overlay_ip: str | None = None,
    ) -> dict[str, Any]:
        """Validate Join Token, allocate an overlay IP, register the node, and return cluster credentials."""
        if not isinstance(join_token, str) or not join_token.strip():
            raise PermissionError("Missing enrollment join token")
        if not isinstance(node_id, str) or not node_id.strip():
            raise ValueError("Missing or invalid node_id")
        if not isinstance(underlay_host, str) or not underlay_host.strip():
            raise ValueError("Missing or invalid underlay_host")
        if not isinstance(wg_public_key, str) or not wg_public_key.strip():
            raise ValueError("Missing or invalid wg_public_key")

        now = time.time()
        with self._lock:
            matched_token: EnrollmentToken | None = None
            for tok in self._tokens.values():
                if hmac.compare_digest(tok.secret_token, join_token.strip()):
                    matched_token = tok
                    break

            if matched_token is None or not matched_token.is_valid(now=now):
                raise PermissionError("Invalid, expired, or exhausted enrollment join token")

            used_by_others = {
                ip for nid, ip in self._allocated_ips.items() if nid != node_id
            } | {
                reg.overlay_ip for nid, reg in self._nodes.items() if nid != node_id
            }

            allocated_ip: str | None = None
            if requested_overlay_ip and requested_overlay_ip.strip():
                req_ip = requested_overlay_ip.strip()
                if req_ip in used_by_others:
                    raise ValueError(f"Requested overlay IP {req_ip} is already allocated to another peer")
                allocated_ip = req_ip
            elif node_id in self._allocated_ips:
                allocated_ip = self._allocated_ips[node_id]
            else:
                for host_octet in range(10, 250):
                    candidate_ip = f"{self.overlay_subnet_prefix}{host_octet}"
                    if candidate_ip not in used_by_others:
                        allocated_ip = candidate_ip
                        break
                if allocated_ip is None:
                    raise RuntimeError("Overlay IP pool exhausted")

            matched_token.used_count += 1
            self._allocated_ips[node_id] = allocated_ip
            auth_token_id = f"enrolled-{matched_token.token_id}"
            reg = NodeRegistration(
                node_id=node_id.strip(),
                overlay_ip=allocated_ip,
                underlay_host=underlay_host.strip(),
                wg_port=int(wg_port),
                qkd_port=int(qkd_port),
                wg_public_key=wg_public_key.strip(),
                auth_token_id=auth_token_id,
                registered_at=now,
            )
            reg_result = self.register_node(reg)
            return {
                "status": "enrolled",
                "token_id": matched_token.token_id,
                "allocated_overlay_ip": allocated_ip,
                "cluster_hmac_secret_hex": self.cluster_hmac_secret_hex,
                "auth_token_id": auth_token_id,
                "node": reg_result["node"],
                "peers": reg_result["peers"],
            }

    def register_node(self, registration: NodeRegistration) -> dict[str, Any]:
        with self._lock:
            self._nodes[registration.node_id] = registration
            self._allocated_ips[registration.node_id] = registration.overlay_ip
            # Create default DIRECT_P2P directives between newly registered peers if not yet evaluated
            now = time.time()
            for other_id, other_reg in self._nodes.items():
                if other_id == registration.node_id:
                    continue
                if (registration.node_id, other_id) not in self._directives:
                    self._directives[(registration.node_id, other_id)] = RouteDirective(
                        source_node=registration.node_id,
                        target_node=other_id,
                        route_mode=RouteMode.DIRECT_P2P,
                        next_hop_node=other_id,
                        next_hop_endpoint=f"{other_reg.underlay_host}:{other_reg.wg_port}",
                        anomaly_score=0.0,
                        link_status=LinkStatus.HEALTHY,
                        force_rekey=False,
                        reason="Initial peer registration default P2P route",
                        updated_at=now,
                    )
                else:
                    existing_out = self._directives[(registration.node_id, other_id)]
                    if existing_out.route_mode == RouteMode.DIRECT_P2P and existing_out.next_hop_node == other_id:
                        existing_out.next_hop_endpoint = f"{other_reg.underlay_host}:{other_reg.wg_port}"

                if (other_id, registration.node_id) not in self._directives:
                    self._directives[(other_id, registration.node_id)] = RouteDirective(
                        source_node=other_id,
                        target_node=registration.node_id,
                        route_mode=RouteMode.DIRECT_P2P,
                        next_hop_node=registration.node_id,
                        next_hop_endpoint=f"{registration.underlay_host}:{registration.wg_port}",
                        anomaly_score=0.0,
                        link_status=LinkStatus.HEALTHY,
                        force_rekey=False,
                        reason="Initial peer registration default P2P route",
                        updated_at=now,
                    )
                else:
                    existing_in = self._directives[(other_id, registration.node_id)]
                    if existing_in.route_mode == RouteMode.DIRECT_P2P and existing_in.next_hop_node == registration.node_id:
                        existing_in.next_hop_endpoint = f"{registration.underlay_host}:{registration.wg_port}"

            peers = [
                n.to_dict() for nid, n in sorted(self._nodes.items()) if nid != registration.node_id
            ]
            return {
                "status": "registered",
                "node": registration.to_dict(),
                "peers": peers,
            }

    def ingest_telemetry(self, telemetry: LinkTelemetry) -> dict[str, Any]:
        with self._lock:
            anomaly_score, link_status, reason = self.detector.evaluate_telemetry(telemetry)
            pair = (telemetry.source_node, telemetry.target_node)
            self._latest_metrics[pair] = (telemetry, anomaly_score, link_status, reason)

            optimizer_input = {
                k: (v[0], v[1], v[2]) for k, v in self._latest_metrics.items()
            }
            computed_directives = self.optimizer.compute_directives(self._nodes, optimizer_input)
            for directive in computed_directives:
                self._directives[(directive.source_node, directive.target_node)] = directive

            active_directive = self._directives.get(pair)
            if active_directive is None:
                target_reg = self._nodes.get(telemetry.target_node)
                ep = f"{target_reg.underlay_host}:{target_reg.wg_port}" if target_reg else "127.0.0.1:0"
                active_directive = RouteDirective(
                    source_node=telemetry.source_node,
                    target_node=telemetry.target_node,
                    route_mode=RouteMode.DIRECT_P2P,
                    next_hop_node=telemetry.target_node,
                    next_hop_endpoint=ep,
                    anomaly_score=anomaly_score,
                    link_status=link_status,
                    force_rekey=(link_status != LinkStatus.HEALTHY),
                    reason=reason,
                    updated_at=time.time(),
                )
                self._directives[pair] = active_directive

            record = {
                "telemetry": telemetry.to_dict(),
                "anomaly_score": anomaly_score,
                "link_status": link_status.value,
                "reason": reason,
                "directive": active_directive.to_dict(),
            }
            self._telemetry_history.append(record)

            return {
                "status": "evaluated",
                "evaluation": {
                    "anomaly_score": anomaly_score,
                    "link_status": link_status.value,
                    "reason": reason,
                },
                "directive": active_directive.to_dict(),
            }

    def get_node_topology(self, node_id: str) -> dict[str, Any]:
        with self._lock:
            peers = [
                n.to_dict() for nid, n in sorted(self._nodes.items()) if nid != node_id
            ]
            directives = [
                d.to_dict()
                for (src, _dst), d in sorted(self._directives.items())
                if src == node_id
            ]
            return {
                "node_id": node_id,
                "peers": peers,
                "directives": directives,
            }

    def get_cluster_status(self) -> dict[str, Any]:
        with self._lock:
            links_summary = []
            for (src, dst), (tel, score, status, reason) in sorted(self._latest_metrics.items()):
                directive = self._directives.get((src, dst))
                links_summary.append(
                    {
                        "source_node": src,
                        "target_node": dst,
                        "qber": tel.qber,
                        "qber_delta": tel.qber_delta,
                        "key_rate_bps": tel.key_rate_bps,
                        "latency_ms": tel.latency_ms,
                        "jitter_ms": tel.jitter_ms,
                        "packet_loss_pct": tel.packet_loss_pct,
                        "psk_epoch": tel.psk_epoch,
                        "qkd_abort_count": tel.qkd_abort_count,
                        "anomaly_score": score,
                        "link_status": status.value,
                        "reason": reason,
                        "directive": directive.to_dict() if directive else None,
                    }
                )
            now = time.time()
            return {
                "status": "ok",
                "overlay_subnet_prefix": self.overlay_subnet_prefix,
                "registered_nodes": len(self._nodes),
                "nodes": {nid: reg.to_dict() for nid, reg in sorted(self._nodes.items())},
                "links": links_summary,
                "directives": [d.to_dict() for _, d in sorted(self._directives.items())],
                "telemetry_history_count": len(self._telemetry_history),
                "active_tokens_count": sum(1 for t in self._tokens.values() if t.is_valid(now=now)),
                "tokens": self.list_enrollment_tokens(redact_secret=False),
            }

    def _make_handler(self) -> type[BaseHTTPRequestHandler]:
        controller = self

        class _ControllerRequestHandler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:
                # Silence noisy per-request HTTP stdout logging during tests and CLI tables
                return

            def _send_json(self, status_code: int, payload: dict[str, Any]) -> None:
                body = json.dumps(payload).encode("utf-8")
                self.send_response(status_code)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _read_json_body(self) -> dict[str, Any]:
                content_len = int(self.headers.get("Content-Length", "0"))
                if content_len <= 0:
                    raise ValueError("Empty request body")
                raw = self.rfile.read(content_len)
                return json.loads(raw.decode("utf-8"))

            def do_GET(self) -> None:
                parsed = urlparse(self.path)
                path = parsed.path.rstrip("/")

                if path == "/api/v1/health":
                    with controller._lock:
                        payload = {
                            "status": "ok",
                            "registered_nodes": len(controller._nodes),
                            "active_directives": len(controller._directives),
                            "active_tokens": sum(1 for t in controller._tokens.values() if t.is_valid()),
                        }
                    self._send_json(HTTPStatus.OK, payload)
                    return

                if path == "/api/v1/cluster/status":
                    self._send_json(HTTPStatus.OK, controller.get_cluster_status())
                    return

                if path == "/api/v1/tokens":
                    self._send_json(
                        HTTPStatus.OK,
                        {
                            "status": "ok",
                            "tokens": controller.list_enrollment_tokens(redact_secret=False),
                        },
                    )
                    return

                if path.startswith("/api/v1/topology/"):
                    node_id = path.split("/api/v1/topology/", 1)[1].strip("/")
                    if not node_id:
                        self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Missing node_id"})
                        return
                    self._send_json(HTTPStatus.OK, controller.get_node_topology(node_id))
                    return

                self._send_json(HTTPStatus.NOT_FOUND, {"error": f"Unknown endpoint: {path}"})

            def do_POST(self) -> None:
                parsed = urlparse(self.path)
                path = parsed.path.rstrip("/")

                try:
                    data = self._read_json_body()
                except Exception as exc:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"Invalid JSON body: {exc}"})
                    return

                if path == "/api/v1/nodes/register":
                    try:
                        reg = NodeRegistration.from_dict(data)
                        resp = controller.register_node(reg)
                        self._send_json(HTTPStatus.OK, resp)
                    except ValueError as exc:
                        self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return

                if path == "/api/v1/nodes/enroll":
                    try:
                        resp = controller.enroll_node_with_token(
                            join_token=str(data.get("join_token", "")),
                            node_id=str(data.get("node_id", "")),
                            underlay_host=str(data.get("underlay_host", "127.0.0.1")),
                            wg_port=int(data.get("wg_port", 0)),
                            qkd_port=int(data.get("qkd_port", 0)),
                            wg_public_key=str(data.get("wg_public_key", "")),
                            requested_overlay_ip=data.get("overlay_ip"),
                        )
                        self._send_json(HTTPStatus.OK, resp)
                    except PermissionError as exc:
                        self._send_json(HTTPStatus.FORBIDDEN, {"error": str(exc)})
                    except (ValueError, TypeError, RuntimeError) as exc:
                        self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return

                if path == "/api/v1/tokens/create":
                    try:
                        label = str(data.get("label", "cli-token"))
                        max_uses = int(data.get("max_uses", 10))
                        ttl_seconds = float(data.get("ttl_seconds", 86400.0))
                        custom_token = data.get("custom_token")
                        tok = controller.create_enrollment_token(
                            label=label,
                            max_uses=max_uses,
                            ttl_seconds=ttl_seconds,
                            custom_token=str(custom_token) if custom_token else None,
                        )
                        self._send_json(
                            HTTPStatus.OK,
                            {"status": "created", "token": tok.to_dict(redact_secret=False)},
                        )
                    except (ValueError, TypeError) as exc:
                        self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return

                if path == "/api/v1/tokens/revoke":
                    token_id = str(data.get("token_id", "")).strip()
                    if not token_id:
                        self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Missing token_id"})
                        return
                    revoked = controller.revoke_enrollment_token(token_id)
                    if not revoked:
                        self._send_json(HTTPStatus.NOT_FOUND, {"error": f"Token not found: {token_id}"})
                        return
                    self._send_json(HTTPStatus.OK, {"status": "revoked", "token_id": token_id})
                    return

                if path == "/api/v1/telemetry":
                    try:
                        tel = LinkTelemetry.from_dict(data)
                        resp = controller.ingest_telemetry(tel)
                        self._send_json(HTTPStatus.OK, resp)
                    except ValueError as exc:
                        self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return

                self._send_json(HTTPStatus.NOT_FOUND, {"error": f"Unknown endpoint: {path}"})

        return _ControllerRequestHandler

    def start_background(self) -> tuple[str, int]:
        """Start the ThreadingHTTPServer in a daemon thread and return (host, bound_port)."""
        if self._httpd is not None:
            return self.host, self.port

        handler_cls = self._make_handler()
        self._httpd = ThreadingHTTPServer((self.host, self.port), handler_cls)
        self.port = int(self._httpd.server_address[1])
        self._server_thread = threading.Thread(
            target=self._httpd.serve_forever,
            name="qkd-sdwan-controller-http",
            daemon=True,
        )
        self._server_thread.start()
        return self.host, self.port

    def shutdown(self) -> None:
        """Stop the background HTTP server cleanly."""
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._server_thread is not None:
            self._server_thread.join(timeout=2.0)
            self._server_thread = None
