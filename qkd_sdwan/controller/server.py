"""Central Controller REST API server for QKD-SDWAN node registry, ML telemetry evaluation, and P2P routing."""

from __future__ import annotations

import hmac
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
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



def _extract_client_ip(handler: BaseHTTPRequestHandler) -> str:
    """Extract the client underlay IP from reverse-proxy headers or the HTTP socket peer address."""
    xff = handler.headers.get("X-Forwarded-For") if hasattr(handler, "headers") and handler.headers else None
    if xff:
        first_ip = xff.split(",")[0].strip()
        if first_ip:
            return first_ip
    x_real = handler.headers.get("X-Real-IP") if hasattr(handler, "headers") and handler.headers else None
    if x_real and x_real.strip():
        return x_real.strip()
    if getattr(handler, "client_address", None):
        return str(handler.client_address[0]).strip()
    return ""


_LAN_IPV4_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
)


def _is_lan_or_local_ip(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_unspecified:
        return True
    if isinstance(ip_obj, ipaddress.IPv4Address):
        return any(ip_obj in net for net in _LAN_IPV4_NETWORKS)
    return ip_obj.is_private


def _resolve_peer_underlay_host(reported_host: str, observed_ip: str) -> str:
    """Resolve the peer reachable underlay IP/hostname across LAN, NAT, or public WAN."""
    reported = (reported_host or "").strip()
    observed = (observed_ip or "").strip()

    obs_ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
    if observed:
        try:
            obs_ip_obj = ipaddress.ip_address(observed)
        except ValueError:
            obs_ip_obj = None

    obs_is_non_loopback = (
        obs_ip_obj is not None
        and not obs_ip_obj.is_loopback
        and not obs_ip_obj.is_unspecified
    )

    if reported in ("", "127.0.0.1", "0.0.0.0", "localhost", "::1", "auto"):
        if obs_is_non_loopback:
            return observed
        return "127.0.0.1" if reported in ("", "0.0.0.0", "auto") else reported

    try:
        rep_ip_obj = ipaddress.ip_address(reported)
    except ValueError:
        # Domain name / explicit hostname configured by user
        return reported

    if (
        _is_lan_or_local_ip(rep_ip_obj)
        and obs_ip_obj is not None
        and not _is_lan_or_local_ip(obs_ip_obj)
    ):
        return observed

    return reported


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
        state_path: Path | str | None = None,
        node_offline_ttl_s: float = 6.0,
    ) -> None:
        self.host = host
        self.port = port
        self.detector = detector or IsolationForestDetector()
        self.optimizer = optimizer or OverlayRouteOptimizer()
        self.overlay_subnet_prefix = overlay_subnet_prefix
        self.cluster_hmac_secret_hex = cluster_hmac_secret_hex or secrets.token_hex(32)
        self.state_path: Path | None = Path(state_path) if state_path else None
        self.node_offline_ttl_s = float(node_offline_ttl_s)
        self.stop_event = threading.Event()
        self._lock = threading.RLock()
        self._nodes: dict[str, NodeRegistration] = {}
        self._latest_metrics: dict[tuple[str, str], tuple[LinkTelemetry, float, LinkStatus, str]] = {}
        self._telemetry_history: list[dict[str, Any]] = []
        self._directives: dict[tuple[str, str], RouteDirective] = {}
        self._tokens: dict[str, EnrollmentToken] = {}
        self._allocated_ips: dict[str, str] = {}

        self._httpd: ThreadingHTTPServer | None = None
        self._server_thread: threading.Thread | None = None

        self._load_state()

        existing_bootstrap: EnrollmentToken | None = None
        with self._lock:
            if bootstrap_join_token and bootstrap_join_token.strip():
                for tok in self._tokens.values():
                    if tok.secret_token == bootstrap_join_token.strip():
                        existing_bootstrap = tok
                        break
            else:
                for tok in self._tokens.values():
                    if tok.label == "bootstrap-default" and not tok.revoked:
                        existing_bootstrap = tok
                        break

        if existing_bootstrap is not None:
            if existing_bootstrap.max_uses < 10000:
                existing_bootstrap.max_uses = 10000
            now_ts = time.time()
            if existing_bootstrap.expires_at < now_ts + 86400.0:
                existing_bootstrap.expires_at = now_ts + 31536000.0
            self.bootstrap_token: str = existing_bootstrap.secret_token
        else:
            bootstrap_tok = self.create_enrollment_token(
                label="bootstrap-default",
                max_uses=10000,
                ttl_seconds=31536000.0,
                custom_token=bootstrap_join_token,
            )
            self.bootstrap_token = bootstrap_tok.secret_token

    def _save_state_locked(self) -> None:
        if self.state_path is None:
            return
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "overlay_subnet_prefix": self.overlay_subnet_prefix,
                "cluster_hmac_secret_hex": self.cluster_hmac_secret_hex,
                "allocated_ips": dict(self._allocated_ips),
                "tokens": [t.to_dict(redact_secret=False) for t in self._tokens.values()],
                "nodes": [n.to_dict() for n in self._nodes.values()],
                "directives": [d.to_dict() for d in self._directives.values()],
                "latest_metrics": [
                    {
                        "telemetry": tel.to_dict(),
                        "anomaly_score": score,
                        "link_status": status.value,
                        "reason": reason,
                    }
                    for (_src, _dst), (tel, score, status, reason) in sorted(self._latest_metrics.items())
                ],
                "saved_at": time.time(),
            }
            tmp_path = self.state_path.with_suffix(self.state_path.suffix + ".tmp")
            tmp_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            os.replace(tmp_path, self.state_path)
        except Exception:
            pass

    def _load_state(self) -> None:
        if self.state_path is None or not self.state_path.exists():
            return
        try:
            raw = json.loads(self.state_path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                return
            with self._lock:
                if raw.get("cluster_hmac_secret_hex") and not self.cluster_hmac_secret_hex:
                    self.cluster_hmac_secret_hex = str(raw["cluster_hmac_secret_hex"])
                alloc = raw.get("allocated_ips", {})
                if isinstance(alloc, dict):
                    for k, v in alloc.items():
                        self._allocated_ips[str(k)] = str(v)
                for t_dict in raw.get("tokens", []):
                    if isinstance(t_dict, dict):
                        try:
                            tok = EnrollmentToken.from_dict(t_dict)
                            self._tokens[tok.token_id] = tok
                        except Exception:
                            pass
                for n_dict in raw.get("nodes", []):
                    if isinstance(n_dict, dict):
                        try:
                            node = NodeRegistration.from_dict(n_dict)
                            self._nodes[node.node_id] = node
                            self._allocated_ips[node.node_id] = node.overlay_ip
                        except Exception:
                            pass
                for d_dict in raw.get("directives", []):
                    if isinstance(d_dict, dict):
                        try:
                            directive = RouteDirective.from_dict(d_dict)
                            self._directives[(directive.source_node, directive.target_node)] = directive
                        except Exception:
                            pass
                for m_dict in raw.get("latest_metrics", []):
                    if isinstance(m_dict, dict) and isinstance(m_dict.get("telemetry"), dict):
                        try:
                            tel = LinkTelemetry.from_dict(m_dict["telemetry"])
                            score = float(m_dict.get("anomaly_score", 0.0))
                            status = LinkStatus(str(m_dict.get("link_status", "HEALTHY")))
                            reason = str(m_dict.get("reason", ""))
                            self._latest_metrics[(tel.source_node, tel.target_node)] = (tel, score, status, reason)
                        except Exception:
                            pass
        except Exception:
            pass

    def _refresh_liveness_locked(self, now: float | None = None) -> None:
        """Transition expired nodes to OFFLINE and mark their incident links OFFLINE_DOWN."""
        now_ts = time.time() if now is None else float(now)
        any_changed = False
        for _nid, reg in self._nodes.items():
            last_seen = reg.last_seen if reg.last_seen > 0.0 else reg.registered_at
            if last_seen > 10.0 and reg.status != "OFFLINE" and (now_ts - last_seen) > self.node_offline_ttl_s:
                reg.status = "OFFLINE"
                any_changed = True

        offline_nodes = {nid for nid, reg in self._nodes.items() if reg.status == "OFFLINE"}
        if offline_nodes:
            for (src, dst), (prev_tel, _prev_score, prev_status, _prev_reason) in list(self._latest_metrics.items()):
                if src in offline_nodes or dst in offline_nodes:
                    down_node = dst if dst in offline_nodes else src
                    down_reg = self._nodes.get(down_node)
                    down_last_seen = (
                        (down_reg.last_seen if down_reg.last_seen > 0.0 else down_reg.registered_at)
                        if down_reg is not None
                        else now_ts
                    )
                    silence_s = max(0, int(now_ts - down_last_seen)) if down_last_seen > 10.0 else 0
                    if (
                        prev_status != LinkStatus.OFFLINE_DOWN
                        or prev_tel.packet_loss_pct < 100.0
                        or prev_tel.key_rate_bps > 0.0
                        or prev_tel.qber > 0.0
                    ):
                        offline_tel = LinkTelemetry(
                            source_node=src,
                            target_node=dst,
                            timestamp=now_ts,
                            latency_ms=0.0,
                            jitter_ms=0.0,
                            packet_loss_pct=100.0,
                            throughput_mbps=0.0,
                            qber=0.0,
                            qber_delta=0.0,
                            key_rate_bps=0.0,
                            psk_epoch=prev_tel.psk_epoch,
                            handshake_age_s=round(max(0.0, now_ts - prev_tel.timestamp), 2),
                            qkd_abort_count=prev_tel.qkd_abort_count,
                        )
                        reason_str = (
                            f"Endpoint {down_node} is OFFLINE (service stopped or no heartbeat for {silence_s}s)"
                        )
                        self._latest_metrics[(src, dst)] = (offline_tel, 0.99, LinkStatus.OFFLINE_DOWN, reason_str)
                        any_changed = True

            optimizer_input = {k: (v[0], v[1], v[2]) for k, v in self._latest_metrics.items()}
            for directive in self.optimizer.compute_directives(self._nodes, optimizer_input):
                self._directives[(directive.source_node, directive.target_node)] = directive

            for (src, dst), cur_dir in list(self._directives.items()):
                if dst in offline_nodes and (
                    cur_dir.link_status != LinkStatus.OFFLINE_DOWN or cur_dir.route_mode != RouteMode.QUARANTINED
                ):
                    self._directives[(src, dst)] = RouteDirective(
                        source_node=src,
                        target_node=dst,
                        route_mode=RouteMode.QUARANTINED,
                        next_hop_node="",
                        next_hop_endpoint="",
                        anomaly_score=0.99,
                        link_status=LinkStatus.OFFLINE_DOWN,
                        force_rekey=False,
                        reason=f"Target peer {dst} is OFFLINE (service stopped or heartbeat timed out)",
                        updated_at=now_ts,
                    )
                    any_changed = True
                elif src in offline_nodes and cur_dir.link_status != LinkStatus.OFFLINE_DOWN:
                    self._directives[(src, dst)] = RouteDirective(
                        source_node=src,
                        target_node=dst,
                        route_mode=RouteMode.QUARANTINED,
                        next_hop_node="",
                        next_hop_endpoint="",
                        anomaly_score=0.99,
                        link_status=LinkStatus.OFFLINE_DOWN,
                        force_rekey=False,
                        reason=f"Source peer {src} is OFFLINE",
                        updated_at=now_ts,
                    )
                    any_changed = True

        if any_changed:
            self._save_state_locked()

    def mark_node_offline(self, node_id: str) -> bool:
        """Immediately mark a registered node OFFLINE and transition its links to OFFLINE_DOWN."""
        clean_id = (node_id or "").strip()
        if not clean_id:
            return False
        with self._lock:
            reg = self._nodes.get(clean_id)
            if reg is None:
                return False
            reg.status = "OFFLINE"
            self._refresh_liveness_locked(now=time.time())
            self._save_state_locked()
            return True
    @property
    def base_url(self) -> str:
        connect_host = "127.0.0.1" if self.host in ("0.0.0.0", "::", "") else self.host
        return f"http://{connect_host}:{self.port}"

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
            self._save_state_locked()
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
            self._save_state_locked()
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
        lan_host: str | None = None,
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
        clean_join_token = join_token.strip()
        clean_node_id = node_id.strip()
        with self._lock:
            matched_token: EnrollmentToken | None = None
            if clean_join_token.lower() == "auto":
                for tok in self._tokens.values():
                    if tok.label == "bootstrap-default" and not tok.revoked:
                        if not tok.is_valid(now=now):
                            tok.max_uses = max(tok.max_uses, tok.used_count + 10000)
                            tok.expires_at = max(tok.expires_at, now + 31536000.0)
                        matched_token = tok
                        break
                if matched_token is None:
                    matched_token = self.create_enrollment_token(
                        label="bootstrap-default",
                        max_uses=10000,
                        ttl_seconds=31536000.0,
                    )
            else:
                for tok in self._tokens.values():
                    if hmac.compare_digest(tok.secret_token, clean_join_token):
                        matched_token = tok
                        break

            if matched_token is None or not matched_token.is_valid(now=now):
                raise PermissionError("Invalid, expired, or exhausted enrollment join token")

            used_by_others = {
                ip for nid, ip in self._allocated_ips.items() if nid != clean_node_id
            } | {
                reg.overlay_ip for nid, reg in self._nodes.items() if nid != clean_node_id
            }

            allocated_ip: str | None = None
            if (
                requested_overlay_ip
                and requested_overlay_ip.strip()
                and requested_overlay_ip.strip().lower() not in ("auto", "0.0.0.0")
            ):
                req_ip = requested_overlay_ip.strip()
                if req_ip in used_by_others:
                    raise ValueError(f"Requested overlay IP {req_ip} is already allocated to another peer")
                allocated_ip = req_ip
            elif clean_node_id in self._allocated_ips and self._allocated_ips[clean_node_id] not in used_by_others:
                allocated_ip = self._allocated_ips[clean_node_id]
            else:
                for host_octet in range(10, 250):
                    candidate_ip = f"{self.overlay_subnet_prefix}{host_octet}"
                    if candidate_ip not in used_by_others:
                        allocated_ip = candidate_ip
                        break
                if allocated_ip is None:
                    stale_cutoff = now - 86400.0
                    for stale_nid, stale_reg in sorted(self._nodes.items(), key=lambda kv: kv[1].registered_at):
                        if stale_nid != clean_node_id and stale_reg.registered_at < stale_cutoff:
                            allocated_ip = stale_reg.overlay_ip
                            self._nodes.pop(stale_nid, None)
                            self._allocated_ips.pop(stale_nid, None)
                            break
                if allocated_ip is None:
                    raise RuntimeError("Overlay IP pool exhausted")

            if clean_node_id not in self._allocated_ips:
                matched_token.used_count += 1
            self._allocated_ips[clean_node_id] = allocated_ip
            auth_token_id = f"enrolled-{matched_token.token_id}"
            reg = NodeRegistration(
                node_id=clean_node_id,
                overlay_ip=allocated_ip,
                underlay_host=underlay_host.strip(),
                wg_port=int(wg_port),
                qkd_port=int(qkd_port),
                wg_public_key=wg_public_key.strip(),
                auth_token_id=auth_token_id,
                registered_at=now,
                lan_host=lan_host.strip() if (isinstance(lan_host, str) and lan_host.strip()) else None,
            )
            reg_result = self.register_node(reg)
            self._save_state_locked()
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
            now = time.time()
            used_by_others = {
                ip for nid, ip in self._allocated_ips.items() if nid != registration.node_id
            } | {
                reg.overlay_ip for nid, reg in self._nodes.items() if nid != registration.node_id
            }
            req_ip = (registration.overlay_ip or "").strip()
            if not req_ip or req_ip.lower() in ("auto", "0.0.0.0") or req_ip in used_by_others:
                existing_ip = self._allocated_ips.get(registration.node_id)
                if existing_ip and existing_ip not in used_by_others:
                    registration.overlay_ip = existing_ip
                else:
                    for host_octet in range(10, 250):
                        candidate_ip = f"{self.overlay_subnet_prefix}{host_octet}"
                        if candidate_ip not in used_by_others:
                            registration.overlay_ip = candidate_ip
                            break
            registration.registered_at = now
            registration.status = "ONLINE"
            registration.last_seen = now
            self._nodes[registration.node_id] = registration
            self._allocated_ips[registration.node_id] = registration.overlay_ip
            self._refresh_liveness_locked(now=now)
            # Create or restore default DIRECT_P2P directives between online peers
            for other_id, other_reg in self._nodes.items():
                if other_id == registration.node_id:
                    continue
                if (registration.node_id, other_id) not in self._directives:
                    if other_reg.status == "OFFLINE":
                        self._directives[(registration.node_id, other_id)] = RouteDirective(
                            source_node=registration.node_id,
                            target_node=other_id,
                            route_mode=RouteMode.QUARANTINED,
                            next_hop_node="",
                            next_hop_endpoint="",
                            anomaly_score=0.99,
                            link_status=LinkStatus.OFFLINE_DOWN,
                            force_rekey=False,
                            reason=f"Target peer {other_id} is OFFLINE",
                            updated_at=now,
                        )
                    else:
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
                    if other_reg.status != "OFFLINE" and existing_out.link_status == LinkStatus.OFFLINE_DOWN:
                        self._directives[(registration.node_id, other_id)] = RouteDirective(
                            source_node=registration.node_id,
                            target_node=other_id,
                            route_mode=RouteMode.DIRECT_P2P,
                            next_hop_node=other_id,
                            next_hop_endpoint=f"{other_reg.underlay_host}:{other_reg.wg_port}",
                            anomaly_score=0.0,
                            link_status=LinkStatus.HEALTHY,
                            force_rekey=True,
                            reason=f"Peer {registration.node_id} online; restored DIRECT_P2P to {other_id}",
                            updated_at=now,
                        )
                    elif existing_out.route_mode == RouteMode.DIRECT_P2P and existing_out.next_hop_node == other_id:
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
                    if other_reg.status != "OFFLINE" and existing_in.link_status == LinkStatus.OFFLINE_DOWN:
                        self._directives[(other_id, registration.node_id)] = RouteDirective(
                            source_node=other_id,
                            target_node=registration.node_id,
                            route_mode=RouteMode.DIRECT_P2P,
                            next_hop_node=registration.node_id,
                            next_hop_endpoint=f"{registration.underlay_host}:{registration.wg_port}",
                            anomaly_score=0.0,
                            link_status=LinkStatus.HEALTHY,
                            force_rekey=True,
                            reason=f"Peer {registration.node_id} returned ONLINE; restored DIRECT_P2P",
                            updated_at=now,
                        )
                    elif existing_in.route_mode == RouteMode.DIRECT_P2P and existing_in.next_hop_node == registration.node_id:
                        existing_in.next_hop_endpoint = f"{registration.underlay_host}:{registration.wg_port}"
            peers: list[dict[str, Any]] = []
            for nid, n in sorted(self._nodes.items()):
                if nid == registration.node_id:
                    continue
                p_dict = n.to_dict()
                p_dict["underlay_host"] = self._effective_peer_host(registration, n)
                peers.append(p_dict)
            self._save_state_locked()
            return {
                "status": "registered",
                "cluster_hmac_secret_hex": self.cluster_hmac_secret_hex,
                "node": registration.to_dict(),
                "peers": peers,
            }

    def ingest_telemetry(self, telemetry: LinkTelemetry) -> dict[str, Any]:
        with self._lock:
            now = time.time()
            src_reg = self._nodes.get(telemetry.source_node)
            if src_reg is not None:
                src_reg.registered_at = now
                src_reg.last_seen = now
                src_reg.status = "ONLINE"
            self._refresh_liveness_locked(now=now)
            anomaly_score, link_status, reason = self.detector.evaluate_telemetry(telemetry)
            target_reg = self._nodes.get(telemetry.target_node)
            if target_reg is not None and target_reg.status == "OFFLINE":
                anomaly_score = 0.99
                link_status = LinkStatus.OFFLINE_DOWN
                reason = f"Target peer {telemetry.target_node} is OFFLINE"
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
            self._save_state_locked()
            directive_dict = active_directive.to_dict()
            nh_node = self._nodes.get(active_directive.next_hop_node) if active_directive.next_hop_node else None
            if nh_node is not None and active_directive.route_mode in (RouteMode.DIRECT_P2P, RouteMode.RELAY_P2P):
                eff_nh_host = self._effective_peer_host(src_reg, nh_node)
                directive_dict["next_hop_endpoint"] = f"{eff_nh_host}:{nh_node.wg_port}"

            return {
                "status": "evaluated",
                "evaluation": {
                    "anomaly_score": anomaly_score,
                    "link_status": link_status.value,
                    "reason": reason,
                },
                "directive": directive_dict,
            }

    @staticmethod
    def _effective_peer_host(viewer: NodeRegistration | None, peer: NodeRegistration) -> str:
        if (
            viewer is not None
            and viewer.underlay_host == peer.underlay_host
            and peer.lan_host
            and peer.lan_host not in ("", "127.0.0.1", "0.0.0.0", "localhost", "::1", "auto")
        ):
            return peer.lan_host
        return peer.underlay_host

    def get_node_topology(self, node_id: str) -> dict[str, Any]:
        with self._lock:
            now = time.time()
            viewer = self._nodes.get(node_id)
            if viewer is not None:
                viewer.last_seen = now
                viewer.status = "ONLINE"
            self._refresh_liveness_locked(now=now)
            peers: list[dict[str, Any]] = []
            for nid, n in sorted(self._nodes.items()):
                if nid == node_id:
                    continue
                p_dict = n.to_dict()
                p_dict["underlay_host"] = self._effective_peer_host(viewer, n)
                peers.append(p_dict)

            directives: list[dict[str, Any]] = []
            for (src, _dst), d in sorted(self._directives.items()):
                if src != node_id:
                    continue
                d_dict = d.to_dict()
                nh_node = self._nodes.get(d.next_hop_node) if d.next_hop_node else None
                if nh_node is not None and d.route_mode in (RouteMode.DIRECT_P2P, RouteMode.RELAY_P2P):
                    eff_nh_host = self._effective_peer_host(viewer, nh_node)
                    d_dict["next_hop_endpoint"] = f"{eff_nh_host}:{nh_node.wg_port}"
                directives.append(d_dict)

            return {
                "node_id": node_id,
                "peers": peers,
                "directives": directives,
            }
    def get_cluster_status(self) -> dict[str, Any]:
        with self._lock:
            now = time.time()
            self._refresh_liveness_locked(now=now)
            links_summary = []
            for (src, dst), (tel, score, status, reason) in sorted(self._latest_metrics.items()):
                directive = self._directives.get((src, dst))
                links_summary.append(
                    {
                        "source_node": src,
                        "target_node": dst,
                        "timestamp": tel.timestamp,
                        "qber": tel.qber,
                        "qber_delta": tel.qber_delta,
                        "key_rate_bps": tel.key_rate_bps,
                        "latency_ms": tel.latency_ms,
                        "jitter_ms": tel.jitter_ms,
                        "packet_loss_pct": tel.packet_loss_pct,
                        "throughput_mbps": tel.throughput_mbps,
                        "psk_epoch": tel.psk_epoch,
                        "handshake_age_s": tel.handshake_age_s,
                        "qkd_abort_count": tel.qkd_abort_count,
                        "anomaly_score": score,
                        "link_status": status.value,
                        "reason": reason,
                        "directive": directive.to_dict() if directive else None,
                    }
                )
            online_count = sum(1 for reg in self._nodes.values() if reg.status != "OFFLINE")
            return {
                "status": "ok",
                "overlay_subnet_prefix": self.overlay_subnet_prefix,
                "registered_nodes": len(self._nodes),
                "online_nodes": online_count,
                "offline_nodes": len(self._nodes) - online_count,
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

                client_ip = _extract_client_ip(self)
                if path == "/api/v1/admin/shutdown":
                    if client_ip not in ("127.0.0.1", "::1", "localhost", ""):
                        self._send_json(HTTPStatus.FORBIDDEN, {"error": "Shutdown only permitted from localhost"})
                        return
                    self._send_json(HTTPStatus.OK, {"status": "shutting_down"})
                    controller.stop_event.set()
                    threading.Thread(target=controller.shutdown, daemon=True).start()
                    return

                try:
                    data = self._read_json_body()
                except Exception as exc:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"Invalid JSON body: {exc}"})
                    return

                client_ip = self.client_address[0] if self.client_address else ""
                if path == "/api/v1/nodes/register":
                    try:
                        raw_uh = str(data.get("underlay_host", "")).strip()
                        raw_lan = str(data.get("lan_host", "")).strip()
                        if not raw_lan and raw_uh not in ("", "127.0.0.1", "0.0.0.0", "localhost", "::1", "auto"):
                            try:
                                if _is_lan_or_local_ip(ipaddress.ip_address(raw_uh)):
                                    raw_lan = raw_uh
                            except ValueError:
                                pass
                        data["underlay_host"] = _resolve_peer_underlay_host(raw_uh, client_ip)
                        if raw_lan:
                            data["lan_host"] = raw_lan
                        reg = NodeRegistration.from_dict(data)
                        resp = controller.register_node(reg)
                        self._send_json(HTTPStatus.OK, resp)
                    except ValueError as exc:
                        self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return

                if path == "/api/v1/nodes/enroll":
                    try:
                        raw_uh = str(data.get("underlay_host", "127.0.0.1")).strip()
                        raw_lan = str(data.get("lan_host", "")).strip()
                        if not raw_lan and raw_uh not in ("", "127.0.0.1", "0.0.0.0", "localhost", "::1", "auto"):
                            try:
                                if _is_lan_or_local_ip(ipaddress.ip_address(raw_uh)):
                                    raw_lan = raw_uh
                            except ValueError:
                                pass
                        resolved_uh = _resolve_peer_underlay_host(raw_uh, client_ip)
                        resp = controller.enroll_node_with_token(
                            join_token=str(data.get("join_token", "")),
                            node_id=str(data.get("node_id", "")),
                            underlay_host=resolved_uh,
                            wg_port=int(data.get("wg_port", 0)),
                            qkd_port=int(data.get("qkd_port", 0)),
                            wg_public_key=str(data.get("wg_public_key", "")),
                            requested_overlay_ip=data.get("overlay_ip"),
                            lan_host=raw_lan or None,
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
                if path == "/api/v1/nodes/disconnect":
                    node_id = str(data.get("node_id", "")).strip()
                    if not node_id:
                        self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Missing node_id"})
                        return
                    marked = controller.mark_node_offline(node_id)
                    self._send_json(
                        HTTPStatus.OK,
                        {"status": "offline" if marked else "not_found", "node_id": node_id},
                    )
                    return

                if path == "/api/v1/telemetry":
                    try:
                        tel = LinkTelemetry.from_dict(data)
                        with controller._lock:
                            src_node = controller._nodes.get(tel.source_node)
                            if src_node is not None:
                                new_uh = _resolve_peer_underlay_host(src_node.underlay_host, client_ip)
                                if new_uh != src_node.underlay_host:
                                    src_node.underlay_host = new_uh
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

        class _ReusableThreadingHTTPServer(ThreadingHTTPServer):
            allow_reuse_address = True
            daemon_threads = True

        self._httpd = _ReusableThreadingHTTPServer((self.host, self.port), handler_cls)
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
        self.stop_event.set()
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._server_thread is not None:
            self._server_thread.join(timeout=2.0)
            self._server_thread = None
