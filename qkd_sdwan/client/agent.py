"""SD-WAN Endpoint Agent integrating BB84 QKD negotiation, WireGuard PSK injection, P2P data transfer, and Client CLI."""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any
from urllib import error, parse, request
from qkd_sdwan.client.bb84_engine import BB84ProtocolEngine, QuantumChannelParams
from qkd_sdwan.client.wg_manager import WireGuardTunnelDaemon, generate_wg_keypair
from qkd_sdwan.common.models import (
    BB84SessionResult,
    LinkTelemetry,
    NodeRegistration,
    P2PDataMessage,
    RouteDirective,
    RouteMode,
)

def _default_node_id() -> str:
    """Generate a deterministic, human-friendly node ID from the local machine hostname."""
    try:
        raw_host = socket.gethostname().split(".")[0].strip().lower()
        cleaned = "".join(ch if (ch.isalnum() or ch == "-") else "-" for ch in raw_host).strip("-")
        if cleaned and cleaned not in ("localhost", "ip6-localhost"):
            return cleaned if cleaned.startswith("edge-") else f"edge-{cleaned}"
    except Exception:
        pass
    return "edge-node-01"


def _is_local_interface_ip(ip_str: str) -> bool:
    """Return True if ip_str is currently assigned to a local network interface on this machine."""
    clean = ip_str.strip()
    if not clean or clean.lower() in ("0.0.0.0", "::", "auto"):
        return False
    if clean.lower() in ("127.0.0.1", "localhost", "::1"):
        return True
    try:
        ipaddress.ip_address(clean)
    except ValueError:
        return True
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind((clean, 0))
            return True
    except OSError:
        return False


def _normalize_controller_url(raw_url: str) -> str:
    """Normalize a controller IP/hostname or URL into http://<host>:<port>."""
    clean = raw_url.strip()
    if not clean:
        return "http://192.168.1.2:8080"
    if not clean.startswith(("http://", "https://")):
        clean = f"http://{clean}"
    parsed = parse.urlparse(clean)
    if parsed.hostname and parsed.port is None:
        scheme = parsed.scheme or "http"
        path = parsed.path.rstrip("/")
        return f"{scheme}://{parsed.hostname}:8080{path}"
    return clean.rstrip("/")


def _detect_underlay_host(controller_url: str, configured_host: str | None = None) -> str:
    """Detect the local outbound IPv4 address used to reach the Central Controller, handling network roaming."""
    clean_cfg = (configured_host or "").strip()
    if clean_cfg and clean_cfg.lower() not in ("", "127.0.0.1", "0.0.0.0", "localhost", "::1", "auto"):
        if _is_local_interface_ip(clean_cfg):
            return clean_cfg

    try:
        parsed = parse.urlparse(controller_url)
        target_host = (parsed.hostname or "").strip()
        target_port = int(parsed.port or 8080)
        if target_host and target_host not in ("127.0.0.1", "localhost", "::1", "0.0.0.0"):
            for probe_host, probe_port in ((target_host, target_port), ("192.168.1.1", 80), ("8.8.8.8", 80)):
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                        s.connect((probe_host, probe_port))
                        local_ip = s.getsockname()[0]
                        if local_ip and not local_ip.startswith("127."):
                            return str(local_ip)
                except OSError:
                    continue
    except Exception:
        pass
    if clean_cfg.lower() in ("auto", "0.0.0.0", ""):
        return "127.0.0.1"
    return clean_cfg if _is_local_interface_ip(clean_cfg) else "127.0.0.1"

class TelemetryExporter:
    """HTTP client for communicating node registrations, token enrollment, telemetry, and topology sync with the Controller."""

    def __init__(self, controller_url: str, timeout: float = 5.0) -> None:
        self.controller_url = controller_url.rstrip("/")
        self.timeout = timeout

    def _request_json(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        retries: int = 3,
    ) -> dict[str, Any]:
        url = f"{self.controller_url}{path}"
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {"Content-Type": "application/json; charset=utf-8"} if body is not None else {}
        max_attempts = max(1, int(retries))

        for attempt in range(max_attempts):
            req = request.Request(url, data=body, headers=headers, method=method)
            try:
                with request.urlopen(req, timeout=self.timeout) as resp:
                    raw = resp.read().decode("utf-8")
                    return json.loads(raw)
            except error.HTTPError as exc:
                err_body = exc.read().decode("utf-8", errors="replace")
                exc.close()
                try:
                    parsed = json.loads(err_body)
                    err_msg = str(parsed.get("error", err_body))
                except Exception:
                    err_msg = err_body or str(exc)
                if exc.code == 403:
                    raise PermissionError(err_msg) from exc
                if exc.code in (400, 404):
                    raise ValueError(err_msg) from exc
                raise RuntimeError(f"HTTP {exc.code}: {err_msg}") from exc
            except (error.URLError, TimeoutError, ConnectionError) as exc:
                if attempt + 1 >= max_attempts:
                    raise
                time.sleep(0.05 * (2**attempt))
        raise RuntimeError(f"Failed request to {url}")
    def enroll_node(
        self,
        join_token: str,
        node_id: str,
        underlay_host: str,
        wg_port: int,
        qkd_port: int,
        wg_public_key: str,
        overlay_ip: str | None = None,
        lan_host: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "join_token": join_token,
            "node_id": node_id,
            "underlay_host": underlay_host,
            "wg_port": wg_port,
            "qkd_port": qkd_port,
            "wg_public_key": wg_public_key,
            "overlay_ip": overlay_ip,
        }
        if lan_host:
            payload["lan_host"] = lan_host
        return self._request_json(
            "POST",
            "/api/v1/nodes/enroll",
            payload,
        )

    def register_node(self, registration: NodeRegistration) -> dict[str, Any]:
        return self._request_json("POST", "/api/v1/nodes/register", registration.to_dict())

    def send_telemetry(self, telemetry: LinkTelemetry) -> dict[str, Any]:
        return self._request_json("POST", "/api/v1/telemetry", telemetry.to_dict())

    def fetch_topology(self, node_id: str) -> dict[str, Any]:
        return self._request_json("GET", f"/api/v1/topology/{node_id}")

    def disconnect_node(self, node_id: str) -> dict[str, Any]:
        return self._request_json("POST", "/api/v1/nodes/disconnect", {"node_id": node_id}, retries=1)

class SDWANEndpointAgent:
    """Integrated endpoint orchestrator for P2P BB84 key rotation, WireGuard PSK injection, ML routing, and P2P messaging."""

    def __init__(
        self,
        node_id: str,
        overlay_ip: str,
        controller_url: str,
        auth_secret: bytes = b"qkd-sdwan-default-hmac-secret",
        underlay_host: str = "127.0.0.1",
        wg_port: int = 0,
        qkd_port: int = 0,
        interface_name: str = "wg-qkd0",
        private_key_b64: str | None = None,
        prefer_kernel_wg: bool = False,
        channel_params: QuantumChannelParams | None = None,
        config_path: Path | str | None = None,
        state_path: Path | str | None = None,
    ) -> None:
        self.node_id = node_id
        self.overlay_ip = overlay_ip
        raw_uh_str = (underlay_host or "").strip()
        self.underlay_host_mode = "auto" if raw_uh_str.lower() in ("", "auto", "0.0.0.0") else "configured"
        self.lan_host = _detect_underlay_host(controller_url, None)
        self.underlay_host = _detect_underlay_host(controller_url, underlay_host)
        self.controller_url = controller_url.rstrip("/")
        self.auth_secret = auth_secret
        self.auth_token_id = "hmac-sha256-cluster-v1"
        self.config_path: Path | None = Path(config_path) if config_path else None
        if state_path is not None:
            self.state_path: Path | None = Path(state_path)
        elif self.config_path is not None:
            self.state_path = self.config_path.with_suffix(".state.json")
        else:
            self.state_path = None
        self.control_url: str | None = None
        self.stop_event = threading.Event()
        self._control_httpd: ThreadingHTTPServer | None = None
        self._control_thread: threading.Thread | None = None
        self._heartbeat_thread: threading.Thread | None = None
        self._probe_thread: threading.Thread | None = None
        self._agent_lock = threading.RLock()

        self.exporter = TelemetryExporter(controller_url=self.controller_url)
        self.peer_registry: dict[str, NodeRegistration] = {}
        self.active_directives: dict[str, RouteDirective] = {}
        self._peer_epoch: dict[str, int] = {}
        self._last_qber: dict[str, float] = {}
        self._abort_counts: dict[str, int] = {}
        self._last_rekey_ts: dict[str, float] = {}
        self.last_bb84_results: dict[str, BB84SessionResult] = {}
        self.bb84_history: list[BB84SessionResult] = []
        self.wg_daemon = WireGuardTunnelDaemon(
            node_id=node_id,
            interface_name=interface_name,
            overlay_ip=overlay_ip,
            listen_port=wg_port,
            private_key_b64=private_key_b64,
            prefer_kernel_wg=prefer_kernel_wg,
            bind_host="0.0.0.0",
        )
        self.wg_port = self.wg_daemon.bound_port

        self.bb84_engine = BB84ProtocolEngine(
            node_id=node_id,
            auth_secret=auth_secret,
            channel_params=channel_params,
            peer_lookup=lambda pid: (
                (self.peer_registry[pid].underlay_host, self.peer_registry[pid].qkd_port)
                if pid in self.peer_registry
                else None
            ),
        )
        try:
            try:
                self.bb84_engine.start_tcp_responder(
                    host="0.0.0.0",
                    port=qkd_port,
                    on_key_established=self._on_responder_bb84_completed,
                )
            except OSError:
                if qkd_port != 0:
                    self.bb84_engine.start_tcp_responder(
                        host="0.0.0.0",
                        port=0,
                        on_key_established=self._on_responder_bb84_completed,
                    )
                else:
                    raise
        except Exception:
            self.wg_daemon.close()
            raise
        self.qkd_port = self.bb84_engine.bound_port
        self.load_state()
        self.wg_daemon.register_message_callback(lambda _msg: self.save_state())
    @classmethod
    def enroll_with_controller(
        cls,
        controller_url: str,
        join_token: str,
        node_id: str,
        underlay_host: str = "127.0.0.1",
        wg_port: int = 0,
        qkd_port: int = 0,
        overlay_ip: str | None = None,
        config_output_path: Path | str | None = None,
        prefer_kernel_wg: bool = False,
        channel_params: QuantumChannelParams | None = None,
    ) -> tuple["SDWANEndpointAgent", dict[str, Any]]:
        """Auto-enroll a new client node with the Central Controller using a Join Token."""
        priv_b64, pub_b64 = generate_wg_keypair()
        exporter = TelemetryExporter(controller_url=controller_url)
        enroll_resp = exporter.enroll_node(
            join_token=join_token,
            node_id=node_id,
            underlay_host=underlay_host,
            wg_port=wg_port,
            qkd_port=qkd_port,
            wg_public_key=pub_b64,
            overlay_ip=overlay_ip,
        )
        allocated_ip = str(enroll_resp["allocated_overlay_ip"])
        secret_hex = str(enroll_resp["cluster_hmac_secret_hex"])
        auth_token_id = str(enroll_resp.get("auth_token_id", f"enrolled-{enroll_resp.get('token_id', 'tok')}"))

        agent = cls(
            node_id=node_id,
            overlay_ip=allocated_ip,
            controller_url=controller_url,
            auth_secret=bytes.fromhex(secret_hex),
            underlay_host=underlay_host,
            wg_port=wg_port,
            qkd_port=qkd_port,
            private_key_b64=priv_b64,
            prefer_kernel_wg=prefer_kernel_wg,
            channel_params=channel_params,
            config_path=config_output_path,
        )
        agent.auth_token_id = auth_token_id
        reg_resp = agent.register_with_controller()
        agent.sync_topology()

        enroll_resp["node"] = reg_resp["node"]
        enroll_resp["peers"] = reg_resp["peers"]

        if config_output_path is not None:
            out_path = Path(config_output_path)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            cfg_payload = {
                "node_id": node_id,
                "overlay_ip": allocated_ip,
                "underlay_host": underlay_host,
                "controller_url": controller_url,
                "wg_port": agent.wg_port,
                "qkd_port": agent.qkd_port,
                "wg_private_key": agent.wg_daemon.private_key_b64,
                "wg_public_key": agent.wg_daemon.public_key_b64,
                "cluster_hmac_secret_hex": secret_hex,
                "auth_token_id": auth_token_id,
                "enrolled_token_id": enroll_resp.get("token_id"),
            }
            out_path.write_text(json.dumps(cfg_payload, indent=2) + "\n", encoding="utf-8")
            agent.save_state()
        return agent, enroll_resp

    def _on_responder_bb84_completed(self, result: BB84SessionResult) -> None:
        """Automatically inject the established 256-bit BB84 key on the responder (Bob) side."""
        with self._agent_lock:
            self.last_bb84_results[result.peer_node] = result
            self.bb84_history.append(result)
            if len(self.bb84_history) > 128:
                self.bb84_history.pop(0)

        if not result.aborted and result.final_key_bytes is not None:
            peer_reg = self.peer_registry.get(result.peer_node)
            peer_pub = peer_reg.wg_public_key if peer_reg else None
            if peer_pub is None:
                state = self.wg_daemon.get_peer_state(result.peer_node)
                peer_pub = state.peer_public_key if state else None
            if peer_pub is None:
                try:
                    self.sync_topology()
                except Exception:
                    pass
                peer_reg = self.peer_registry.get(result.peer_node)
                peer_pub = peer_reg.wg_public_key if peer_reg else None
            if peer_pub:
                self.wg_daemon.inject_preshared_key(
                    peer_node=result.peer_node,
                    peer_public_key=peer_pub,
                    raw_key_32bytes=result.final_key_bytes,
                    epoch=result.epoch,
                )
                with self._agent_lock:
                    self._peer_epoch[result.peer_node] = result.epoch
                    self._last_rekey_ts[result.peer_node] = time.time()
        self.save_state()
    def register_with_controller(self) -> dict[str, Any]:
        """Register this endpoint with the Central Controller and populate initial peer table."""
        local_lan = _detect_underlay_host(self.controller_url, None)
        if local_lan and local_lan not in ("127.0.0.1", "0.0.0.0", "localhost", "::1"):
            self.lan_host = local_lan
        reg = NodeRegistration(
            node_id=self.node_id,
            overlay_ip=self.overlay_ip,
            underlay_host=self.underlay_host,
            wg_port=self.wg_port,
            qkd_port=self.qkd_port,
            wg_public_key=self.wg_daemon.public_key_b64,
            auth_token_id=self.auth_token_id,
            registered_at=time.time(),
            lan_host=self.lan_host if self.lan_host not in ("", "127.0.0.1", "0.0.0.0", "localhost", "::1") else None,
        )
        resp = self.exporter.register_node(reg)
        node_info = resp.get("node")
        if isinstance(node_info, dict):
            if node_info.get("underlay_host"):
                self.underlay_host = str(node_info["underlay_host"])
            if node_info.get("overlay_ip") and str(node_info["overlay_ip"]) != self.overlay_ip:
                self.overlay_ip = str(node_info["overlay_ip"])
                self.wg_daemon.overlay_ip = self.overlay_ip
        cluster_secret_hex = resp.get("cluster_hmac_secret_hex")
        if isinstance(cluster_secret_hex, str) and len(cluster_secret_hex) >= 32:
            try:
                new_secret = bytes.fromhex(cluster_secret_hex)
                if new_secret != self.auth_secret:
                    self.auth_secret = new_secret
                    self.bb84_engine.auth_secret = new_secret
            except ValueError:
                pass
        for peer_dict in resp.get("peers", []):
            self._ingest_peer_dict(peer_dict)
        self.save_state()
        return resp
    def _ingest_peer_dict(self, peer_dict: dict[str, Any]) -> NodeRegistration:
        peer_reg = NodeRegistration.from_dict(peer_dict)
        self.peer_registry[peer_reg.node_id] = peer_reg
        self.wg_daemon.register_peer(
            peer_node=peer_reg.node_id,
            peer_public_key=peer_reg.wg_public_key,
            peer_overlay_ip=peer_reg.overlay_ip,
            underlay_endpoint=f"{peer_reg.underlay_host}:{peer_reg.wg_port}",
        )
        return peer_reg

    def sync_topology(self) -> dict[str, Any]:
        """Fetch latest peer registrations and active RouteDirectives from the Central Controller."""
        topo = self.exporter.fetch_topology(self.node_id)
        for peer_dict in topo.get("peers", []):
            self._ingest_peer_dict(peer_dict)
        for dir_dict in topo.get("directives", []):
            directive = RouteDirective.from_dict(dir_dict)
            self.active_directives[directive.target_node] = directive
            self.wg_daemon.apply_route_directive(directive)
        self.save_state()
        return topo

    def send_p2p_data(
        self,
        target_node: str,
        payload: bytes,
        content_type: str = "text",
        filename: str | None = None,
        auto_rekey: bool = True,
        sync_topology: bool = True,
    ) -> dict[str, Any]:
        """Send an encrypted P2P application message or file payload to target_node over the WireGuard overlay."""
        if sync_topology:
            self.sync_topology()
        if target_node not in self.peer_registry:
            raise KeyError(f"Peer {target_node} is not registered with Central Controller")

        if auto_rekey and self._peer_epoch.get(target_node, 0) == 0:
            self.run_key_rotation_and_telemetry_cycle(target_node)

        peer_state = self.wg_daemon.get_peer_state(target_node)
        psk_epoch = self._peer_epoch.get(target_node, peer_state.psk_epoch if peer_state else 0)
        route_mode_str = peer_state.route_mode.value if peer_state else RouteMode.DIRECT_P2P.value
        via_relay = peer_state.via_relay_node if peer_state else None

        msg = P2PDataMessage(
            message_id=f"msg-{secrets.token_hex(6)}",
            source_node=self.node_id,
            target_node=target_node,
            content_type=content_type,
            filename=filename,
            payload_b64=base64.b64encode(payload).decode("ascii"),
            psk_epoch=psk_epoch,
            route_mode=route_mode_str,
            via_relay_node=via_relay,
            timestamp=time.time(),
        )
        envelope = {
            "type": "P2P_APP_MESSAGE",
            "message": msg.to_dict(),
        }
        wire_bytes = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
        try:
            delivery = self.wg_daemon.send_overlay_packet(target_node=target_node, payload=wire_bytes)
        except TimeoutError:
            if peer_state is not None and peer_state.route_mode == RouteMode.DIRECT_P2P:
                relayed_deliv: dict[str, Any] | None = None
                for cand_id, cand_reg in self.peer_registry.items():
                    if cand_id == target_node:
                        continue
                    fallback_dir = RouteDirective(
                        source_node=self.node_id,
                        target_node=target_node,
                        route_mode=RouteMode.RELAY_P2P,
                        next_hop_node=cand_id,
                        next_hop_endpoint=f"{cand_reg.underlay_host}:{cand_reg.wg_port}",
                        anomaly_score=0.65,
                        link_status=RouteDirective.from_dict(
                            {
                                "source_node": self.node_id,
                                "target_node": target_node,
                                "route_mode": "RELAY_P2P",
                                "next_hop_node": cand_id,
                                "next_hop_endpoint": f"{cand_reg.underlay_host}:{cand_reg.wg_port}",
                                "anomaly_score": 0.65,
                                "link_status": "DEGRADED_UNDERLAY",
                                "force_rekey": False,
                                "reason": f"Auto-failover to P2P relay {cand_id} across NAT/WAN",
                                "updated_at": time.time(),
                            }
                        ).link_status,
                        force_rekey=False,
                        reason=f"Auto-failover to P2P relay {cand_id} across NAT/WAN",
                        updated_at=time.time(),
                    )
                    self.wg_daemon.apply_route_directive(fallback_dir)
                    self.active_directives[target_node] = fallback_dir
                    try:
                        relayed_deliv = self.wg_daemon.send_overlay_packet(target_node=target_node, payload=wire_bytes)
                        break
                    except Exception:
                        continue
                if relayed_deliv is None:
                    raise
                delivery = relayed_deliv
            else:
                raise

        msg.route_mode = str(delivery.get("route_mode", msg.route_mode))
        msg.via_relay_node = delivery.get("via_relay_node") or msg.via_relay_node
        self.wg_daemon.record_outbox_message(msg)
        self.save_state()
        return {
            "status": "sent",
            "message": msg.to_dict(),
            "delivery": delivery,
        }
    def send_p2p_text(
        self,
        target_node: str,
        text: str,
        auto_rekey: bool = True,
        sync_topology: bool = True,
    ) -> dict[str, Any]:
        """Send an encrypted UTF-8 text message to a peer over the WireGuard QKD overlay."""
        return self.send_p2p_data(
            target_node=target_node,
            payload=text.encode("utf-8"),
            content_type="text",
            filename=None,
            auto_rekey=auto_rekey,
            sync_topology=sync_topology,
        )

    def send_p2p_file(
        self,
        target_node: str,
        file_path: str | Path,
        auto_rekey: bool = True,
        sync_topology: bool = True,
    ) -> dict[str, Any]:
        """Read a local file and transmit it encrypted to a peer over the WireGuard QKD overlay."""
        path_obj = Path(file_path)
        file_bytes = path_obj.read_bytes()
        return self.send_p2p_data(
            target_node=target_node,
            payload=file_bytes,
            content_type="file",
            filename=path_obj.name,
            auto_rekey=auto_rekey,
            sync_topology=sync_topology,
        )

    def get_received_messages(self, clear: bool = False) -> list[P2PDataMessage]:
        """Retrieve decrypted P2P application messages received by this endpoint."""
        return self.wg_daemon.get_inbox_messages(clear=clear)

    def get_sent_messages(self, clear: bool = False) -> list[P2PDataMessage]:
        """Retrieve P2P application messages sent by this endpoint."""
        return self.wg_daemon.get_outbox_messages(clear=clear)

    def save_inbox_file(self, message_id_or_index: str | int, dest_dir: str | Path = ".") -> Path:
        """Export a received message or file from the inbox to disk after verifying SHA-256 integrity."""
        msgs = self.get_received_messages(clear=False)
        target_msg: P2PDataMessage | None = None

        if isinstance(message_id_or_index, int):
            if 1 <= message_id_or_index <= len(msgs):
                target_msg = msgs[message_id_or_index - 1]
            elif 0 <= message_id_or_index < len(msgs):
                target_msg = msgs[message_id_or_index]
        else:
            key_str = str(message_id_or_index).strip()
            for m in msgs:
                if m.message_id == key_str:
                    target_msg = m
                    break
            if target_msg is None and key_str.isdigit():
                idx = int(key_str)
                if 1 <= idx <= len(msgs):
                    target_msg = msgs[idx - 1]
                elif 0 <= idx < len(msgs):
                    target_msg = msgs[idx]

        if target_msg is None:
            raise KeyError(f"Inbox message not found: {message_id_or_index}")

        raw_bytes = target_msg.decode_payload(verify=True)
        safe_name = Path(target_msg.filename or f"{target_msg.message_id}.bin").name
        dest_path = Path(dest_dir)
        dest_path.mkdir(parents=True, exist_ok=True)
        out_file = dest_path / safe_name
        out_file.write_bytes(raw_bytes)
        return out_file
    def run_key_rotation_and_telemetry_cycle(
        self,
        target_node: str,
        override_channel_params: QuantumChannelParams | None = None,
        simulated_underlay: dict[str, float] | None = None,
        probe_payload: bytes = b"QKD-SDWAN-P2P-PROBE",
    ) -> dict[str, Any]:
        """Execute a full P2P cycle: topology sync, BB84 session, PSK injection, telemetry report, and routing update."""
        # 1. Sync peer list and existing directives from Central Controller
        self.sync_topology()
        if target_node not in self.peer_registry:
            raise KeyError(f"Peer {target_node} is not registered with Central Controller")

        peer_reg = self.peer_registry[target_node]
        next_epoch = self._peer_epoch.get(target_node, 0) + 1

        # 2. Negotiate BB84 quantum session over TCP with the peer (falling back to relay node if direct TCP is unreachable)
        probe_stats_fallback: dict[str, Any] | None = None
        try:
            bb84_result = self.bb84_engine.initiate_session(
                peer_host=peer_reg.underlay_host,
                peer_port=peer_reg.qkd_port,
                peer_node=target_node,
                epoch=next_epoch,
                override_params=override_channel_params,
            )
        except (OSError, TimeoutError, ConnectionError):
            relay_candidates: list[NodeRegistration] = []
            cur_dir = self.active_directives.get(target_node)
            if cur_dir and cur_dir.next_hop_node and cur_dir.next_hop_node != target_node and cur_dir.next_hop_node in self.peer_registry:
                relay_candidates.append(self.peer_registry[cur_dir.next_hop_node])
            for cand_id, cand_reg in self.peer_registry.items():
                if cand_id != target_node and cand_reg.status != "OFFLINE" and cand_reg not in relay_candidates:
                    relay_candidates.append(cand_reg)
            bb84_result_relayed: BB84SessionResult | None = None
            for relay_reg in relay_candidates:
                try:
                    bb84_result_relayed = self.bb84_engine.initiate_session(
                        peer_host=relay_reg.underlay_host,
                        peer_port=relay_reg.qkd_port,
                        peer_node=target_node,
                        epoch=next_epoch,
                        override_params=override_channel_params,
                    )
                    break
                except Exception:
                    continue
            if bb84_result_relayed is None:
                probe_stats_fallback = self.wg_daemon.probe_peer_link(
                    target_node=target_node,
                    count=3,
                    timeout=0.5,
                    probe_payload=probe_payload,
                )
                if peer_reg.status == "OFFLINE" or not probe_stats_fallback["reachable"]:
                    bb84_result = BB84SessionResult(
                        session_id=f"bb84-offline-{secrets.token_hex(4)}",
                        peer_node=target_node,
                        epoch=next_epoch,
                        raw_Exported_qubits=0,
                        transmitted_qubits=0,
                        sifted_key_bits=0,
                        measured_qber=0.0,
                        corrected_errors=0,
                        final_key_bytes=None,
                        psk_fingerprint_sha256=None,
                        aborted=True,
                        abort_reason="PEER_OFFLINE_UNREACHABLE",
                        duration_ms=0.0,
                        key_rate_bps=0.0,
                    )
                    with self._agent_lock:
                        self.last_bb84_results[target_node] = bb84_result
                        self.bb84_history.append(bb84_result)
                        if len(self.bb84_history) > 128:
                            self.bb84_history.pop(0)
                        self._abort_counts[target_node] = self._abort_counts.get(target_node, 0) + 1
                        self._last_rekey_ts[target_node] = time.time()
                        if target_node in self.peer_registry:
                            self.peer_registry[target_node].status = "OFFLINE"
                    peer_state = self.wg_daemon.get_peer_state(target_node)
                    handshake_age_s = (
                        round(max(0.0, time.time() - peer_state.last_psk_rotated_at), 2)
                        if (peer_state and peer_state.last_psk_rotated_at > 0)
                        else 0.0
                    )
                    offline_tel = LinkTelemetry(
                        source_node=self.node_id,
                        target_node=target_node,
                        timestamp=time.time(),
                        latency_ms=0.0,
                        jitter_ms=0.0,
                        packet_loss_pct=100.0,
                        throughput_mbps=0.0,
                        qber=0.0,
                        qber_delta=0.0,
                        key_rate_bps=0.0,
                        psk_epoch=self._peer_epoch.get(target_node, 0),
                        handshake_age_s=handshake_age_s,
                        qkd_abort_count=self._abort_counts.get(target_node, 1),
                    )
                    controller_resp = self.exporter.send_telemetry(offline_tel)
                    directive = RouteDirective.from_dict(controller_resp["directive"])
                    self.active_directives[target_node] = directive
                    self.wg_daemon.apply_route_directive(directive)
                    self.save_state()
                    return {
                        "source_node": self.node_id,
                        "target_node": target_node,
                        "bb84": bb84_result.to_summary_dict(),
                        "psk_injected": False,
                        "injection_info": None,
                        "telemetry": offline_tel.to_dict(),
                        "evaluation": controller_resp["evaluation"],
                        "directive": directive.to_dict(),
                        "emergency_relay_rekey_executed": False,
                        "dataplane_delivery": None,
                    }
                existing_bb84 = self.last_bb84_results.get(target_node)
                if existing_bb84 is not None and not existing_bb84.aborted and existing_bb84.final_key_bytes is not None:
                    bb84_result = existing_bb84
                else:
                    bb84_result = self.bb84_engine.negotiate_nat_relayed_session(
                        peer_node=target_node,
                        epoch=next_epoch,
                        rtt_ms=float(probe_stats_fallback["latency_ms"]),
                        override_params=override_channel_params,
                    )
                    last_deliv = probe_stats_fallback.get("last_delivery") or {}
                    if last_deliv.get("status") == "AUTH_PROBE_REPLY":
                        bb84_result.final_key_bytes = None
            else:
                bb84_result = bb84_result_relayed
        with self._agent_lock:
            self.last_bb84_results[target_node] = bb84_result
            self.bb84_history.append(bb84_result)
            if len(self.bb84_history) > 128:
                self.bb84_history.pop(0)
            self._last_rekey_ts[target_node] = time.time()
        psk_injected = False
        injection_info: dict[str, Any] | None = None
        if not bb84_result.aborted:
            self._abort_counts[target_node] = 0
            self._peer_epoch[target_node] = next_epoch
            if bb84_result.final_key_bytes is not None:
                # 3. Inject 256-bit BB84 key into WireGuard PresharedKey slot
                injection_info = self.wg_daemon.inject_preshared_key(
                    peer_node=target_node,
                    peer_public_key=peer_reg.wg_public_key,
                    raw_key_32bytes=bb84_result.final_key_bytes,
                    epoch=next_epoch,
                )
                psk_injected = True
        else:
            # 4. BB84 aborted (e.g., QBER > 11% Shor-Preskill bound): reject key rotation & increment abort count
            self._abort_counts[target_node] = self._abort_counts.get(target_node, 0) + 1
        # 5. Measure real P2P overlay link metrics via multi-packet UDP probing and send LinkTelemetry to Controller
        probe_stats = probe_stats_fallback or self.wg_daemon.probe_peer_link(
            target_node=target_node,
            count=3,
            timeout=0.6,
            probe_payload=probe_payload,
        )
        probe_delivery: dict[str, Any] | None = probe_stats.get("last_delivery")
        peer_state = self.wg_daemon.get_peer_state(target_node)

        sim = simulated_underlay or {}
        latency_ms = float(sim.get("latency_ms", probe_stats["latency_ms"]))
        jitter_ms = float(sim.get("jitter_ms", probe_stats["jitter_ms"]))
        packet_loss_pct = float(sim.get("packet_loss_pct", probe_stats["packet_loss_pct"]))
        throughput_mbps = float(sim.get("throughput_mbps", probe_stats["throughput_mbps"]))

        prev_qber = self._last_qber.get(target_node, bb84_result.measured_qber)
        qber_delta = round(bb84_result.measured_qber - prev_qber, 6)
        self._last_qber[target_node] = bb84_result.measured_qber

        active_epoch = self._peer_epoch.get(target_node, 0)
        handshake_age_s = (
            round(max(0.0, time.time() - peer_state.last_psk_rotated_at), 2)
            if (peer_state and peer_state.last_psk_rotated_at > 0)
            else 0.0
        )

        telemetry = LinkTelemetry(
            source_node=self.node_id,
            target_node=target_node,
            timestamp=time.time(),
            latency_ms=latency_ms,
            jitter_ms=jitter_ms,
            packet_loss_pct=packet_loss_pct,
            throughput_mbps=throughput_mbps,
            qber=bb84_result.measured_qber,
            qber_delta=qber_delta,
            key_rate_bps=bb84_result.key_rate_bps,
            psk_epoch=active_epoch,
            handshake_age_s=handshake_age_s,
            qkd_abort_count=self._abort_counts.get(target_node, 0),
        )

        controller_resp = self.exporter.send_telemetry(telemetry)
        directive = RouteDirective.from_dict(controller_resp["directive"])
        self.active_directives[target_node] = directive

        # 6. Apply Controller RouteDirective (including RELAY_P2P failover or emergency re-key)
        self.wg_daemon.apply_route_directive(directive)
        rekey_triggered = False
        if directive.force_rekey and directive.route_mode == RouteMode.RELAY_P2P and directive.next_hop_node:
            relay_node = directive.next_hop_node
            if relay_node in self.peer_registry:
                relay_reg = self.peer_registry[relay_node]
                relay_epoch = self._peer_epoch.get(relay_node, 0) + 1
                relay_bb84 = self.bb84_engine.initiate_session(
                    peer_host=relay_reg.underlay_host,
                    peer_port=relay_reg.qkd_port,
                    peer_node=relay_node,
                    epoch=relay_epoch,
                )
                with self._agent_lock:
                    self.last_bb84_results[relay_node] = relay_bb84
                    self.bb84_history.append(relay_bb84)
                    if len(self.bb84_history) > 128:
                        self.bb84_history.pop(0)
                if not relay_bb84.aborted and relay_bb84.final_key_bytes is not None:
                    self.wg_daemon.inject_preshared_key(
                        peer_node=relay_node,
                        peer_public_key=relay_reg.wg_public_key,
                        raw_key_32bytes=relay_bb84.final_key_bytes,
                        epoch=relay_epoch,
                    )
                    self._peer_epoch[relay_node] = relay_epoch
                    rekey_triggered = True
        # Verify data-plane packet delivery along the newly applied directive (DIRECT_P2P or RELAY_P2P)
        post_directive_delivery: dict[str, Any] | None = None
        if directive.route_mode != RouteMode.QUARANTINED:
            if (
                directive.route_mode == RouteMode.DIRECT_P2P
                and isinstance(probe_delivery, dict)
                and probe_delivery.get("route_mode") == "RELAY_P2P"
                and probe_delivery.get("via_relay_node") in self.peer_registry
            ):
                rel_id = str(probe_delivery["via_relay_node"])
                rel_reg = self.peer_registry[rel_id]
                relay_dir = RouteDirective(
                    source_node=self.node_id,
                    target_node=target_node,
                    route_mode=RouteMode.RELAY_P2P,
                    next_hop_node=rel_id,
                    next_hop_endpoint=f"{rel_reg.underlay_host}:{rel_reg.wg_port}",
                    anomaly_score=directive.anomaly_score,
                    link_status=directive.link_status,
                    force_rekey=directive.force_rekey,
                    reason=f"Auto-failover to P2P relay {rel_id} across NAT/WAN",
                    updated_at=time.time(),
                )
                self.wg_daemon.apply_route_directive(relay_dir)
                self.active_directives[target_node] = relay_dir
                directive = relay_dir
                post_directive_delivery = probe_delivery
            else:
                try:
                    post_directive_delivery = self.wg_daemon.send_overlay_packet(
                        target_node=target_node,
                        payload=probe_payload,
                        allow_quarantined_probe=True,
                    )
                except TimeoutError:
                    if directive.route_mode == RouteMode.DIRECT_P2P:
                        for cand_id, cand_reg in self.peer_registry.items():
                            if cand_id == target_node:
                                continue
                            relay_dir = RouteDirective(
                                source_node=self.node_id,
                                target_node=target_node,
                                route_mode=RouteMode.RELAY_P2P,
                                next_hop_node=cand_id,
                                next_hop_endpoint=f"{cand_reg.underlay_host}:{cand_reg.wg_port}",
                                anomaly_score=directive.anomaly_score,
                                link_status=directive.link_status,
                                force_rekey=directive.force_rekey,
                                reason=f"Auto-failover to P2P relay {cand_id} across NAT/WAN",
                                updated_at=time.time(),
                            )
                            self.wg_daemon.apply_route_directive(relay_dir)
                            self.active_directives[target_node] = relay_dir
                            directive = relay_dir
                            try:
                                post_directive_delivery = self.wg_daemon.send_overlay_packet(
                                    target_node=target_node,
                                    payload=probe_payload,
                                    allow_quarantined_probe=True,
                                )
                                break
                            except Exception:
                                continue
                    if post_directive_delivery is None:
                        raise
        self.save_state()
        return {
            "source_node": self.node_id,
            "target_node": target_node,
            "bb84": bb84_result.to_summary_dict(),
            "psk_injected": psk_injected,
            "injection_info": injection_info,
            "telemetry": telemetry.to_dict(),
            "evaluation": controller_resp["evaluation"],
            "directive": directive.to_dict(),
            "emergency_relay_rekey_executed": rekey_triggered,
            "dataplane_delivery": post_directive_delivery or probe_delivery,
        }

    def export_state_dict(self, include_dashboard: bool = False) -> dict[str, Any]:
        """Export a JSON-serializable snapshot of the endpoint state, BB84 sessions, and P2P inbox/outbox."""
        with self._agent_lock:
            bb84_list = [s.to_summary_dict() for s in self.bb84_history[-64:]]
            peers_list = [p.to_dict() for _, p in sorted(self.peer_registry.items())]
            directives_list = [d.to_dict() for _, d in sorted(self.active_directives.items())]

        wg_peers_dict = {
            pid: pstate.to_dict() for pid, pstate in sorted(self.wg_daemon.list_peers().items())
        }
        inbox_list = [m.to_dict() for m in self.get_received_messages(clear=False)]
        outbox_list = [m.to_dict() for m in self.get_sent_messages(clear=False)]
        payload: dict[str, Any] = {
            "status": "ok",
            "pid": os.getpid(),
            "control_url": self.control_url,
            "node_id": self.node_id,
            "overlay_ip": self.overlay_ip,
            "underlay_host": self.underlay_host,
            "controller_url": self.controller_url,
            "wg_port": self.wg_port,
            "qkd_port": self.qkd_port,
            "wg_public_key": self.wg_daemon.public_key_b64,
            "wg_backend_mode": self.wg_daemon.backend_mode,
            "auth_token_id": self.auth_token_id,
            "relay_forwarded_packets": self.wg_daemon.relay_forwarded_packets,
            "peers": peers_list,
            "wg_peers": wg_peers_dict,
            "directives": directives_list,
            "bb84_history": bb84_list,
            "inbox": inbox_list,
            "outbox": outbox_list,
            "saved_at": time.time(),
        }
        if include_dashboard:
            payload["dashboard_ascii"] = render_client_dashboard(self)
        return payload

    def save_state(self) -> None:
        """Atomically persist the endpoint runtime state to state_path."""
        if self.state_path is None:
            return
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            snap = self.export_state_dict(include_dashboard=False)
            tmp_path = self.state_path.with_suffix(self.state_path.suffix + ".tmp")
            tmp_path.write_text(json.dumps(snap, indent=2) + "\n", encoding="utf-8")
            os.replace(tmp_path, self.state_path)
        except Exception:
            pass

    def load_state(self) -> None:
        """Restore persisted BB84 history, inbox/outbox messages, and peer table from state_path."""
        if self.state_path is None or not self.state_path.exists():
            return
        try:
            raw = json.loads(self.state_path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                return
            with self._agent_lock:
                for p_dict in raw.get("peers", []):
                    if isinstance(p_dict, dict):
                        try:
                            self._ingest_peer_dict(p_dict)
                        except Exception:
                            pass
                for d_dict in raw.get("directives", []):
                    if isinstance(d_dict, dict):
                        try:
                            directive = RouteDirective.from_dict(d_dict)
                            self.active_directives[directive.target_node] = directive
                            self.wg_daemon.apply_route_directive(directive)
                        except Exception:
                            pass
                loaded_bb84: list[BB84SessionResult] = []
                for s_dict in raw.get("bb84_history", []):
                    if isinstance(s_dict, dict):
                        try:
                            sess = BB84SessionResult.from_summary_dict(s_dict)
                            loaded_bb84.append(sess)
                            self.last_bb84_results[sess.peer_node] = sess
                            if not sess.aborted and sess.epoch > self._peer_epoch.get(sess.peer_node, 0):
                                self._peer_epoch[sess.peer_node] = sess.epoch
                        except Exception:
                            pass
                if loaded_bb84:
                    self.bb84_history = loaded_bb84[-128:]
            with self.wg_daemon._lock:
                existing_in_ids = {m.message_id for m in self.wg_daemon._inbox_messages}
                for m_dict in raw.get("inbox", []):
                    if isinstance(m_dict, dict):
                        try:
                            msg = P2PDataMessage.from_dict(m_dict)
                            if msg.message_id not in existing_in_ids:
                                self.wg_daemon._inbox_messages.append(msg)
                                existing_in_ids.add(msg.message_id)
                        except Exception:
                            pass
                existing_out_ids = {m.message_id for m in self.wg_daemon._outbox_messages}
                for m_dict in raw.get("outbox", []):
                    if isinstance(m_dict, dict):
                        try:
                            msg = P2PDataMessage.from_dict(m_dict)
                            if msg.message_id not in existing_out_ids:
                                self.wg_daemon._outbox_messages.append(msg)
                                existing_out_ids.add(msg.message_id)
                        except Exception:
                            pass
        except Exception:
            pass

    def update_runtime_config(
        self,
        controller_url: str | None = None,
        node_id: str | None = None,
        overlay_ip: str | None = None,
        underlay_host: str | None = None,
        join_token: str | None = None,
    ) -> dict[str, Any]:
        """Dynamically update endpoint configuration in memory, persist to endpoint.json, and re-register with Controller."""
        with self._agent_lock:
            if controller_url and controller_url.strip():
                norm_url = controller_url.strip()
                if not norm_url.startswith(("http://", "https://")):
                    norm_url = f"http://{norm_url}"
                self.controller_url = norm_url.rstrip("/")
                self.exporter = TelemetryExporter(controller_url=self.controller_url)
            if node_id and node_id.strip():
                self.node_id = node_id.strip()
                self.wg_daemon.node_id = self.node_id
                self.bb84_engine.node_id = self.node_id
            if overlay_ip and overlay_ip.strip():
                self.overlay_ip = overlay_ip.strip()
                self.wg_daemon.overlay_ip = self.overlay_ip
            if underlay_host is not None and underlay_host.strip():
                self.underlay_host = _detect_underlay_host(self.controller_url, underlay_host.strip())
            else:
                self.underlay_host = _detect_underlay_host(self.controller_url, None)
            self.wg_daemon.bind_host = self.underlay_host

        enrolled = False
        registered = False
        sync_error: str | None = None
        if join_token and join_token.strip():
            try:
                enroll_resp = self.exporter.enroll_node(
                    join_token=join_token.strip(),
                    node_id=self.node_id,
                    underlay_host=self.underlay_host,
                    wg_port=self.wg_port,
                    qkd_port=self.qkd_port,
                    wg_public_key=self.wg_daemon.public_key_b64,
                    overlay_ip=overlay_ip.strip() if (overlay_ip and overlay_ip.strip()) else None,
                )
                self.overlay_ip = str(enroll_resp.get("allocated_overlay_ip", self.overlay_ip))
                self.wg_daemon.overlay_ip = self.overlay_ip
                secret_hex = str(enroll_resp.get("cluster_hmac_secret_hex", ""))
                if secret_hex:
                    self.auth_secret = bytes.fromhex(secret_hex)
                    self.bb84_engine.auth_secret = self.auth_secret
                self.auth_token_id = str(enroll_resp.get("auth_token_id", self.auth_token_id))
                node_info = enroll_resp.get("node")
                if isinstance(node_info, dict) and node_info.get("underlay_host"):
                    self.underlay_host = str(node_info["underlay_host"])
                enrolled = True
            except Exception as exc:
                sync_error = str(exc)

        try:
            self.register_with_controller()
            self.sync_topology()
            registered = True
            sync_error = None
        except Exception as exc:
            if sync_error is None:
                sync_error = str(exc)

        if self.config_path is not None:
            try:
                existing_cfg: dict[str, Any] = {}
                if self.config_path.is_file():
                    existing_cfg = json.loads(self.config_path.read_text(encoding="utf-8"))
                existing_cfg.update(
                    {
                        "node_id": self.node_id,
                        "overlay_ip": self.overlay_ip,
                        "underlay_host": self.underlay_host,
                        "controller_url": self.controller_url,
                        "wg_port": self.wg_port,
                        "qkd_port": self.qkd_port,
                        "wg_private_key": self.wg_daemon.private_key_b64,
                        "wg_public_key": self.wg_daemon.public_key_b64,
                        "cluster_hmac_secret_hex": self.auth_secret.hex(),
                        "classical_hmac_secret_hex": self.auth_secret.hex(),
                        "auth_token_id": self.auth_token_id,
                        "updated_at": time.time(),
                    }
                )
                self.config_path.parent.mkdir(parents=True, exist_ok=True)
                self.config_path.write_text(json.dumps(existing_cfg, indent=2) + "\n", encoding="utf-8")
            except Exception:
                pass

        self.save_state()
        return {
            "status": "updated",
            "node_id": self.node_id,
            "overlay_ip": self.overlay_ip,
            "underlay_host": self.underlay_host,
            "controller_url": self.controller_url,
            "wg_port": self.wg_port,
            "qkd_port": self.qkd_port,
            "enrolled": enrolled,
            "registered_with_controller": registered,
            "sync_error": sync_error,
            "config_path": str(self.config_path) if self.config_path else None,
        }

    def _make_local_control_handler(self) -> type[BaseHTTPRequestHandler]:
        agent = self

        class _LocalControlHandler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:
                return

            def _send_json(self, status_code: int, payload: dict[str, Any]) -> None:
                body = json.dumps(payload).encode("utf-8")
                self.send_response(status_code)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _read_json(self) -> dict[str, Any]:
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0:
                    return {}
                raw = self.rfile.read(length)
                return json.loads(raw.decode("utf-8"))

            def do_GET(self) -> None:
                parsed_url = parse.urlparse(self.path)
                path = parsed_url.path.rstrip("/")
                if path == "/local/v1/status":
                    if "fast=1" not in parsed_url.query:
                        try:
                            agent.sync_topology()
                        except Exception:
                            pass
                        agent.save_state()
                    self._send_json(HTTPStatus.OK, agent.export_state_dict(include_dashboard=True))
                    return
                self._send_json(HTTPStatus.NOT_FOUND, {"error": f"Unknown local endpoint: {path}"})

            def do_POST(self) -> None:
                path = parse.urlparse(self.path).path.rstrip("/")
                try:
                    data = self._read_json()
                except Exception as exc:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"Invalid JSON: {exc}"})
                    return

                if path == "/local/v1/stop":
                    self._send_json(HTTPStatus.OK, {"status": "stopping", "node_id": agent.node_id})
                    agent.stop_event.set()
                    threading.Thread(target=agent.close, daemon=True).start()
                    return

                if path == "/local/v1/rekey":
                    target_node = str(data.get("target_node", "")).strip()
                    if not target_node:
                        self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Missing target_node"})
                        return
                    try:
                        res = agent.run_key_rotation_and_telemetry_cycle(target_node)
                        self._send_json(HTTPStatus.OK, res)
                    except Exception as exc:
                        self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return

                if path == "/local/v1/send":
                    target_node = str(data.get("target_node", "")).strip()
                    text = data.get("text")
                    file_path = data.get("file_path")
                    if not target_node:
                        self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Missing target_node"})
                        return
                    try:
                        if file_path:
                            res = agent.send_p2p_file(target_node, str(file_path))
                        else:
                            res = agent.send_p2p_text(target_node, str(text or ""))
                        self._send_json(HTTPStatus.OK, res)
                    except Exception as exc:
                        self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return

                if path == "/local/v1/savefile":
                    msg_key = data.get("message_id_or_index", 1)
                    dest_dir = str(data.get("dest_dir", "."))
                    try:
                        saved_path = agent.save_inbox_file(msg_key, dest_dir)
                        self._send_json(
                            HTTPStatus.OK,
                            {"status": "saved", "saved_path": str(saved_path)},
                        )
                    except Exception as exc:
                        self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return

                if path == "/local/v1/config":
                    try:
                        res = agent.update_runtime_config(
                            controller_url=data.get("controller_url"),
                            node_id=data.get("node_id"),
                            overlay_ip=data.get("overlay_ip"),
                            underlay_host=data.get("underlay_host"),
                            join_token=data.get("join_token"),
                        )
                        self._send_json(HTTPStatus.OK, res)
                    except Exception as exc:
                        self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return

                self._send_json(HTTPStatus.NOT_FOUND, {"error": f"Unknown local endpoint: {path}"})

        return _LocalControlHandler

    def probe_and_report_peer(self, target_node: str) -> dict[str, Any] | None:
        """Probe a peer via real UDP packets and report updated LinkTelemetry to the Central Controller."""
        if target_node == self.node_id or target_node not in self.peer_registry:
            return None
        probe_stats = self.wg_daemon.probe_peer_link(target_node, count=2, timeout=0.4)
        peer_state = self.wg_daemon.get_peer_state(target_node)
        handshake_age_s = (
            round(max(0.0, time.time() - peer_state.last_psk_rotated_at), 2)
            if (peer_state and peer_state.last_psk_rotated_at > 0)
            else 0.0
        )
        if not probe_stats["reachable"]:
            telemetry = LinkTelemetry(
                source_node=self.node_id,
                target_node=target_node,
                timestamp=time.time(),
                latency_ms=0.0,
                jitter_ms=0.0,
                packet_loss_pct=100.0,
                throughput_mbps=0.0,
                qber=0.0,
                qber_delta=0.0,
                key_rate_bps=0.0,
                psk_epoch=self._peer_epoch.get(target_node, 0),
                handshake_age_s=handshake_age_s,
                qkd_abort_count=self._abort_counts.get(target_node, 0) + 1,
            )
        else:
            with self._agent_lock:
                last_bb84 = self.last_bb84_results.get(target_node)
            qber_val = float(last_bb84.measured_qber) if (last_bb84 and not last_bb84.aborted) else 0.0
            key_rate_val = float(last_bb84.key_rate_bps) if (last_bb84 and not last_bb84.aborted) else 0.0
            telemetry = LinkTelemetry(
                source_node=self.node_id,
                target_node=target_node,
                timestamp=time.time(),
                latency_ms=float(probe_stats["latency_ms"]),
                jitter_ms=float(probe_stats["jitter_ms"]),
                packet_loss_pct=float(probe_stats["packet_loss_pct"]),
                throughput_mbps=float(probe_stats["throughput_mbps"]),
                qber=qber_val,
                qber_delta=0.0,
                key_rate_bps=key_rate_val,
                psk_epoch=self._peer_epoch.get(target_node, 0),
                handshake_age_s=handshake_age_s,
                qkd_abort_count=self._abort_counts.get(target_node, 0),
            )
        controller_resp = self.exporter.send_telemetry(telemetry)
        directive = RouteDirective.from_dict(controller_resp["directive"])
        self.active_directives[target_node] = directive
        self.wg_daemon.apply_route_directive(directive)
        return controller_resp

    def _heartbeat_loop(self, interval: float) -> None:
        wait_s = max(0.5, float(interval))
        while not self.stop_event.wait(timeout=wait_s):
            try:
                detected_lan = _detect_underlay_host(self.controller_url, None)
                if detected_lan and detected_lan not in ("127.0.0.1", "0.0.0.0", "localhost", "::1"):
                    with self._agent_lock:
                        if self.underlay_host_mode == "auto" and self.underlay_host == self.lan_host and detected_lan != self.lan_host:
                            self.underlay_host = detected_lan
                        self.lan_host = detected_lan
                self.register_with_controller()
                self.sync_topology()
            except Exception:
                pass
            try:
                self.wg_daemon.send_keepalive()
            except Exception:
                pass
            self.save_state()

    def _telemetry_probe_loop(self, interval: float) -> None:
        wait_s = max(1.0, float(interval))
        while not self.stop_event.wait(timeout=wait_s):
            for peer_reg in list(self.peer_registry.values()):
                if self.stop_event.is_set():
                    break
                if peer_reg.node_id == self.node_id:
                    continue
                try:
                    now_ts = time.time()
                    last_rk = self._last_rekey_ts.get(peer_reg.node_id, 0.0)
                    if peer_reg.status != "OFFLINE" and (
                        self._peer_epoch.get(peer_reg.node_id, 0) == 0 or (now_ts - last_rk) >= 10.0
                    ):
                        self.run_key_rotation_and_telemetry_cycle(peer_reg.node_id)
                    else:
                        self.probe_and_report_peer(peer_reg.node_id)
                except Exception:
                    pass
            self.save_state()

    def start_daemon_services(self, heartbeat_interval: float = 2.0) -> str:
        """Start the Local Control HTTP API on 127.0.0.1 and the background auto-heartbeat and probe threads."""
        if self._control_httpd is not None and self.control_url:
            return self.control_url

        handler_cls = self._make_local_control_handler()

        class _ReusableControlHTTPServer(ThreadingHTTPServer):
            allow_reuse_address = True
            daemon_threads = True

        self._control_httpd = _ReusableControlHTTPServer(("127.0.0.1", 0), handler_cls)
        bound_port = int(self._control_httpd.server_address[1])
        self.control_url = f"http://127.0.0.1:{bound_port}"
        self._control_thread = threading.Thread(
            target=self._control_httpd.serve_forever,
            name=f"qkd-client-control-{self.node_id}",
            daemon=True,
        )
        self._control_thread.start()

        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop,
            args=(heartbeat_interval,),
            name=f"qkd-client-heartbeat-{self.node_id}",
            daemon=True,
        )
        self._heartbeat_thread.start()

        self._probe_thread = threading.Thread(
            target=self._telemetry_probe_loop,
            args=(max(2.0, float(heartbeat_interval)),),
            name=f"qkd-client-probe-{self.node_id}",
            daemon=True,
        )
        self._probe_thread.start()
        self.save_state()
        return self.control_url
    def close(self, notify_controller: bool = True) -> None:
        """Stop Local Control API, heartbeat thread, BB84 responder, and WireGuard UDP sockets."""
        self.stop_event.set()
        self.control_url = None
        if notify_controller:
            try:
                fast_exp = TelemetryExporter(controller_url=self.controller_url, timeout=0.8)
                fast_exp.disconnect_node(self.node_id)
            except Exception:
                pass
        self.save_state()
        if self._control_httpd is not None:
            try:
                self._control_httpd.shutdown()
                self._control_httpd.server_close()
            except Exception:
                pass
            self._control_httpd = None
        self.bb84_engine.stop_tcp_responder()
        self.wg_daemon.close()

def _format_ascii_table(headers: list[str], rows: list[list[str]]) -> list[str]:
    if not rows:
        rows = [["(none)"] + ["-" for _ in headers[1:]]]
    widths = [len(h) for h in headers]
    for row in rows:
        for idx, cell in enumerate(row):
            if idx < len(widths):
                widths[idx] = max(widths[idx], len(str(cell)))

    sep = "+-" + "-+-".join("-" * w for w in widths) + "-+"
    header_line = "| " + " | ".join(str(h).ljust(widths[i]) for i, h in enumerate(headers)) + " |"
    lines = [sep, header_line, sep]
    for row in rows:
        padded = [str(row[i] if i < len(row) else "").ljust(widths[i]) for i in range(len(headers))]
        lines.append("| " + " | ".join(padded) + " |")
    lines.append(sep)
    return lines


def render_client_dashboard(agent: SDWANEndpointAgent) -> str:
    """Render a 4-panel ASCII CLI Dashboard for the SD-WAN Endpoint Client."""
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    now_ts = time.time()
    peers = agent.wg_daemon.list_peers()
    inbox_msgs = agent.get_received_messages(clear=False)
    outbox_msgs = agent.get_sent_messages(clear=False)

    with agent._agent_lock:
        bb84_sessions = list(agent.bb84_history)
        if not bb84_sessions and agent.last_bb84_results:
            bb84_sessions = list(agent.last_bb84_results.values())

    online_peers_count = sum(1 for r in agent.peer_registry.values() if r.status != "OFFLINE")
    total_peers_count = len(agent.peer_registry)

    lines: list[str] = []
    banner = "=" * 124
    lines.append(banner)
    lines.append(" QKD-SDWAN ENDPOINT CLIENT — INTERACTIVE CLI DASHBOARD (BB84 QKD + WIREGUARD P2P OVERLAY) ")
    lines.append(banner)
    lines.append(
        f" Node ID          : {agent.node_id:<34} | Overlay IP         : {agent.overlay_ip}"
    )
    lines.append(
        f" Controller URL   : {agent.controller_url:<34} | Timestamp          : {now_str}"
    )
    lines.append(
        f" WG UDP Endpoint  : {f'{agent.underlay_host}:{agent.wg_port}':<34} | QKD TCP Endpoint   : {agent.underlay_host}:{agent.qkd_port}"
    )
    lines.append(
        f" WG Backend Mode  : {agent.wg_daemon.backend_mode:<34} | Online / Total Peer: {online_peers_count} / {total_peers_count}"
    )
    lines.append(
        f" WG Public Key    : {agent.wg_daemon.public_key_b64:<34} | Relay Forwarded    : {agent.wg_daemon.relay_forwarded_packets} pkts"
    )
    lines.append("-" * 124)

    # Panel 1: WireGuard Tunnel Peers & BB84 Quantum PSK State
    lines.append("[1] P2P WIREGUARD TUNNEL PEERS & BB84 QUANTUM PSK STATE")
    peer_rows: list[list[str]] = []
    for pid, pstate in sorted(peers.items()):
        preg = agent.peer_registry.get(pid)
        p_status = preg.status if preg else "ONLINE"
        last_seen_ts = (preg.last_seen if (preg and preg.last_seen > 0) else (preg.registered_at if preg else 0.0))
        seen_age_str = f"{max(0.0, now_ts - last_seen_ts):.1f}s" if last_seen_ts > 10.0 else "live"
        status_cell = f"{p_status} ({seen_age_str})" if p_status == "ONLINE" else "OFFLINE"
        rot_str = (
            f"{max(0.0, now_ts - pstate.last_psk_rotated_at):.1f}s ago"
            if pstate.last_psk_rotated_at > 10.0
            else ("-" if pstate.psk_epoch == 0 else "active")
        )
        fp_str = pstate.current_psk_fingerprint or "(unkeyed)"
        if p_status == "OFFLINE" and pstate.current_psk_fingerprint:
            fp_str = f"{fp_str} (STALE-OFFLINE)"
        peer_rows.append(
            [
                pid,
                status_cell,
                pstate.peer_overlay_ip,
                pstate.underlay_endpoint,
                pstate.route_mode.value,
                pstate.via_relay_node or "-",
                str(pstate.psk_epoch),
                fp_str,
                rot_str,
                f"{pstate.tx_bytes}B / {pstate.rx_bytes}B",
            ]
        )
    lines.extend(
        _format_ascii_table(
            [
                "Peer Node",
                "Peer Status",
                "Overlay IP",
                "Underlay Endpoint",
                "RouteMode",
                "Via Relay",
                "PSK Epoch",
                "PSK Fingerprint",
                "Last Rotated",
                "TX / RX Bytes",
            ],
            peer_rows,
        )
    )
    lines.append("")

    # Panel 2: Recent BB84 Quantum Key Distribution Sessions
    lines.append("[2] RECENT BB84 QUANTUM KEY DISTRIBUTION SESSIONS")
    bb84_rows: list[list[str]] = []
    for sess in bb84_sessions[-10:]:
        photons_str = f"{sess.raw_Exported_qubits}/{sess.transmitted_qubits}/{sess.sifted_key_bits}"
        qber_str = f"{sess.measured_qber * 100:.2f}%"
        krate_str = f"{sess.key_rate_bps:.0f} bps"
        dur_str = f"{sess.duration_ms:.1f}ms"
        preg = agent.peer_registry.get(sess.peer_node)
        peer_live_str = preg.status if preg else "ONLINE"
        if sess.aborted:
            status_str = f"ABORTED ({sess.abort_reason or 'QBER>11%'})"
        else:
            status_str = f"OK (fp:{sess.psk_fingerprint_sha256 or '-'})"
        if len(status_str) > 36:
            status_str = status_str[:33] + "..."
        bb84_rows.append(
            [
                sess.session_id,
                sess.peer_node,
                peer_live_str,
                str(sess.epoch),
                photons_str,
                qber_str,
                str(sess.corrected_errors),
                krate_str,
                dur_str,
                status_str,
            ]
        )
    lines.extend(
        _format_ascii_table(
            [
                "Session ID",
                "Peer Node",
                "Peer Live",
                "Epoch",
                "Photons (Raw/Det/Sift)",
                "QBER",
                "Corrected",
                "Key Rate",
                "Duration",
                "Status",
            ],
            bb84_rows,
        )
    )
    lines.append("")

    # Panel 3: Active Controller ML Routing Directives
    lines.append("[3] ACTIVE CONTROLLER ML ROUTING DIRECTIVES")
    dir_rows: list[list[str]] = []
    for target_id, d in sorted(agent.active_directives.items()):
        reason_str = d.reason
        if len(reason_str) > 40:
            reason_str = reason_str[:37] + "..."
        upd_str = f"{max(0.0, now_ts - d.updated_at):.1f}s ago" if d.updated_at > 10.0 else "live"
        dir_rows.append(
            [
                f"{d.source_node} -> {target_id}",
                d.route_mode.value,
                d.next_hop_node or "-",
                d.next_hop_endpoint or "-",
                f"{d.anomaly_score:.3f}",
                d.link_status.value,
                "YES" if d.force_rekey else "NO",
                upd_str,
                reason_str,
            ]
        )
    lines.extend(
        _format_ascii_table(
            [
                "Source -> Target",
                "RouteMode",
                "Next Hop",
                "Next Hop Endpoint",
                "ML Score",
                "LinkStatus",
                "Force Rekey",
                "Updated",
                "Reason",
            ],
            dir_rows,
        )
    )
    lines.append("")

    # Panel 4: Encrypted P2P Application Inbox & Outbox
    lines.append("[4] ENCRYPTED P2P APPLICATION INBOX & OUTBOX (MESSAGES & FILES)")
    msg_rows: list[list[str]] = []
    combined_msgs: list[tuple[str, P2PDataMessage]] = [
        *[("IN", m) for m in inbox_msgs],
        *[("OUT", m) for m in outbox_msgs],
    ]
    combined_msgs.sort(key=lambda item: item[1].timestamp)
    for direction, m in combined_msgs[-12:]:
        peer_col = m.source_node if direction == "IN" else m.target_node
        sha_short = f"{m.payload_sha256[:12]}..." if m.payload_sha256 else "-"
        try:
            raw_len = len(m.decode_payload(verify=False))
        except Exception:
            raw_len = 0
        if m.content_type == "file":
            summary = f"FILE '{m.filename or 'unnamed'}' ({raw_len} bytes)"
        else:
            txt = m.decode_text(verify=False)
            if len(txt) > 36:
                txt = txt[:33] + "..."
            summary = f"TEXT: {txt}"
        msg_rows.append(
            [
                direction,
                m.message_id,
                peer_col,
                m.content_type.upper(),
                m.route_mode,
                m.via_relay_node or "-",
                str(m.psk_epoch),
                sha_short,
                summary,
            ]
        )
    lines.extend(
        _format_ascii_table(
            [
                "Dir",
                "Message ID",
                "Peer Node",
                "Type",
                "RouteMode",
                "Via Relay",
                "PSK Ep",
                "SHA-256",
                "Content / Filename & Size",
            ],
            msg_rows,
        )
    )
    lines.append(banner)
    return "\n".join(lines)


def run_client_dashboard_interactive(agent: SDWANEndpointAgent) -> int:
    """Run the interactive 4-panel ASCII CLI Dashboard for an SD-WAN Endpoint Client."""
    while True:
        try:
            agent.register_with_controller()
            agent.sync_topology()
        except Exception as exc:
            print(f" [!] Warning: Cannot reach Controller at {agent.controller_url}: {exc}")
        print("\n" + render_client_dashboard(agent))
        print(
            " Actions: [r] Refresh & Sync | [c] Change Controller URL | [k] Rekey BB84 Peer | "
            "[m] Send P2P Text | [f] Send P2P File | [s] Save Inbox File | [q] Quit"
        )
        try:
            choice = input(f" {agent.node_id} dashboard> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if choice in ("q", "quit", "exit"):
            break
        if choice in ("r", "refresh", ""):
            continue
        if choice == "c":
            new_url = input(f"   New Controller URL [{agent.controller_url}]: ").strip()
            if new_url:
                if not new_url.startswith(("http://", "https://")):
                    new_url = f"http://{new_url}"
                agent.controller_url = new_url.rstrip("/")
                agent.exporter = TelemetryExporter(controller_url=agent.controller_url)
                agent.underlay_host = _detect_underlay_host(agent.controller_url, None)
                agent.wg_daemon.bind_host = agent.underlay_host
            continue
        if choice == "k":
            peer_id = input("   Target peer node ID: ").strip()
            if peer_id:
                try:
                    res = agent.run_key_rotation_and_telemetry_cycle(peer_id)
                    bb84 = res["bb84"]
                    print(
                        f"   [+] BB84 Session with {peer_id}: QBER={bb84['measured_qber']*100:.2f}%, "
                        f"PSK Injected={res['psk_injected']}, fp={bb84['psk_fingerprint_sha256']}"
                    )
                except Exception as exc:
                    print(f"   [!] BB84 rekey error: {exc}")
        elif choice == "m":
            peer_id = input("   Target peer node ID: ").strip()
            text = input("   Message text: ").strip()
            if peer_id and text:
                try:
                    res = agent.send_p2p_text(peer_id, text)
                    deliv = res["delivery"]
                    print(
                        f"   [+] Sent {res['message']['message_id']} to {peer_id} via {deliv['route_mode']} "
                        f"(PSK Epoch {deliv['psk_epoch']}, RTT {deliv['rtt_ms']:.2f} ms)"
                    )
                except Exception as exc:
                    print(f"   [!] Send text error: {exc}")
        elif choice == "f":
            peer_id = input("   Target peer node ID: ").strip()
            fpath = input("   Local file path: ").strip()
            if peer_id and fpath:
                try:
                    res = agent.send_p2p_file(peer_id, fpath)
                    deliv = res["delivery"]
                    print(
                        f"   [+] Sent file '{res['message']['filename']}' to {peer_id} via {deliv['route_mode']} "
                        f"(PSK Epoch {deliv['psk_epoch']}, RTT {deliv['rtt_ms']:.2f} ms)"
                    )
                except Exception as exc:
                    print(f"   [!] Send file error: {exc}")
        elif choice == "s":
            msg_key = input("   Inbox message ID or index (1..N): ").strip()
            dest_dir = input("   Destination directory (default '.'): ").strip() or "."
            if msg_key:
                try:
                    saved_path = agent.save_inbox_file(msg_key, dest_dir)
                    print(f"   [+] Saved verified inbox file to: {saved_path}")
                except Exception as exc:
                    print(f"   [!] Save inbox file error: {exc}")
    return 0


def run_client_dashboard_via_daemon(config_path: Path) -> int:
    """Run the interactive 4-panel ASCII CLI Dashboard connected to a running local Client daemon."""
    while True:
        status = _request_local_daemon(config_path, "GET", "/local/v1/status", timeout=5.0)
        if status is None:
            print(" [!] Local client daemon is no longer running.")
            break
        node_id = str(status.get("node_id", "edge-client"))
        ctrl_url = str(status.get("controller_url", "http://127.0.0.1:8080"))
        print("\n" + str(status.get("dashboard_ascii", "")))
        print(
            " Actions: [r] Refresh & Sync | [c] Change Controller URL | [k] Rekey BB84 Peer | "
            "[m] Send P2P Text | [f] Send P2P File | [s] Save Inbox File | [q] Quit"
        )
        try:
            choice = input(f" {node_id} dashboard> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if choice in ("q", "quit", "exit"):
            break
        if choice in ("r", "refresh", ""):
            continue
        if choice == "c":
            new_url = input(f"   New Controller URL [{ctrl_url}]: ").strip()
            if new_url:
                try:
                    res = _request_local_daemon(
                        config_path,
                        "POST",
                        "/local/v1/config",
                        {"controller_url": new_url},
                        timeout=10.0,
                    )
                    if res:
                        print(f"   [+] Updated Controller URL to {res.get('controller_url')} (registered={res.get('registered_with_controller')})")
                except Exception as exc:
                    print(f"   [!] Config update error: {exc}")
        elif choice == "k":
            peer_id = input("   Target peer node ID: ").strip()
            if peer_id:
                try:
                    res = _request_local_daemon(
                        config_path,
                        "POST",
                        "/local/v1/rekey",
                        {"target_node": peer_id},
                        timeout=15.0,
                    )
                    if res:
                        bb84 = res["bb84"]
                        print(
                            f"   [+] BB84 Session with {peer_id}: QBER={bb84['measured_qber']*100:.2f}%, "
                            f"PSK Injected={res['psk_injected']}, fp={bb84['psk_fingerprint_sha256']}"
                        )
                except Exception as exc:
                    print(f"   [!] BB84 rekey error: {exc}")
        elif choice == "m":
            peer_id = input("   Target peer node ID: ").strip()
            text = input("   Message text: ").strip()
            if peer_id and text:
                try:
                    res = _request_local_daemon(
                        config_path,
                        "POST",
                        "/local/v1/send",
                        {"target_node": peer_id, "text": text},
                        timeout=15.0,
                    )
                    if res:
                        deliv = res["delivery"]
                        print(
                            f"   [+] Sent {res['message']['message_id']} to {peer_id} via {deliv['route_mode']} "
                            f"(PSK Epoch {deliv['psk_epoch']}, RTT {deliv['rtt_ms']:.2f} ms)"
                        )
                except Exception as exc:
                    print(f"   [!] Send text error: {exc}")
        elif choice == "f":
            peer_id = input("   Target peer node ID: ").strip()
            fpath = input("   Local file path: ").strip()
            if peer_id and fpath:
                try:
                    res = _request_local_daemon(
                        config_path,
                        "POST",
                        "/local/v1/send",
                        {"target_node": peer_id, "file_path": str(Path(fpath).resolve())},
                        timeout=20.0,
                    )
                    if res:
                        deliv = res["delivery"]
                        print(
                            f"   [+] Sent file '{res['message']['filename']}' to {peer_id} via {deliv['route_mode']} "
                            f"(PSK Epoch {deliv['psk_epoch']}, RTT {deliv['rtt_ms']:.2f} ms)"
                        )
                except Exception as exc:
                    print(f"   [!] Send file error: {exc}")
        elif choice == "s":
            msg_key = input("   Inbox message ID or index (1..N): ").strip()
            dest_dir = input("   Destination directory (default '.'): ").strip() or "."
            if msg_key:
                try:
                    res = _request_local_daemon(
                        config_path,
                        "POST",
                        "/local/v1/savefile",
                        {"message_id_or_index": msg_key, "dest_dir": str(Path(dest_dir).resolve())},
                        timeout=10.0,
                    )
                    if res:
                        print(f"   [+] Saved verified inbox file to: {res.get('saved_path')}")
                except Exception as exc:
                    print(f"   [!] Save inbox file error: {exc}")
    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="qkd-sdwan-client",
        description="Lightweight Distributed P2P SD-WAN Endpoint Client with BB84 QKD, Join-Token Auto-Enrollment, and P2P Data Transfer",
    )
    parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to endpoint JSON configuration file (default: /etc/qkd-sdwan/endpoint.json)",
    )
    parser.add_argument("--node-id", type=str, help="Override endpoint node ID")
    parser.add_argument("--overlay-ip", type=str, help="Override WireGuard overlay IPv4 address")
    parser.add_argument("--controller-url", type=str, help="Override Central Controller base URL")
    parser.add_argument("--underlay-host", type=str, default=None, help="Override underlay IP/hostname")
    parser.add_argument("--join-token", type=str, help="Optional Join Token for automatic controller enrollment")
    parser.add_argument("--wg-port", type=int, default=None, help="WireGuard UDP listen port")
    parser.add_argument("--qkd-port", type=int, default=None, help="BB84 QKD TCP listen port")
    parser.add_argument(
        "--prefer-kernel-wg",
        action="store_true",
        help="Prefer kernel `wg set` binary when running as root with wireguard-tools installed",
    )
    parser.add_argument(
        "-d",
        "--daemon",
        action="store_true",
        help="Run the Client P2P agent as a persistent background daemon",
    )
    parser.add_argument(
        "--dashboard",
        action="store_true",
        help="Launch the 4-panel interactive Client CLI Dashboard",
    )
    parser.add_argument(
        "--check-config",
        action="store_true",
        help="Validate configuration file and print endpoint identity without connecting",
    )

    subparsers = parser.add_subparsers(dest="subcommand")

    # subcommand: up
    up_p = subparsers.add_parser("up", help="Connect to Central Controller, auto-enroll if needed, and start/update background Client daemon")
    up_p.add_argument("target_controller", nargs="?", default=None, help="Optional Controller IP or URL (e.g. 192.168.1.2)")
    up_p.add_argument("--config", type=str, default=argparse.SUPPRESS, help="Path to endpoint.json")
    up_p.add_argument("--controller-url", type=str, default=argparse.SUPPRESS, help="Override Controller URL")
    up_p.add_argument("--node-id", type=str, default=argparse.SUPPRESS, help="Override node ID")
    up_p.add_argument("--overlay-ip", type=str, default=argparse.SUPPRESS, help="Override overlay IP")
    up_p.add_argument("--underlay-host", type=str, default=argparse.SUPPRESS, help="Override underlay IP/hostname")
    up_p.add_argument("--join-token", type=str, default=argparse.SUPPRESS, help="Optional Join Token (default: auto)")
    up_p.add_argument("--wg-port", type=int, default=argparse.SUPPRESS, help="WireGuard UDP port")
    up_p.add_argument("--qkd-port", type=int, default=argparse.SUPPRESS, help="BB84 QKD TCP port")
    up_p.add_argument("--heartbeat-interval", type=float, default=2.0, help="Heartbeat & roaming interval in seconds (default: 2.0)")

    # subcommand: serve
    serve_p = subparsers.add_parser("serve", help="Run the persistent Client P2P daemon (WireGuard UDP + BB84 QKD TCP + Local Control API)")
    serve_p.add_argument("--config", type=str, default=argparse.SUPPRESS, help="Path to endpoint.json")
    serve_p.add_argument("--controller-url", type=str, default=argparse.SUPPRESS, help="Override Controller URL")
    serve_p.add_argument("--node-id", type=str, default=argparse.SUPPRESS, help="Override node ID")
    serve_p.add_argument("--overlay-ip", type=str, default=argparse.SUPPRESS, help="Override overlay IP")
    serve_p.add_argument("--underlay-host", type=str, default=argparse.SUPPRESS, help="Override underlay IP/hostname")
    serve_p.add_argument("--join-token", type=str, default=argparse.SUPPRESS, help="Optional Join Token to auto-enroll on startup")
    serve_p.add_argument("--wg-port", type=int, default=argparse.SUPPRESS, help="WireGuard UDP port")
    serve_p.add_argument("--qkd-port", type=int, default=argparse.SUPPRESS, help="BB84 QKD TCP port")
    serve_p.add_argument("-d", "--daemon", action="store_true", default=argparse.SUPPRESS, help="Run in background as a daemon process")
    serve_p.add_argument("--heartbeat-interval", type=float, default=2.0, help="Heartbeat & keepalive interval in seconds (default: 2.0)")

    # subcommand: stop
    stop_p = subparsers.add_parser("stop", help="Stop a running background Client P2P daemon")
    stop_p.add_argument("--config", type=str, default=argparse.SUPPRESS, help="Path to endpoint.json")

    # subcommand: down (alias for stop)
    down_p = subparsers.add_parser("down", help="Stop a running background Client P2P daemon")
    down_p.add_argument("--config", type=str, default=argparse.SUPPRESS, help="Path to endpoint.json")

    # subcommand: peers
    peers_p = subparsers.add_parser("peers", help="List all registered SD-WAN peers, endpoints, route modes, and BB84 PSK status")
    peers_p.add_argument("--config", type=str, default=argparse.SUPPRESS, help="Path to endpoint.json")
    peers_p.add_argument("--json", action="store_true", help="Output raw JSON peer list")

    # subcommand: config
    cfg_p = subparsers.add_parser("config", help="View or dynamically update Client configuration (e.g. --controller-url) and re-sync")
    cfg_p.add_argument("--config", type=str, default=argparse.SUPPRESS, help="Path to endpoint.json")
    cfg_p.add_argument("--controller-url", type=str, default=None, help="New Central Controller base URL")
    cfg_p.add_argument("--node-id", type=str, default=None, help="New endpoint node ID")
    cfg_p.add_argument("--overlay-ip", type=str, default=None, help="New overlay IPv4 address")
    cfg_p.add_argument("--underlay-host", type=str, default=None, help="New underlay IP/hostname")
    cfg_p.add_argument("--join-token", type=str, default=None, help="Join Token to enroll with the new Controller")

    # subcommand: rekey
    rekey_p = subparsers.add_parser("rekey", help="Negotiate a 256-bit BB84 quantum session with a peer (or all peers) and inject WireGuard PSK")
    rekey_p.add_argument("pos_target_node", nargs="?", default=None, help="Target peer node ID (omit or use --all to rekey all peers)")
    rekey_p.add_argument("--config", type=str, default=argparse.SUPPRESS, help="Path to endpoint.json")
    rekey_p.add_argument("--controller-url", type=str, default=argparse.SUPPRESS, help="Override Controller URL")
    rekey_p.add_argument("--to", default=None, dest="target_node", help="Target peer node ID")
    rekey_p.add_argument("--all", action="store_true", help="Negotiate BB84 key rotation with all registered peers")

    # subcommand: inbox
    inbox_p = subparsers.add_parser("inbox", help="View received P2P messages/files or export a verified file from the inbox")
    inbox_p.add_argument("--config", type=str, default=argparse.SUPPRESS, help="Path to endpoint.json")
    inbox_p.add_argument("--save", default=None, help="Message ID or 1-based index to save/export to disk")
    inbox_p.add_argument("--dir", type=Path, default=Path("."), help="Destination directory when using --save (default: .)")
    inbox_p.add_argument("--json", action="store_true", help="Output raw JSON inbox & outbox list")

    # subcommand: save
    save_p = subparsers.add_parser("save", help="Export a verified file from the P2P inbox to disk")
    save_p.add_argument("message_id_or_index", help="Message ID or 1-based inbox index")
    save_p.add_argument("dest_dir", nargs="?", type=Path, default=Path("."), help="Destination directory (default: .)")
    save_p.add_argument("--config", type=str, default=argparse.SUPPRESS, help="Path to endpoint.json")

    # subcommand: init-config
    init_p = subparsers.add_parser("init-config", help="Generate endpoint.json configuration, WireGuard keypair, and automatic Join-Token enrollment")
    init_p.add_argument("--output", type=Path, required=True, help="Output path for endpoint.json")
    init_p.add_argument("--node-id", type=str, default="auto", help="Endpoint node ID (default: auto from hostname)")
    init_p.add_argument("--overlay-ip", type=str, default="10.200.0.10", help="Overlay IPv4 address (default: 10.200.0.10 / auto-allocated)")
    init_p.add_argument("--controller-url", type=str, default="http://192.168.1.2:8080", help="Central Controller base URL")
    init_p.add_argument("--join-token", nargs="?", const="", type=str, default="", help="Optional Join Token for automatic enrollment (default: auto)")
    init_p.add_argument("--wg-port", type=int, default=51820, help="WireGuard UDP listen port (default: 51820)")
    init_p.add_argument("--qkd-port", type=int, default=52820, help="BB84 QKD TCP listen port (default: 52820)")
    init_p.add_argument("--interface", type=str, default="wg-qkd0", help="WireGuard interface name (default: wg-qkd0)")
    init_p.add_argument("--backend-mode", type=str, default="USERSPACE_CRYPTO_WG", help="WireGuard backend mode")
    init_p.add_argument("--underlay-host", type=str, default="auto", help="Underlay IP/hostname reachable by peers (default: auto)")
    init_p.add_argument("--explicit-ip", action="store_true", help="Request the explicit --overlay-ip during Join-Token enrollment")

    # subcommand: enroll
    enroll_p = subparsers.add_parser("enroll", help="Enroll this client node with the Central Controller using a Join Token")
    enroll_p.add_argument("--controller-url", default="http://192.168.1.2:8080", help="Central Controller base URL")
    enroll_p.add_argument("--join-token", default="auto", help="Enrollment Join Token issued by the Controller (default: auto)")
    enroll_p.add_argument("--node-id", default="auto", help="Unique node identifier (default: auto from hostname)")
    enroll_p.add_argument("--underlay-host", default="auto", help="Underlay IP/hostname reachable by peers")
    enroll_p.add_argument("--overlay-ip", default=None, help="Optional requested overlay IP (auto-allocated if omitted)")
    enroll_p.add_argument("--wg-port", type=int, default=51820, help="Configured WireGuard UDP listen port")
    enroll_p.add_argument("--qkd-port", type=int, default=52820, help="Configured BB84 QKD TCP listen port")
    enroll_p.add_argument("--output-config", type=Path, default=None, help="Path to write enrolled endpoint.json config")

    # subcommand: send
    send_p = subparsers.add_parser("send", help="Send an encrypted P2P text message or file to another Client")
    send_p.add_argument("pos_target_node", nargs="?", default=None, help="Target peer node ID")
    send_p.add_argument("pos_text", nargs="?", default=None, help="UTF-8 text message to send")
    send_p.add_argument("--config", type=str, default=argparse.SUPPRESS, help="Path to endpoint.json")
    send_p.add_argument("--controller-url", type=str, default=argparse.SUPPRESS, help="Override Controller URL")
    send_p.add_argument("--node-id", type=str, default=argparse.SUPPRESS, help="Override source node ID")
    send_p.add_argument("--overlay-ip", type=str, default=argparse.SUPPRESS, help="Override source overlay IP")
    send_p.add_argument("--to", default=None, dest="target_node", help="Target peer node ID")
    send_p.add_argument("--text", type=str, default=None, help="UTF-8 text message to send")
    send_p.add_argument("--file", type=Path, default=None, help="Path to file to send")

    # subcommand: sendfile
    sendfile_p = subparsers.add_parser("sendfile", help="Send an encrypted file to another Client over P2P WireGuard")
    sendfile_p.add_argument("pos_target_node", nargs="?", default=None, help="Target peer node ID")
    sendfile_p.add_argument("pos_file", nargs="?", type=Path, default=None, help="Path to file to send")
    sendfile_p.add_argument("--config", type=str, default=argparse.SUPPRESS, help="Path to endpoint.json")
    sendfile_p.add_argument("--to", default=None, dest="target_node", help="Target peer node ID")
    sendfile_p.add_argument("--file", type=Path, default=None, help="Path to file to send")

    # subcommand: dashboard
    dash_p = subparsers.add_parser("dashboard", help="Display the 4-panel Client CLI Dashboard (snapshot, live watch, or interactive)")
    dash_p.add_argument("--config", type=str, default=argparse.SUPPRESS, help="Path to endpoint.json")
    dash_p.add_argument("--controller-url", type=str, default=argparse.SUPPRESS, help="Override Controller URL")
    dash_p.add_argument("--node-id", type=str, default=argparse.SUPPRESS, help="Override node ID")
    dash_p.add_argument("--overlay-ip", type=str, default=argparse.SUPPRESS, help="Override overlay IP")
    dash_p.add_argument("--join-token", type=str, default=argparse.SUPPRESS, help="Optional Join Token to auto-enroll on startup")
    dash_p.add_argument("--wg-port", type=int, default=argparse.SUPPRESS, help="WireGuard UDP port")
    dash_p.add_argument("--qkd-port", type=int, default=argparse.SUPPRESS, help="BB84 QKD TCP port")
    dash_p.add_argument("--once", action="store_true", help="Print a single 4-panel Client Dashboard snapshot and exit")
    dash_p.add_argument("--interval", type=float, default=0.0, help="Auto-refresh interval in seconds (0 = interactive menu)")

    # subcommand: console
    con_p = subparsers.add_parser("console", help="Start interactive P2P Client console for live messaging and BB84 rekeying")
    con_p.add_argument("--config", type=str, default=argparse.SUPPRESS, help="Path to endpoint.json")
    con_p.add_argument("--controller-url", type=str, default=argparse.SUPPRESS, help="Override Controller URL")
    con_p.add_argument("--node-id", type=str, default=argparse.SUPPRESS, help="Override node ID")
    con_p.add_argument("--overlay-ip", type=str, default=argparse.SUPPRESS, help="Override overlay IP")
    con_p.add_argument("--join-token", type=str, default=argparse.SUPPRESS, help="Optional Join Token to auto-enroll on startup")
    con_p.add_argument("--wg-port", type=int, default=argparse.SUPPRESS, help="WireGuard UDP port")
    con_p.add_argument("--qkd-port", type=int, default=argparse.SUPPRESS, help="BB84 QKD TCP port")

    # subcommand: status
    stat_p = subparsers.add_parser("status", help="Show local client identity, peers, and active routing directives")
    stat_p.add_argument("--config", type=str, default=argparse.SUPPRESS, help="Path to endpoint.json")
    stat_p.add_argument("--controller-url", type=str, default=argparse.SUPPRESS, help="Override Controller URL")
    stat_p.add_argument("--node-id", type=str, default=argparse.SUPPRESS, help="Override node ID")
    stat_p.add_argument("--overlay-ip", type=str, default=argparse.SUPPRESS, help="Override overlay IP")
    stat_p.add_argument("--json", action="store_true", help="Output raw JSON status")
    return parser


def _default_user_client_config_path() -> Path:
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("ProgramData")
        if base:
            return Path(base) / "qkd-sdwan-client" / "etc" / "endpoint.json"
    return Path.home() / ".local" / "share" / "qkd-sdwan-client" / "etc" / "endpoint.json"


def _resolve_client_config_path(args: argparse.Namespace) -> Path:
    explicit = getattr(args, "config", None) or os.environ.get("QKD_SDWAN_CLIENT_CONFIG")
    if explicit:
        return Path(explicit)
    sub = getattr(args, "subcommand", None)
    if sub not in ("up", "config", "init-config") and (
        getattr(args, "node_id", None) is not None or getattr(args, "overlay_ip", None) is not None
    ):
        return Path("/etc/qkd-sdwan/endpoint.json")
    candidates: list[Path] = [
        Path.home() / ".local" / "share" / "qkd-sdwan-client" / "etc" / "endpoint.json",
        Path("/etc/qkd-sdwan/endpoint.json"),
        Path("/opt/qkd-sdwan-client/etc/endpoint.json"),
    ]
    for env_key in ("LOCALAPPDATA", "ProgramData"):
        env_dir = os.environ.get(env_key)
        if env_dir:
            candidates.append(Path(env_dir) / "qkd-sdwan-client" / "etc" / "endpoint.json")
    for cand in candidates:
        if cand.is_file():
            return cand
    return _default_user_client_config_path()


def _load_endpoint_config(args: argparse.Namespace) -> dict[str, Any]:
    cfg: dict[str, Any] = {}
    cfg_path = _resolve_client_config_path(args)
    if cfg_path.is_file():
        cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    return cfg
def _request_local_daemon(
    config_path: Path | None,
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
    timeout: float = 15.0,
) -> dict[str, Any] | None:
    """Communicate with the running Local Control HTTP API of the Client daemon if active."""
    if config_path is None:
        return None
    state_path = config_path.with_suffix(".state.json")
    if not state_path.is_file():
        return None
    try:
        state_data = json.loads(state_path.read_text(encoding="utf-8"))
    except Exception:
        return None
    control_url = state_data.get("control_url")
    if not control_url or not isinstance(control_url, str):
        return None

    url = f"{control_url.rstrip('/')}{path}"
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json; charset=utf-8"
    req = request.Request(url, data=body, headers=headers, method=method)
    try:
        with request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except error.HTTPError as exc:
        err_body = exc.read().decode("utf-8", errors="replace")
        exc.close()
        try:
            parsed = json.loads(err_body)
            err_msg = str(parsed.get("error", err_body))
        except Exception:
            err_msg = err_body or str(exc)
        raise RuntimeError(err_msg) from exc
    except (error.URLError, TimeoutError, ConnectionError, OSError):
        return None

def _run_init_config(args: argparse.Namespace) -> int:
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    priv, pub = generate_wg_keypair()
    raw_join_token = (getattr(args, "join_token", "") or "").strip()
    effective_join_token = raw_join_token or "auto"
    ctrl_url = _normalize_controller_url(str(getattr(args, "controller_url", None) or "http://192.168.1.2:8080"))
    raw_node_id = str(getattr(args, "node_id", None) or "auto").strip()
    node_id = _default_node_id() if raw_node_id.lower() in ("", "auto", "edge-node-01") else raw_node_id
    overlay_ip = str(getattr(args, "overlay_ip", None) or "10.200.0.10").strip()
    raw_wg = getattr(args, "wg_port", None)
    wg_port = int(raw_wg) if raw_wg is not None else 51820
    raw_qkd = getattr(args, "qkd_port", None)
    qkd_port = int(raw_qkd) if raw_qkd is not None else 52820
    interface_name = str(getattr(args, "interface", None) or "wg-qkd0")
    backend_mode = str(getattr(args, "backend_mode", None) or "USERSPACE_CRYPTO_WG")
    explicit_ip = bool(getattr(args, "explicit_ip", False)) or (
        overlay_ip not in ("", "10.200.0.10", "auto", "0.0.0.0")
    )
    underlay_host = _detect_underlay_host(ctrl_url, getattr(args, "underlay_host", None) or "auto")

    hmac_secret = secrets.token_hex(32)
    auth_token_id = "hmac-sha256-cluster-v1"
    enrolled_token_id: str | None = None
    enrolled_ok = False

    try:
        req_data = {
            "join_token": effective_join_token,
            "node_id": node_id,
            "underlay_host": underlay_host,
            "wg_port": wg_port,
            "qkd_port": qkd_port,
            "wg_public_key": pub,
            "overlay_ip": overlay_ip if explicit_ip else None,
        }
        body = json.dumps(req_data).encode("utf-8")
        req = request.Request(
            f"{ctrl_url}/api/v1/nodes/enroll",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with request.urlopen(req, timeout=3.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            overlay_ip = str(data.get("allocated_overlay_ip", overlay_ip))
            hmac_secret = str(data.get("cluster_hmac_secret_hex", hmac_secret))
            auth_token_id = str(data.get("auth_token_id", f"enrolled-{data.get('token_id', 'tok')}"))
            enrolled_token_id = data.get("token_id")
            node_dict = data.get("node")
            if isinstance(node_dict, dict) and node_dict.get("underlay_host"):
                underlay_host = str(node_dict["underlay_host"])
            enrolled_ok = True
            print(f"      [+] Successfully enrolled {node_id} via Join Token at {ctrl_url} (allocated IP: {overlay_ip}, underlay: {underlay_host})")
    except Exception as exc:
        if raw_join_token:
            print(f"      [!] Join-Token enrollment failed at {ctrl_url} ({exc}); attempting direct node registration...")

    if not enrolled_ok:
        try:
            reg_data = {
                "node_id": node_id,
                "overlay_ip": overlay_ip if explicit_ip else "auto",
                "underlay_host": underlay_host,
                "wg_port": wg_port,
                "qkd_port": qkd_port,
                "wg_public_key": pub,
                "auth_token_id": auth_token_id,
                "registered_at": time.time(),
            }
            body = json.dumps(reg_data).encode("utf-8")
            req = request.Request(
                f"{ctrl_url}/api/v1/nodes/register",
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with request.urlopen(req, timeout=3.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                hmac_secret = str(data.get("cluster_hmac_secret_hex", hmac_secret))
                node_dict = data.get("node")
                if isinstance(node_dict, dict):
                    if node_dict.get("underlay_host"):
                        underlay_host = str(node_dict["underlay_host"])
                    if node_dict.get("overlay_ip"):
                        overlay_ip = str(node_dict["overlay_ip"])
                print(f"      [+] Registered {node_id} with Controller at {ctrl_url} (overlay IP: {overlay_ip}, underlay: {underlay_host})")
        except Exception as exc:
            if overlay_ip in ("auto", "0.0.0.0", ""):
                overlay_ip = "10.200.0.10"
            print(f"      [!] Controller at {ctrl_url} not reachable during install ({exc}); node will register when started")
    cfg = {
        "node_id": node_id,
        "overlay_ip": overlay_ip,
        "underlay_host": underlay_host,
        "interface_name": interface_name,
        "controller_url": ctrl_url,
        "wg_port": wg_port,
        "qkd_port": qkd_port,
        "wg_backend_mode": backend_mode,
        "wg_private_key": priv,
        "wg_public_key": pub,
        "classical_hmac_secret_hex": hmac_secret,
        "cluster_hmac_secret_hex": hmac_secret,
        "auth_token_id": auth_token_id,
        "enrolled_token_id": enrolled_token_id,
        "qber_abort_threshold": 0.11,
        "generated_at": time.time(),
    }
    out_path.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
    return 0


def _build_agent_from_args(args: argparse.Namespace) -> SDWANEndpointAgent:
    cfg_path = _resolve_client_config_path(args)
    cfg = _load_endpoint_config(args)
    node_id = getattr(args, "node_id", None) or cfg.get("node_id", "edge-local-01")
    overlay_ip = getattr(args, "overlay_ip", None) or cfg.get("overlay_ip", "10.200.0.10")
    controller_url = getattr(args, "controller_url", None) or cfg.get("controller_url", "http://127.0.0.1:8080")
    underlay_override = getattr(args, "underlay_host", None) or cfg.get("underlay_host")
    underlay_host = _detect_underlay_host(controller_url, underlay_override)
    raw_wg_port = getattr(args, "wg_port", None)
    wg_port = int(raw_wg_port) if raw_wg_port is not None else int(cfg.get("wg_port", 0))
    raw_qkd_port = getattr(args, "qkd_port", None)
    qkd_port = int(raw_qkd_port) if raw_qkd_port is not None else int(cfg.get("qkd_port", 0))
    secret_hex = cfg.get("cluster_hmac_secret_hex")
    auth_secret = bytes.fromhex(secret_hex) if secret_hex else b"qkd-sdwan-default-hmac-secret"
    join_token = getattr(args, "join_token", None)
    effective_cfg_path = cfg_path if (cfg_path.is_file() or getattr(args, "config", None) or os.environ.get("QKD_SDWAN_CLIENT_CONFIG")) else None
    if join_token:
        agent, _ = SDWANEndpointAgent.enroll_with_controller(
            controller_url=controller_url,
            join_token=join_token,
            node_id=node_id,
            underlay_host=underlay_host,
            wg_port=wg_port,
            qkd_port=qkd_port,
            overlay_ip=getattr(args, "overlay_ip", None),
            config_output_path=effective_cfg_path,
        )
        return agent

    agent = SDWANEndpointAgent(
        node_id=node_id,
        overlay_ip=overlay_ip,
        controller_url=controller_url,
        auth_secret=auth_secret,
        underlay_host=underlay_host,
        wg_port=wg_port,
        qkd_port=qkd_port,
        private_key_b64=cfg.get("wg_private_key"),
        prefer_kernel_wg=getattr(args, "prefer_kernel_wg", False),
        config_path=effective_cfg_path,
    )
    if cfg.get("auth_token_id"):
        agent.auth_token_id = str(cfg["auth_token_id"])
    return agent


def _run_console(agent: SDWANEndpointAgent) -> int:
    def _on_incoming(msg: P2PDataMessage) -> None:
        via_str = f" via RELAY {msg.via_relay_node}" if msg.via_relay_node else " (DIRECT_P2P)"
        if msg.content_type == "file":
            size_b = len(msg.decode_payload())
            print(
                f"\n[INBOX FILE] From {msg.source_node}{via_str} | File: {msg.filename} ({size_b} bytes) "
                f"| PSK Epoch: {msg.psk_epoch}"
            )
        else:
            print(
                f"\n[INBOX MSG] From {msg.source_node}{via_str} | PSK Epoch: {msg.psk_epoch} "
                f"| Text: {msg.decode_text()}"
            )

    agent.wg_daemon.register_message_callback(_on_incoming)
    print("=" * 92)
    print(f" QKD-SDWAN P2P Client Console — Node: {agent.node_id} ({agent.overlay_ip})")
    print(f" Underlay WG UDP : {agent.underlay_host}:{agent.wg_port} | BB84 QKD TCP : {agent.underlay_host}:{agent.qkd_port}")
    print(
        " Commands: dashboard | peers | rekey <peer> | send <peer> <text> | "
        "sendfile <peer> <path> | inbox | savefile <id> [dir] | quit"
    )
    print("=" * 92)
    while True:
        try:
            line = input(f"{agent.node_id}> ").strip()
        except EOFError:
            break
        if not line:
            continue
        parts = line.split(maxsplit=2)
        cmd = parts[0].lower()

        if cmd in ("quit", "exit", "q"):
            break
        if cmd in ("dashboard", "ui"):
            try:
                agent.sync_topology()
            except Exception:
                pass
            print(render_client_dashboard(agent))
            continue
        if cmd == "peers":
            try:
                agent.sync_topology()
            except Exception:
                pass
            peers = agent.wg_daemon.list_peers()
            if not peers:
                print("  (no peers registered)")
            for pid, pstate in sorted(peers.items()):
                print(
                    f"  - {pid:<14} | Overlay: {pstate.peer_overlay_ip:<13} | Mode: {pstate.route_mode.value:<10} "
                    f"| Relay: {pstate.via_relay_node or '-':<12} | PSK Epoch: {pstate.psk_epoch} "
                    f"(fp: {pstate.current_psk_fingerprint or 'none'})"
                )
        elif cmd == "rekey" and len(parts) >= 2:
            target = parts[1]
            res = agent.run_key_rotation_and_telemetry_cycle(target)
            bb84 = res["bb84"]
            print(
                f"  [+] BB84 Session with {target}: QBER={bb84['measured_qber']*100:.2f}%, "
                f"PSK Injected={res['psk_injected']}, RouteMode={res['directive']['route_mode']}"
            )
        elif cmd == "send" and len(parts) >= 3:
            target, text_msg = parts[1], parts[2]
            res = agent.send_p2p_text(target, text_msg)
            deliv = res["delivery"]
            print(
                f"  [+] Delivered msg {res['message']['message_id']} to {target} via {deliv['route_mode']} "
                f"(PSK Epoch {deliv['psk_epoch']}, RTT {deliv['rtt_ms']:.2f} ms)"
            )
        elif cmd == "sendfile" and len(parts) >= 3:
            target, fpath = parts[1], parts[2]
            res = agent.send_p2p_file(target, fpath)
            deliv = res["delivery"]
            print(
                f"  [+] Delivered file '{res['message']['filename']}' to {target} via {deliv['route_mode']} "
                f"(PSK Epoch {deliv['psk_epoch']}, RTT {deliv['rtt_ms']:.2f} ms)"
            )
        elif cmd == "inbox":
            msgs = agent.get_received_messages(clear=False)
            if not msgs:
                print("  (inbox empty)")
            for idx, m in enumerate(msgs, start=1):
                if m.content_type == "file":
                    print(
                        f"  [{idx}] {m.message_id} from {m.source_node} ({m.route_mode}): "
                        f"FILE '{m.filename}' ({len(m.decode_payload())} bytes)"
                    )
                else:
                    print(
                        f"  [{idx}] {m.message_id} from {m.source_node} ({m.route_mode}): {m.decode_text()}"
                    )
        elif cmd == "savefile" and len(parts) >= 2:
            msg_id_or_idx = parts[1]
            dest_dir = parts[2] if len(parts) >= 3 else "."
            saved = agent.save_inbox_file(msg_id_or_idx, dest_dir)
            print(f"  [+] Saved verified inbox file to: {saved}")
        else:
            print(
                "  Commands: dashboard | peers | rekey <peer> | send <peer> <text> | "
                "sendfile <peer> <path> | inbox | savefile <id> [dir] | quit"
            )
    return 0


def _run_serve_client(args: argparse.Namespace) -> int:
    cfg_path = _resolve_client_config_path(args)
    if getattr(args, "daemon", False) and os.environ.get("QKD_SDWAN_DAEMON_CHILD") != "1":
        existing = _request_local_daemon(cfg_path, "GET", "/local/v1/status", timeout=1.0)
        if existing is not None:
            print(
                json.dumps(
                    {
                        "status": "already_running",
                        "pid": existing.get("pid"),
                        "node_id": existing.get("node_id"),
                        "overlay_ip": existing.get("overlay_ip"),
                        "control_url": existing.get("control_url"),
                    },
                    indent=2,
                )
            )
            return 0

        child_env = os.environ.copy()
        child_env["QKD_SDWAN_DAEMON_CHILD"] = "1"
        py_paths = [p for p in sys.path if p]
        if py_paths:
            existing_pp = child_env.get("PYTHONPATH", "")
            child_env["PYTHONPATH"] = os.pathsep.join(py_paths + ([existing_pp] if existing_pp else []))

        child_cmd = [sys.executable, "-m", "qkd_sdwan.client.agent", "--config", str(cfg_path), "serve"]
        if getattr(args, "node_id", None):
            child_cmd.extend(["--node-id", str(args.node_id)])
        if getattr(args, "overlay_ip", None):
            child_cmd.extend(["--overlay-ip", str(args.overlay_ip)])
        if getattr(args, "controller_url", None):
            child_cmd.extend(["--controller-url", str(args.controller_url)])
        if getattr(args, "underlay_host", None):
            child_cmd.extend(["--underlay-host", str(args.underlay_host)])
        if getattr(args, "join_token", None):
            child_cmd.extend(["--join-token", str(args.join_token)])
        if getattr(args, "wg_port", None) is not None:
            child_cmd.extend(["--wg-port", str(args.wg_port)])
        if getattr(args, "qkd_port", None) is not None:
            child_cmd.extend(["--qkd-port", str(args.qkd_port)])
        hb_int = getattr(args, "heartbeat_interval", None)
        if hb_int is not None:
            child_cmd.extend(["--heartbeat-interval", str(hb_int)])

        log_path = cfg_path.with_suffix(".log")
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
        except Exception:
            log_path = Path(tempfile.gettempdir()) / f"qkd-sdwan-client-{os.getpid()}.log"
        spawned_pid: int | None = None
        if os.name == "nt":
            try:
                launch_cmd_path = cfg_path.with_suffix(".launch.cmd")
                cmd_str = subprocess.list2cmdline(child_cmd)
                bat_lines = [
                    "@echo off",
                    "set \"QKD_SDWAN_DAEMON_CHILD=1\"",
                    f"set \"PYTHONPATH={child_env.get('PYTHONPATH', '')}\"",
                    f"{cmd_str} >> \"{log_path}\" 2>&1",
                ]
                launch_cmd_path.write_text("\r\n".join(bat_lines) + "\r\n", encoding="utf-8")
                ps_expr = (
                    f"$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create "
                    f"-Arguments @{{CommandLine='{launch_cmd_path}'}}; "
                    f"if ($r.ReturnValue -eq 0 -and $r.ProcessId) {{ Write-Output $r.ProcessId }} else {{ exit 1 }}"
                )
                wmi_res = subprocess.run(
                    ["powershell", "-NoProfile", "-Command", ps_expr],
                    capture_output=True,
                    text=True,
                    timeout=5.0,
                )
                if wmi_res.returncode == 0 and wmi_res.stdout.strip().splitlines():
                    spawned_pid = int(wmi_res.stdout.strip().splitlines()[-1].strip())
            except Exception:
                spawned_pid = None

        if spawned_pid is None:
            log_fh = open(log_path, "a", encoding="utf-8")
            popen_kwargs: dict[str, Any] = {
                "stdin": subprocess.DEVNULL,
                "stdout": log_fh,
                "stderr": subprocess.STDOUT,
                "env": child_env,
            }
            if os.name == "nt":
                popen_kwargs["creationflags"] = (
                    getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                    | getattr(subprocess, "DETACHED_PROCESS", 0)
                )
            else:
                popen_kwargs["start_new_session"] = True

            proc = subprocess.Popen(child_cmd, **popen_kwargs)
            log_fh.close()
            spawned_pid = proc.pid

        deadline = time.time() + 8.0
        daemon_status: dict[str, Any] | None = None
        while time.time() < deadline:
            daemon_status = _request_local_daemon(cfg_path, "GET", "/local/v1/status?fast=1", timeout=0.8)
            if daemon_status is not None and daemon_status.get("control_url"):
                break
            time.sleep(0.1)

        if daemon_status is None:
            raise RuntimeError(f"Client daemon (PID {spawned_pid}) failed to start Local Control API (log: {log_path})")

        actual_pid = daemon_status.get("pid") or spawned_pid
        print("=" * 96)
        print(f" QKD-SDWAN Endpoint Client Daemon Running in Background (PID: {actual_pid})")
        print(f" Node ID          : {daemon_status.get('node_id')} ({daemon_status.get('overlay_ip')})")
        print(f" Controller URL   : {daemon_status.get('controller_url')}")
        print(f" WG UDP / QKD TCP : {daemon_status.get('underlay_host')}:{daemon_status.get('wg_port')} / {daemon_status.get('qkd_port')}")
        print(f" Local Control URL: {daemon_status.get('control_url')}")
        print("=" * 96)
        return 0

    agent = _build_agent_from_args(args)
    if agent.config_path is None:
        agent.config_path = cfg_path
        agent.state_path = cfg_path.with_suffix(".state.json")
    def _handle_sigterm(_signum: int, _frame: Any) -> None:
        agent.stop_event.set()

    try:
        signal.signal(signal.SIGTERM, _handle_sigterm)
    except Exception:
        pass

    try:
        hb_interval = float(getattr(args, "heartbeat_interval", 2.0) or 2.0)
        ctrl_api_url = agent.start_daemon_services(heartbeat_interval=hb_interval)
        try:
            agent.register_with_controller()
            agent.sync_topology()
        except Exception as exc:
            print(f"[!] Warning: Initial Controller sync failed ({exc}); background heartbeat will auto-retry.")
        print(f" QKD-SDWAN Endpoint Client Daemon Active — Node: {agent.node_id} ({agent.overlay_ip})")
        print(f" Controller URL   : {agent.controller_url}")
        print(f" WG UDP / QKD TCP : {agent.underlay_host}:{agent.wg_port} / {agent.underlay_host}:{agent.qkd_port}")
        print(f" Local Control API: {ctrl_api_url}")
        print("=" * 96)
        while not agent.stop_event.is_set():
            agent.stop_event.wait(timeout=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        agent.close()
    return 0


def _run_stop_client(args: argparse.Namespace) -> int:
    cfg_path = _resolve_client_config_path(args)
    state_path = cfg_path.with_suffix(".state.json")
    pid_val: int | None = None
    node_id_val: str | None = None
    ctrl_url_val: str | None = None
    if state_path.is_file():
        try:
            raw = json.loads(state_path.read_text(encoding="utf-8"))
            pid_val = int(raw["pid"]) if raw.get("pid") else None
            node_id_val = str(raw["node_id"]) if raw.get("node_id") else None
            ctrl_url_val = str(raw["controller_url"]) if raw.get("controller_url") else None
        except Exception:
            pass
    if cfg_path.is_file() and (not node_id_val or not ctrl_url_val):
        try:
            raw_cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
            node_id_val = node_id_val or (str(raw_cfg["node_id"]) if raw_cfg.get("node_id") else None)
            ctrl_url_val = ctrl_url_val or (str(raw_cfg["controller_url"]) if raw_cfg.get("controller_url") else None)
        except Exception:
            pass

    resp = _request_local_daemon(cfg_path, "POST", "/local/v1/stop", {}, timeout=2.0)
    stopped_via_api = resp is not None

    if pid_val is not None and stopped_via_api:
        deadline = time.time() + 2.5
        while time.time() < deadline:
            if os.name == "nt":
                if _request_local_daemon(cfg_path, "GET", "/local/v1/status?fast=1", timeout=0.25) is None:
                    break
                time.sleep(0.05)
            else:
                try:
                    os.kill(pid_val, 0)
                    time.sleep(0.05)
                except Exception:
                    break
        else:
            try:
                os.kill(pid_val, signal.SIGTERM)
            except Exception:
                pass
    if node_id_val and ctrl_url_val:
        try:
            TelemetryExporter(controller_url=ctrl_url_val, timeout=1.0).disconnect_node(node_id_val)
        except Exception:
            pass
    print(
        json.dumps(
            {
                "status": "stopped",
                "config_path": str(cfg_path),
                "pid": pid_val,
                "stopped_via_api": stopped_via_api,
            },
            indent=2,
        )
    )
    return 0


def _run_config_client(args: argparse.Namespace) -> int:
    cfg_path = _resolve_client_config_path(args)
    has_updates = any(
        getattr(args, field, None) is not None
        for field in ("controller_url", "node_id", "overlay_ip", "underlay_host", "join_token")
    )
    daemon_status = _request_local_daemon(cfg_path, "GET", "/local/v1/status", timeout=1.5)
    if not has_updates:
        if daemon_status is not None:
            print(
                json.dumps(
                    {
                        "status": "ok",
                        "daemon_running": True,
                        "node_id": daemon_status.get("node_id"),
                        "overlay_ip": daemon_status.get("overlay_ip"),
                        "underlay_host": daemon_status.get("underlay_host"),
                        "controller_url": daemon_status.get("controller_url"),
                        "wg_port": daemon_status.get("wg_port"),
                        "qkd_port": daemon_status.get("qkd_port"),
                        "config_path": str(cfg_path),
                    },
                    indent=2,
                )
            )
            return 0
        cfg = _load_endpoint_config(args)
        print(json.dumps({"status": "ok", "daemon_running": False, "config_path": str(cfg_path), "config": cfg}, indent=2))
        return 0

    if daemon_status is not None:
        res = _request_local_daemon(
            cfg_path,
            "POST",
            "/local/v1/config",
            {
                "controller_url": getattr(args, "controller_url", None),
                "node_id": getattr(args, "node_id", None),
                "overlay_ip": getattr(args, "overlay_ip", None),
                "underlay_host": getattr(args, "underlay_host", None),
                "join_token": getattr(args, "join_token", None),
            },
            timeout=10.0,
        )
        print(json.dumps(res, indent=2))
        return 0

    # Offline config update when daemon is not running
    cfg = _load_endpoint_config(args)
    if getattr(args, "controller_url", None):
        norm_url = str(args.controller_url).strip()
        if not norm_url.startswith(("http://", "https://")):
            norm_url = f"http://{norm_url}"
        cfg["controller_url"] = norm_url.rstrip("/")
    if getattr(args, "node_id", None):
        cfg["node_id"] = str(args.node_id).strip()
    if getattr(args, "overlay_ip", None):
        cfg["overlay_ip"] = str(args.overlay_ip).strip()
    if getattr(args, "underlay_host", None):
        cfg["underlay_host"] = _detect_underlay_host(str(cfg.get("controller_url", "http://127.0.0.1:8080")), str(args.underlay_host))
    elif "controller_url" in cfg:
        cfg["underlay_host"] = _detect_underlay_host(str(cfg["controller_url"]), cfg.get("underlay_host"))

    if not cfg.get("wg_private_key") or not cfg.get("wg_public_key"):
        priv, pub = generate_wg_keypair()
        cfg["wg_private_key"] = priv
        cfg["wg_public_key"] = pub

    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "status": "updated",
                "daemon_running": False,
                "node_id": cfg.get("node_id"),
                "overlay_ip": cfg.get("overlay_ip"),
                "underlay_host": cfg.get("underlay_host"),
                "controller_url": cfg.get("controller_url"),
                "config_path": str(cfg_path),
            },
            indent=2,
        )
    )
    return 0


def _run_up_client(args: argparse.Namespace) -> int:
    cfg_path = _resolve_client_config_path(args)
    raw_ctrl = getattr(args, "target_controller", None) or getattr(args, "controller_url", None)
    norm_ctrl = _normalize_controller_url(str(raw_ctrl)) if raw_ctrl else None

    if not cfg_path.is_file():
        init_ns = argparse.Namespace(
            output=cfg_path,
            node_id=getattr(args, "node_id", None) or _default_node_id(),
            overlay_ip=getattr(args, "overlay_ip", None) or "10.200.0.10",
            controller_url=norm_ctrl or "http://192.168.1.2:8080",
            join_token=getattr(args, "join_token", None) or "auto",
            wg_port=getattr(args, "wg_port", None) or 51820,
            qkd_port=getattr(args, "qkd_port", None) or 52820,
            interface="wg-qkd0",
            backend_mode="USERSPACE_CRYPTO_WG",
            underlay_host=getattr(args, "underlay_host", None) or "auto",
            explicit_ip=bool(getattr(args, "overlay_ip", None)),
        )
        _run_init_config(init_ns)

    existing = _request_local_daemon(cfg_path, "GET", "/local/v1/status", timeout=1.5)
    if existing is not None:
        if any(
            x is not None
            for x in (
                norm_ctrl,
                getattr(args, "node_id", None),
                getattr(args, "overlay_ip", None),
                getattr(args, "underlay_host", None),
                getattr(args, "join_token", None),
            )
        ):
            upd = _request_local_daemon(
                cfg_path,
                "POST",
                "/local/v1/config",
                {
                    "controller_url": norm_ctrl,
                    "node_id": getattr(args, "node_id", None),
                    "overlay_ip": getattr(args, "overlay_ip", None),
                    "underlay_host": getattr(args, "underlay_host", None) or "auto",
                    "join_token": getattr(args, "join_token", None) or ("auto" if norm_ctrl else None),
                },
                timeout=10.0,
            )
            print(json.dumps(upd, indent=2))
            return 0
        print(
            json.dumps(
                {
                    "status": "up",
                    "pid": existing.get("pid"),
                    "node_id": existing.get("node_id"),
                    "overlay_ip": existing.get("overlay_ip"),
                    "underlay_host": existing.get("underlay_host"),
                    "controller_url": existing.get("controller_url"),
                    "wg_port": existing.get("wg_port"),
                    "qkd_port": existing.get("qkd_port"),
                    "peers_count": len(existing.get("peers", [])),
                },
                indent=2,
            )
        )
        return 0

    if norm_ctrl:
        setattr(args, "controller_url", norm_ctrl)
    setattr(args, "config", str(cfg_path))
    setattr(args, "daemon", True)
    return _run_serve_client(args)


def _run_peers_client(args: argparse.Namespace) -> int:
    cfg_path = _resolve_client_config_path(args)
    daemon_status = _request_local_daemon(cfg_path, "GET", "/local/v1/status", timeout=5.0)
    if daemon_status is None:
        agent = _build_agent_from_args(args)
        try:
            try:
                agent.register_with_controller()
                agent.sync_topology()
            except Exception:
                pass
            daemon_status = agent.export_state_dict(include_dashboard=False)
        finally:
            agent.close(notify_controller=False)
    peers = daemon_status.get("peers", [])
    wg_peers = daemon_status.get("wg_peers", {})
    if getattr(args, "json", False):
        print(json.dumps({"node_id": daemon_status.get("node_id"), "peers": peers, "wg_peers": wg_peers}, indent=2))
        return 0

    rows: list[list[str]] = []
    for p in peers:
        pid = str(p.get("node_id", ""))
        wstate = wg_peers.get(pid, {})
        rows.append(
            [
                pid,
                str(p.get("overlay_ip", "")),
                f"{p.get('underlay_host', '')}:{p.get('wg_port', '')}",
                str(p.get("qkd_port", "")),
                str(wstate.get("route_mode", "DIRECT_P2P")),
                str(wstate.get("via_relay_node") or "-"),
                str(wstate.get("psk_epoch", 0)),
                str(wstate.get("current_psk_fingerprint") or "(unkeyed)")[:16],
            ]
        )
    print(
        "\n".join(
            _format_ascii_table(
                ["Peer Node", "Overlay IP", "WG Endpoint", "QKD TCP", "RouteMode", "Via Relay", "PSK Epoch", "PSK Fingerprint"],
                rows,
            )
        )
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    sub = getattr(args, "subcommand", None)
    cfg_path = _resolve_client_config_path(args)

    if sub == "init-config":
        return _run_init_config(args)

    if sub == "up":
        return _run_up_client(args)

    if sub in ("stop", "down"):
        return _run_stop_client(args)

    if sub == "peers":
        return _run_peers_client(args)

    if sub == "config":
        return _run_config_client(args)

    if sub == "enroll":
        raw_nid = str(args.node_id or "auto").strip()
        eff_nid = _default_node_id() if raw_nid.lower() in ("", "auto") else raw_nid
        eff_ctrl = _normalize_controller_url(str(args.controller_url))
        eff_uh = _detect_underlay_host(eff_ctrl, args.underlay_host)
        agent, enroll_resp = SDWANEndpointAgent.enroll_with_controller(
            controller_url=eff_ctrl,
            join_token=args.join_token or "auto",
            node_id=eff_nid,
            underlay_host=eff_uh,
            wg_port=args.wg_port,
            qkd_port=args.qkd_port,
            overlay_ip=args.overlay_ip,
            config_output_path=args.output_config,
        )
        try:
            print(
                json.dumps(
                    {
                        "status": "enrolled",
                        "node_id": agent.node_id,
                        "allocated_overlay_ip": enroll_resp["allocated_overlay_ip"],
                        "token_id": enroll_resp["token_id"],
                        "wg_public_key": agent.wg_daemon.public_key_b64,
                        "output_config": str(args.output_config) if args.output_config else None,
                    },
                    indent=2,
                )
            )
        finally:
            agent.close(notify_controller=False)
        return 0

    if getattr(args, "check_config", False):
        cfg = _load_endpoint_config(args)
        node_id = args.node_id or cfg.get("node_id", _default_node_id())
        overlay_ip = args.overlay_ip or cfg.get("overlay_ip", "10.200.0.10")
        controller_url = args.controller_url or cfg.get("controller_url", "http://192.168.1.2:8080")
        print(
            json.dumps(
                {
                    "status": "valid",
                    "node_id": node_id,
                    "overlay_ip": overlay_ip,
                    "controller_url": controller_url,
                },
                indent=2,
            )
        )
        return 0

    if sub == "rekey":
        target_peer = getattr(args, "target_node", None) or getattr(args, "pos_target_node", None)
        rekey_all = bool(getattr(args, "all", False)) or not target_peer
        daemon_status = _request_local_daemon(cfg_path, "GET", "/local/v1/status", timeout=5.0)
        if daemon_status is not None:
            if not rekey_all and target_peer:
                daemon_res = _request_local_daemon(
                    cfg_path,
                    "POST",
                    "/local/v1/rekey",
                    {"target_node": target_peer},
                    timeout=20.0,
                )
                print(json.dumps(daemon_res, indent=2))
                return 0
            peers_list = [str(p.get("node_id")) for p in daemon_status.get("peers", []) if p.get("node_id")]
            if not peers_list:
                raise SystemExit("Error: no registered peers found to rekey")
            results = []
            for pid in peers_list:
                r = _request_local_daemon(cfg_path, "POST", "/local/v1/rekey", {"target_node": pid}, timeout=20.0)
                if r is not None:
                    results.append(r)
            if len(results) == 1 and not getattr(args, "all", False):
                print(json.dumps(results[0], indent=2))
            else:
                print(
                    json.dumps(
                        {
                            "status": "rekeyed_all",
                            "peers_rekeyed": len(results),
                            "psk_injected": all(bool(r.get("psk_injected")) for r in results),
                            "results": results,
                        },
                        indent=2,
                    )
                )
            return 0

        agent = _build_agent_from_args(args)
        try:
            agent.register_with_controller()
            topo = agent.sync_topology()
            if not rekey_all and target_peer:
                res = agent.run_key_rotation_and_telemetry_cycle(target_peer)
                print(json.dumps(res, indent=2))
                return 0
            peers_list = [str(p.get("node_id")) for p in topo.get("peers", []) if p.get("node_id")]
            if not peers_list:
                raise SystemExit("Error: no registered peers found to rekey")
            results = [agent.run_key_rotation_and_telemetry_cycle(pid) for pid in peers_list]
            if len(results) == 1 and not getattr(args, "all", False):
                print(json.dumps(results[0], indent=2))
            else:
                print(
                    json.dumps(
                        {
                            "status": "rekeyed_all",
                            "peers_rekeyed": len(results),
                            "psk_injected": all(bool(r.get("psk_injected")) for r in results),
                            "results": results,
                        },
                        indent=2,
                    )
                )
        finally:
            agent.close()
        return 0

    if sub in ("send", "sendfile"):
        target_peer = getattr(args, "target_node", None) or getattr(args, "pos_target_node", None)
        if not target_peer:
            raise SystemExit(f"Error: specify target peer node ID for '{sub}'")
        file_arg = getattr(args, "file", None) or getattr(args, "pos_file", None)
        text_arg = getattr(args, "text", None)
        if text_arg is None and getattr(args, "pos_text", None) is not None:
            text_arg = getattr(args, "pos_text", None)
        if sub == "sendfile" and not file_arg:
            raise SystemExit("Error: specify file path for 'sendfile'")
        if not text_arg and not file_arg:
            raise SystemExit("Error: specify message text or --file for 'send'")
        daemon_res = _request_local_daemon(
            cfg_path,
            "POST",
            "/local/v1/send",
            {
                "target_node": target_peer,
                "text": text_arg,
                "file_path": str(Path(file_arg).resolve()) if file_arg else None,
            },
            timeout=20.0,
        )
        if daemon_res is not None:
            print(json.dumps(daemon_res, indent=2))
            return 0
        agent = _build_agent_from_args(args)
        try:
            agent.register_with_controller()
            agent.sync_topology()
            if file_arg:
                res = agent.send_p2p_file(target_peer, file_arg)
            else:
                res = agent.send_p2p_text(target_peer, str(text_arg))
            print(json.dumps(res, indent=2))
        finally:
            agent.close()
        return 0

    if sub == "save":
        daemon_res = _request_local_daemon(
            cfg_path,
            "POST",
            "/local/v1/savefile",
            {
                "message_id_or_index": args.message_id_or_index,
                "dest_dir": str(Path(args.dest_dir).resolve()),
            },
            timeout=10.0,
        )
        if daemon_res is not None:
            print(json.dumps(daemon_res, indent=2))
            return 0
        agent = _build_agent_from_args(args)
        try:
            saved_path = agent.save_inbox_file(args.message_id_or_index, args.dest_dir)
            print(json.dumps({"status": "saved", "saved_path": str(saved_path)}, indent=2))
        finally:
            agent.close()
        return 0

    if sub == "inbox":
        if args.save is not None:
            daemon_res = _request_local_daemon(
                cfg_path,
                "POST",
                "/local/v1/savefile",
                {
                    "message_id_or_index": args.save,
                    "dest_dir": str(Path(args.dir).resolve()),
                },
                timeout=10.0,
            )
            if daemon_res is not None:
                print(json.dumps(daemon_res, indent=2))
                return 0
            agent = _build_agent_from_args(args)
            try:
                saved_path = agent.save_inbox_file(args.save, args.dir)
                print(json.dumps({"status": "saved", "saved_path": str(saved_path)}, indent=2))
            finally:
                agent.close()
            return 0

        daemon_status = _request_local_daemon(cfg_path, "GET", "/local/v1/status", timeout=5.0)
        if daemon_status is None:
            state_path = cfg_path.with_suffix(".state.json")
            if state_path.is_file():
                daemon_status = json.loads(state_path.read_text(encoding="utf-8"))
            else:
                daemon_status = {"inbox": [], "outbox": []}

        inbox_items = daemon_status.get("inbox", [])
        outbox_items = daemon_status.get("outbox", [])
        if getattr(args, "json", False):
            print(json.dumps({"inbox": inbox_items, "outbox": outbox_items}, indent=2))
            return 0

        rows: list[list[str]] = []
        for idx, m_dict in enumerate(inbox_items, start=1):
            msg = P2PDataMessage.from_dict(m_dict)
            raw_len = len(msg.decode_payload(verify=False))
            summary = (
                f"FILE '{msg.filename}' ({raw_len} bytes)"
                if msg.content_type == "file"
                else msg.decode_text(verify=False)
            )
            rows.append(
                [
                    str(idx),
                    msg.message_id,
                    msg.source_node,
                    msg.content_type.upper(),
                    msg.route_mode,
                    str(msg.psk_epoch),
                    msg.payload_sha256[:16],
                    summary,
                ]
            )
        print(
            "\n".join(
                _format_ascii_table(
                    ["#", "Message ID", "From Peer", "Type", "RouteMode", "PSK Epoch", "SHA-256", "Content / Filename"],
                    rows,
                )
            )
        )
        return 0

    if sub == "status":
        daemon_status = _request_local_daemon(cfg_path, "GET", "/local/v1/status", timeout=5.0)
        if daemon_status is not None:
            payload = {
                "node_id": daemon_status.get("node_id"),
                "overlay_ip": daemon_status.get("overlay_ip"),
                "underlay_host": daemon_status.get("underlay_host"),
                "controller_url": daemon_status.get("controller_url"),
                "wg_port": daemon_status.get("wg_port"),
                "qkd_port": daemon_status.get("qkd_port"),
                "wg_public_key": daemon_status.get("wg_public_key"),
                "daemon_pid": daemon_status.get("pid"),
                "control_url": daemon_status.get("control_url"),
                "peers": daemon_status.get("peers", []),
                "directives": daemon_status.get("directives", []),
                "inbox_count": len(daemon_status.get("inbox", [])),
                "outbox_count": len(daemon_status.get("outbox", [])),
            }
            print(json.dumps(payload, indent=2))
            return 0
        agent = _build_agent_from_args(args)
        try:
            agent.register_with_controller()
            topo = agent.sync_topology()
            payload = {
                "node_id": agent.node_id,
                "overlay_ip": agent.overlay_ip,
                "underlay_host": agent.underlay_host,
                "controller_url": agent.controller_url,
                "wg_port": agent.wg_port,
                "qkd_port": agent.qkd_port,
                "wg_public_key": agent.wg_daemon.public_key_b64,
                "peers": topo.get("peers", []),
                "directives": topo.get("directives", []),
            }
            print(json.dumps(payload, indent=2))
        finally:
            agent.close(notify_controller=False)
        return 0

    if sub == "dashboard" or getattr(args, "dashboard", False):
        daemon_status = _request_local_daemon(cfg_path, "GET", "/local/v1/status", timeout=5.0)
        if daemon_status is not None:
            if getattr(args, "once", False):
                print(str(daemon_status.get("dashboard_ascii", "")))
                return 0
            interval = float(getattr(args, "interval", 0.0) or 0.0)
            if interval > 0.0:
                try:
                    while True:
                        live = _request_local_daemon(cfg_path, "GET", "/local/v1/status", timeout=5.0)
                        if live is None:
                            break
                        print("\033[2J\033[H" + str(live.get("dashboard_ascii", "")), flush=True)
                        time.sleep(interval)
                except KeyboardInterrupt:
                    return 0
                return 0
            return run_client_dashboard_via_daemon(cfg_path)

        agent = _build_agent_from_args(args)
        try:
            try:
                agent.register_with_controller()
                agent.sync_topology()
            except Exception as exc:
                print(f"[!] Warning: Could not reach Controller at {agent.controller_url}: {exc}")
            if getattr(args, "once", False):
                print(render_client_dashboard(agent))
                return 0
            agent.start_daemon_services()
            interval = float(getattr(args, "interval", 0.0) or 0.0)
            if interval > 0.0:
                try:
                    while True:
                        try:
                            agent.sync_topology()
                        except Exception:
                            pass
                        print("\033[2J\033[H" + render_client_dashboard(agent), flush=True)
                        time.sleep(interval)
                except KeyboardInterrupt:
                    return 0
            return run_client_dashboard_interactive(agent)
        finally:
            agent.close(notify_controller=not bool(getattr(args, "once", False)))
    if sub == "console":
        agent = _build_agent_from_args(args)
        try:
            try:
                agent.register_with_controller()
                agent.sync_topology()
            except Exception:
                pass
            agent.start_daemon_services()
            return _run_console(agent)
        finally:
            agent.close()

    if sub is None and not getattr(args, "daemon", False) and os.environ.get("QKD_SDWAN_DAEMON_CHILD") != "1" and sys.stdin.isatty():
        existing = _request_local_daemon(cfg_path, "GET", "/local/v1/status", timeout=1.0)
        if existing is None and cfg_path.is_file():
            setattr(args, "daemon", True)
            _run_serve_client(args)
        if _request_local_daemon(cfg_path, "GET", "/local/v1/status", timeout=1.5) is not None:
            return run_client_dashboard_via_daemon(cfg_path)

    return _run_serve_client(args)
if __name__ == "__main__":
    raise SystemExit(main())
