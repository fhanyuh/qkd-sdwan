"""SD-WAN Endpoint Agent integrating BB84 QKD negotiation, WireGuard PSK injection, P2P data transfer, and Client CLI."""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets
import threading
import time
from typing import Any
from urllib import error, request
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
    ) -> dict[str, Any]:
        return self._request_json(
            "POST",
            "/api/v1/nodes/enroll",
            {
                "join_token": join_token,
                "node_id": node_id,
                "underlay_host": underlay_host,
                "wg_port": wg_port,
                "qkd_port": qkd_port,
                "wg_public_key": wg_public_key,
                "overlay_ip": overlay_ip,
            },
        )

    def register_node(self, registration: NodeRegistration) -> dict[str, Any]:
        return self._request_json("POST", "/api/v1/nodes/register", registration.to_dict())

    def send_telemetry(self, telemetry: LinkTelemetry) -> dict[str, Any]:
        return self._request_json("POST", "/api/v1/telemetry", telemetry.to_dict())

    def fetch_topology(self, node_id: str) -> dict[str, Any]:
        return self._request_json("GET", f"/api/v1/topology/{node_id}")


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
    ) -> None:
        self.node_id = node_id
        self.overlay_ip = overlay_ip
        self.underlay_host = underlay_host
        self.controller_url = controller_url
        self.auth_secret = auth_secret
        self.auth_token_id = "hmac-sha256-cluster-v1"
        self._agent_lock = threading.RLock()

        self.exporter = TelemetryExporter(controller_url=controller_url)
        self.peer_registry: dict[str, NodeRegistration] = {}
        self.active_directives: dict[str, RouteDirective] = {}
        self._peer_epoch: dict[str, int] = {}
        self._last_qber: dict[str, float] = {}
        self._abort_counts: dict[str, int] = {}
        self.last_bb84_results: dict[str, BB84SessionResult] = {}
        self.bb84_history: list[BB84SessionResult] = []

        self.wg_daemon = WireGuardTunnelDaemon(
            node_id=node_id,
            interface_name=interface_name,
            overlay_ip=overlay_ip,
            listen_port=wg_port,
            private_key_b64=private_key_b64,
            prefer_kernel_wg=prefer_kernel_wg,
            bind_host=underlay_host,
        )
        self.wg_port = self.wg_daemon.bound_port

        self.bb84_engine = BB84ProtocolEngine(
            node_id=node_id,
            auth_secret=auth_secret,
            channel_params=channel_params,
        )
        try:
            self.bb84_engine.start_tcp_responder(
                host=underlay_host,
                port=qkd_port,
                on_key_established=self._on_responder_bb84_completed,
            )
        except Exception:
            self.wg_daemon.close()
            raise
        self.qkd_port = self.bb84_engine.bound_port
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
    def register_with_controller(self) -> dict[str, Any]:
        """Register this endpoint with the Central Controller and populate initial peer table."""
        reg = NodeRegistration(
            node_id=self.node_id,
            overlay_ip=self.overlay_ip,
            underlay_host=self.underlay_host,
            wg_port=self.wg_port,
            qkd_port=self.qkd_port,
            wg_public_key=self.wg_daemon.public_key_b64,
            auth_token_id=self.auth_token_id,
            registered_at=time.time(),
        )
        resp = self.exporter.register_node(reg)
        for peer_dict in resp.get("peers", []):
            self._ingest_peer_dict(peer_dict)
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
        delivery = self.wg_daemon.send_overlay_packet(target_node=target_node, payload=wire_bytes)

        msg.route_mode = str(delivery.get("route_mode", msg.route_mode))
        msg.via_relay_node = delivery.get("via_relay_node") or msg.via_relay_node
        self.wg_daemon.record_outbox_message(msg)

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

        # 2. Negotiate BB84 quantum session directly over TCP with the peer
        bb84_result = self.bb84_engine.initiate_session(
            peer_host=peer_reg.underlay_host,
            peer_port=peer_reg.qkd_port,
            peer_node=target_node,
            epoch=next_epoch,
            override_params=override_channel_params,
        )
        with self._agent_lock:
            self.last_bb84_results[target_node] = bb84_result
            self.bb84_history.append(bb84_result)
            if len(self.bb84_history) > 128:
                self.bb84_history.pop(0)
        psk_injected = False
        injection_info: dict[str, Any] | None = None
        if not bb84_result.aborted and bb84_result.final_key_bytes is not None:
            # 3. Inject 256-bit BB84 key into WireGuard PresharedKey slot
            injection_info = self.wg_daemon.inject_preshared_key(
                peer_node=target_node,
                peer_public_key=peer_reg.wg_public_key,
                raw_key_32bytes=bb84_result.final_key_bytes,
                epoch=next_epoch,
            )
            self._peer_epoch[target_node] = next_epoch
            self._abort_counts[target_node] = 0
            psk_injected = True
        else:
            # 4. BB84 aborted (e.g., QBER > 11% Shor-Preskill bound): reject key rotation & increment abort count
            self._abort_counts[target_node] = self._abort_counts.get(target_node, 0) + 1

        # 5. Measure P2P overlay link metrics and send LinkTelemetry to Controller
        measured_rtt_ms = 8.0
        probe_delivery: dict[str, Any] | None = None
        peer_state = self.wg_daemon.get_peer_state(target_node)
        if peer_state is not None and peer_state.route_mode != RouteMode.QUARANTINED:
            try:
                probe_delivery = self.wg_daemon.send_overlay_packet(target_node, probe_payload)
                measured_rtt_ms = float(probe_delivery.get("rtt_ms", 8.0))
            except Exception:
                measured_rtt_ms = 95.0

        sim = simulated_underlay or {}
        latency_ms = float(sim.get("latency_ms", max(3.5, measured_rtt_ms)))
        jitter_ms = float(sim.get("jitter_ms", max(0.3, latency_ms * 0.08)))
        packet_loss_pct = float(sim.get("packet_loss_pct", 0.05))
        throughput_mbps = float(sim.get("throughput_mbps", max(50.0, 500.0 - latency_ms * 2.5 - packet_loss_pct * 25.0)))

        prev_qber = self._last_qber.get(target_node, bb84_result.measured_qber)
        qber_delta = bb84_result.measured_qber - prev_qber
        self._last_qber[target_node] = bb84_result.measured_qber

        active_epoch = self._peer_epoch.get(target_node, 0)
        handshake_age_s = (
            max(0.01, time.time() - peer_state.last_psk_rotated_at)
            if (peer_state and peer_state.last_psk_rotated_at > 0)
            else 0.5
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
            post_directive_delivery = self.wg_daemon.send_overlay_packet(
                target_node=target_node,
                payload=probe_payload,
            )

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

    def close(self) -> None:
        """Stop background BB84 responder and WireGuard UDP sockets."""
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
    peers = agent.wg_daemon.list_peers()
    inbox_msgs = agent.get_received_messages(clear=False)
    outbox_msgs = agent.get_sent_messages(clear=False)

    with agent._agent_lock:
        bb84_sessions = list(agent.bb84_history)
        if not bb84_sessions and agent.last_bb84_results:
            bb84_sessions = list(agent.last_bb84_results.values())

    lines: list[str] = []
    banner = "=" * 118
    lines.append(banner)
    lines.append(" QKD-SDWAN ENDPOINT CLIENT — INTERACTIVE CLI DASHBOARD (BB84 QKD + WIREGUARD P2P OVERLAY) ")
    lines.append(banner)
    lines.append(
        f" Node ID          : {agent.node_id:<32} | Overlay IP         : {agent.overlay_ip}"
    )
    lines.append(
        f" Controller URL   : {agent.controller_url:<32} | Timestamp          : {now_str}"
    )
    lines.append(
        f" WG UDP Endpoint  : {f'{agent.underlay_host}:{agent.wg_port}':<32} | QKD TCP Endpoint   : {agent.underlay_host}:{agent.qkd_port}"
    )
    lines.append(
        f" WG Backend Mode  : {agent.wg_daemon.backend_mode:<32} | Auth Token ID      : {agent.auth_token_id}"
    )
    lines.append(
        f" WG Public Key    : {agent.wg_daemon.public_key_b64:<32} | Relay Forwarded    : {agent.wg_daemon.relay_forwarded_packets} pkts"
    )
    lines.append("-" * 118)

    # Panel 1: WireGuard Tunnel Peers & BB84 Quantum PSK State
    lines.append("[1] P2P WIREGUARD TUNNEL PEERS & BB84 QUANTUM PSK STATE")
    peer_rows: list[list[str]] = []
    for pid, pstate in sorted(peers.items()):
        peer_rows.append(
            [
                pid,
                pstate.peer_overlay_ip,
                pstate.underlay_endpoint,
                pstate.route_mode.value,
                pstate.via_relay_node or "-",
                str(pstate.psk_epoch),
                pstate.current_psk_fingerprint or "(unkeyed)",
                f"{pstate.tx_bytes}B / {pstate.rx_bytes}B",
            ]
        )
    lines.extend(
        _format_ascii_table(
            [
                "Peer Node",
                "Overlay IP",
                "Underlay Endpoint",
                "RouteMode",
                "Via Relay",
                "PSK Epoch",
                "PSK Fingerprint",
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
        krate_str = f"{sess.key_rate_bps:.0f}"
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
                str(sess.epoch),
                photons_str,
                qber_str,
                str(sess.corrected_errors),
                krate_str,
                status_str,
            ]
        )
    lines.extend(
        _format_ascii_table(
            [
                "Session ID",
                "Peer Node",
                "Epoch",
                "Photons (Raw/Det/Sift)",
                "QBER",
                "Corrected",
                "Key Rate (bps)",
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
        dir_rows.append(
            [
                f"{d.source_node} -> {target_id}",
                d.route_mode.value,
                d.next_hop_node or "-",
                d.next_hop_endpoint or "-",
                f"{d.anomaly_score:.3f}",
                d.link_status.value,
                "YES" if d.force_rekey else "NO",
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
            agent.sync_topology()
        except Exception:
            pass
        print("\n" + render_client_dashboard(agent))
        print(
            " Actions: [r] Refresh & Sync | [k] Rekey BB84 Peer | [m] Send P2P Text | "
            "[f] Send P2P File | [s] Save Inbox File | [q] Quit"
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
    parser.add_argument("--join-token", type=str, help="Optional Join Token for automatic controller enrollment")
    parser.add_argument("--wg-port", type=int, default=None, help="WireGuard UDP listen port")
    parser.add_argument("--qkd-port", type=int, default=None, help="BB84 QKD TCP listen port")
    parser.add_argument(
        "--prefer-kernel-wg",
        action="store_true",
        help="Prefer kernel `wg set` binary when running as root with wireguard-tools installed",
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

    # subcommand: init-config
    init_p = subparsers.add_parser("init-config", help="Generate endpoint.json configuration, WireGuard keypair, and optional Join-Token enrollment")
    init_p.add_argument("--output", type=Path, required=True, help="Output path for endpoint.json")
    init_p.add_argument("--node-id", type=str, default="edge-node-01", help="Endpoint node ID (default: edge-node-01)")
    init_p.add_argument("--overlay-ip", type=str, default="10.200.0.10", help="Overlay IPv4 address (default: 10.200.0.10)")
    init_p.add_argument("--controller-url", type=str, default="http://127.0.0.1:8080", help="Central Controller base URL")
    init_p.add_argument("--join-token", type=str, default="", help="Optional Join Token for automatic enrollment")
    init_p.add_argument("--wg-port", type=int, default=51820, help="WireGuard UDP listen port (default: 51820)")
    init_p.add_argument("--qkd-port", type=int, default=52820, help="BB84 QKD TCP listen port (default: 52820)")
    init_p.add_argument("--interface", type=str, default="wg-qkd0", help="WireGuard interface name (default: wg-qkd0)")
    init_p.add_argument("--backend-mode", type=str, default="USERSPACE_CRYPTO_WG", help="WireGuard backend mode")
    init_p.add_argument("--explicit-ip", action="store_true", help="Request the explicit --overlay-ip during Join-Token enrollment")

    # subcommand: enroll
    enroll_p = subparsers.add_parser("enroll", help="Enroll this client node with the Central Controller using a Join Token")
    enroll_p.add_argument("--controller-url", default="http://127.0.0.1:8080", help="Central Controller base URL")
    enroll_p.add_argument("--join-token", required=True, help="Enrollment Join Token issued by the Controller")
    enroll_p.add_argument("--node-id", required=True, help="Unique node identifier (e.g. edge-jkt-01)")
    enroll_p.add_argument("--underlay-host", default="127.0.0.1", help="Underlay IP/hostname reachable by peers")
    enroll_p.add_argument("--overlay-ip", default=None, help="Optional requested overlay IP (auto-allocated if omitted)")
    enroll_p.add_argument("--wg-port", type=int, default=51820, help="Configured WireGuard UDP listen port")
    enroll_p.add_argument("--qkd-port", type=int, default=59100, help="Configured BB84 QKD TCP listen port")
    enroll_p.add_argument("--output-config", type=Path, default=None, help="Path to write enrolled endpoint.json config")

    # subcommand: send
    send_p = subparsers.add_parser("send", help="Send an encrypted P2P text message or file to another Client")
    send_p.add_argument("--config", type=str, default=argparse.SUPPRESS, help="Path to endpoint.json")
    send_p.add_argument("--controller-url", type=str, default=argparse.SUPPRESS, help="Override Controller URL")
    send_p.add_argument("--node-id", type=str, default=argparse.SUPPRESS, help="Override source node ID")
    send_p.add_argument("--overlay-ip", type=str, default=argparse.SUPPRESS, help="Override source overlay IP")
    send_p.add_argument("--to", required=True, dest="target_node", help="Target peer node ID")
    send_p.add_argument("--text", type=str, default=None, help="UTF-8 text message to send")
    send_p.add_argument("--file", type=Path, default=None, help="Path to file to send")

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


def _load_endpoint_config(args: argparse.Namespace) -> dict[str, Any]:
    cfg: dict[str, Any] = {}
    config_str = getattr(args, "config", None) or os.environ.get("QKD_SDWAN_CLIENT_CONFIG") or "/etc/qkd-sdwan/endpoint.json"
    if config_str:
        cfg_path = Path(config_str)
        if cfg_path.is_file():
            cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    return cfg


def _run_init_config(args: argparse.Namespace) -> int:
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    priv, pub = generate_wg_keypair()
    join_token = (getattr(args, "join_token", "") or "").strip()
    ctrl_url = str(getattr(args, "controller_url", None) or "http://127.0.0.1:8080").rstrip("/")
    node_id = str(getattr(args, "node_id", None) or "edge-node-01")
    overlay_ip = str(getattr(args, "overlay_ip", None) or "10.200.0.10")
    wg_port = int(getattr(args, "wg_port", None) or 51820)
    qkd_port = int(getattr(args, "qkd_port", None) or 52820)
    interface_name = str(getattr(args, "interface", None) or "wg-qkd0")
    backend_mode = str(getattr(args, "backend_mode", None) or "USERSPACE_CRYPTO_WG")
    explicit_ip = bool(getattr(args, "explicit_ip", False))

    hmac_secret = secrets.token_hex(32)
    auth_token_id = "hmac-sha256-cluster-v1"
    enrolled_token_id: str | None = None

    if join_token:
        try:
            req_data = {
                "join_token": join_token,
                "node_id": node_id,
                "underlay_host": "127.0.0.1",
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
                print(f"      [+] Successfully enrolled {node_id} via Join Token (allocated IP: {overlay_ip})")
        except Exception as exc:
            print(f"      [!] Controller enrollment skipped ({exc}); configuring standalone keys")

    cfg = {
        "node_id": node_id,
        "overlay_ip": overlay_ip,
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
    cfg = _load_endpoint_config(args)
    node_id = getattr(args, "node_id", None) or cfg.get("node_id", "edge-local-01")
    overlay_ip = getattr(args, "overlay_ip", None) or cfg.get("overlay_ip", "10.200.0.10")
    controller_url = getattr(args, "controller_url", None) or cfg.get("controller_url", "http://127.0.0.1:8080")
    underlay_host = cfg.get("underlay_host", "127.0.0.1")
    raw_wg_port = getattr(args, "wg_port", None)
    wg_port = int(raw_wg_port) if raw_wg_port is not None else int(cfg.get("wg_port", 0))
    raw_qkd_port = getattr(args, "qkd_port", None)
    qkd_port = int(raw_qkd_port) if raw_qkd_port is not None else int(cfg.get("qkd_port", 0))
    secret_hex = cfg.get("cluster_hmac_secret_hex")
    auth_secret = bytes.fromhex(secret_hex) if secret_hex else b"qkd-sdwan-default-hmac-secret"

    join_token = getattr(args, "join_token", None)
    if join_token:
        agent, _ = SDWANEndpointAgent.enroll_with_controller(
            controller_url=controller_url,
            join_token=join_token,
            node_id=node_id,
            underlay_host=underlay_host,
            wg_port=wg_port,
            qkd_port=qkd_port,
            overlay_ip=getattr(args, "overlay_ip", None),
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


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    sub = getattr(args, "subcommand", None)

    if sub == "init-config":
        return _run_init_config(args)

    if sub == "enroll":
        agent, enroll_resp = SDWANEndpointAgent.enroll_with_controller(
            controller_url=args.controller_url,
            join_token=args.join_token,
            node_id=args.node_id,
            underlay_host=args.underlay_host,
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
            agent.close()
        return 0

    if getattr(args, "check_config", False):
        cfg = _load_endpoint_config(args)
        node_id = args.node_id or cfg.get("node_id", "edge-local-01")
        overlay_ip = args.overlay_ip or cfg.get("overlay_ip", "10.200.0.10")
        controller_url = args.controller_url or cfg.get("controller_url", "http://127.0.0.1:8080")
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

    if sub == "send":
        if not args.text and not args.file:
            raise SystemExit("Error: specify either --text or --file for 'send'")
        agent = _build_agent_from_args(args)
        try:
            agent.register_with_controller()
            agent.sync_topology()
            if args.file:
                res = agent.send_p2p_file(args.target_node, args.file)
            else:
                res = agent.send_p2p_text(args.target_node, str(args.text))
            print(json.dumps(res, indent=2))
        finally:
            agent.close()
        return 0

    if sub == "status":
        agent = _build_agent_from_args(args)
        try:
            agent.register_with_controller()
            topo = agent.sync_topology()
            payload = {
                "node_id": agent.node_id,
                "overlay_ip": agent.overlay_ip,
                "controller_url": agent.controller_url,
                "wg_port": agent.wg_port,
                "qkd_port": agent.qkd_port,
                "wg_public_key": agent.wg_daemon.public_key_b64,
                "peers": topo.get("peers", []),
                "directives": topo.get("directives", []),
            }
            print(json.dumps(payload, indent=2))
        finally:
            agent.close()
        return 0

    if sub == "dashboard" or getattr(args, "dashboard", False):
        agent = _build_agent_from_args(args)
        try:
            try:
                agent.register_with_controller()
                agent.sync_topology()
            except Exception:
                pass
            if getattr(args, "once", False):
                print(render_client_dashboard(agent))
                return 0
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
            agent.close()

    if sub == "console":
        agent = _build_agent_from_args(args)
        try:
            agent.register_with_controller()
            agent.sync_topology()
            return _run_console(agent)
        finally:
            agent.close()

    agent = _build_agent_from_args(args)
    try:
        agent.register_with_controller()
        print(f"[qkd-sdwan-agent] Registered {agent.node_id} ({agent.overlay_ip}) with {agent.controller_url}")
    finally:
        agent.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
