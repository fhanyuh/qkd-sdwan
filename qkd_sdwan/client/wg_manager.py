"""WireGuard P2P tunnel daemon and 256-bit BB84 PresharedKey (PSK) injector."""

from __future__ import annotations

import base64
from collections.abc import Callable
from dataclasses import asdict, dataclass
import hashlib
import json
import os
import secrets
import shutil
import socket
import subprocess
import threading
import time
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from qkd_sdwan.common.models import P2PDataMessage, RouteDirective, RouteMode


def generate_wg_keypair() -> tuple[str, str]:
    """Generate a WireGuard-compatible Curve25519 (X25519) keypair encoded as 44-char Base64 strings."""
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key()
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(priv_bytes).decode("ascii"), base64.b64encode(pub_bytes).decode("ascii")


@dataclass
class PeerTunnelState:
    """State of a P2P WireGuard overlay tunnel with a specific peer."""

    peer_node: str
    peer_public_key: str
    peer_overlay_ip: str
    underlay_endpoint: str
    route_mode: RouteMode
    via_relay_node: str | None
    current_psk_b64: str | None
    current_psk_fingerprint: str | None
    psk_epoch: int
    last_psk_rotated_at: float
    tx_bytes: int
    rx_bytes: int

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["current_psk_b64"] = "<redacted>" if self.current_psk_b64 else None
        data["route_mode"] = self.route_mode.value if isinstance(self.route_mode, RouteMode) else str(self.route_mode)
        return data


class WireGuardTunnelDaemon:
    """Manage P2P WireGuard tunnels, BB84 256-bit PSK injection, and AEAD overlay transport."""

    def __init__(
        self,
        node_id: str,
        interface_name: str,
        overlay_ip: str,
        listen_port: int,
        private_key_b64: str | None = None,
        prefer_kernel_wg: bool = False,
        bind_host: str = "127.0.0.1",
    ) -> None:
        self.node_id = node_id
        self.interface_name = interface_name
        self.overlay_ip = overlay_ip
        self.listen_port = listen_port
        self.bind_host = bind_host

        if private_key_b64 is None:
            priv_b64, pub_b64 = generate_wg_keypair()
            self.private_key_b64 = priv_b64
            self.public_key_b64 = pub_b64
        else:
            self.private_key_b64 = private_key_b64
            priv_raw = base64.b64decode(private_key_b64.encode("ascii"))
            priv_obj = x25519.X25519PrivateKey.from_private_bytes(priv_raw)
            pub_raw = priv_obj.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            self.public_key_b64 = base64.b64encode(pub_raw).decode("ascii")

        self._x25519_priv = x25519.X25519PrivateKey.from_private_bytes(
            base64.b64decode(self.private_key_b64.encode("ascii"))
        )

        has_wg_binary = shutil.which("wg") is not None
        is_root = hasattr(os, "geteuid") and os.geteuid() == 0
        if prefer_kernel_wg and has_wg_binary and is_root:
            self.backend_mode = "KERNEL_WG"
        else:
            self.backend_mode = "USERSPACE_CRYPTO_WG"

        self._lock = threading.RLock()
        self._send_lock = threading.Lock()
        self._peers: dict[str, PeerTunnelState] = {}
        self._direct_endpoints: dict[str, str] = {}
        self._session_aead_keys: dict[str, bytes] = {}
        self._pending_acks: dict[str, tuple[threading.Event, dict[str, Any]]] = {}
        self._inbox_messages: list[P2PDataMessage] = []
        self._outbox_messages: list[P2PDataMessage] = []
        self._seen_packet_ids: list[str] = []
        self._seen_packet_set: set[str] = set()
        self._message_callbacks: list[Callable[[P2PDataMessage], None]] = []
        self.relay_forwarded_packets: int = 0
        self.auth_failure_count: int = 0
        self._stop_event = threading.Event()
        self._udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            if os.name != "nt":
                self._udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                self._udp_sock.bind(("0.0.0.0", self.listen_port))
            except OSError:
                if self.listen_port != 0:
                    self._udp_sock.bind(("0.0.0.0", 0))
                else:
                    raise
                try:
                    self._udp_sock.ioctl(socket.SIO_UDP_CONNRESET, False)
                except OSError:
                    pass
            self._udp_sock.settimeout(0.2)
            self._bound_port = self._udp_sock.getsockname()[1]
        except Exception:
            self._udp_sock.close()
            raise
        self.listen_port = self._bound_port

        self._listener_thread = threading.Thread(
            target=self._udp_receive_loop,
            name=f"wg-udp-{self.node_id}",
            daemon=True,
        )
        self._listener_thread.start()

    @property
    def bound_port(self) -> int:
        return self._bound_port

    def register_message_callback(self, callback: Callable[[P2PDataMessage], None]) -> None:
        """Register a callback invoked whenever an encrypted application P2PDataMessage arrives."""
        with self._lock:
            self._message_callbacks.append(callback)

    def get_inbox_messages(self, clear: bool = False) -> list[P2PDataMessage]:
        """Return received P2P application messages (optionally clearing the inbox)."""
        with self._lock:
            items = list(self._inbox_messages)
            if clear:
                self._inbox_messages.clear()
            return items

    def record_outbox_message(self, msg: P2PDataMessage) -> None:
        """Record a sent P2PDataMessage in the local outbox history."""
        with self._lock:
            self._outbox_messages.append(msg)

    def get_outbox_messages(self, clear: bool = False) -> list[P2PDataMessage]:
        """Return sent P2P application messages (optionally clearing the outbox)."""
        with self._lock:
            items = list(self._outbox_messages)
            if clear:
                self._outbox_messages.clear()
            return items
    @staticmethod
    def _parse_endpoint(endpoint: str) -> tuple[str, int]:
        host, port_str = endpoint.rsplit(":", 1)
        clean_host = host.strip()
        norm_host = "127.0.0.1" if clean_host in ("0.0.0.0", "::", "") else clean_host
        return norm_host, int(port_str)

    def _derive_session_aead_key(self, peer_public_key_b64: str, raw_psk_32bytes: bytes) -> bytes:
        peer_pub_raw = base64.b64decode(peer_public_key_b64.encode("ascii"))
        peer_pub = x25519.X25519PublicKey.from_public_bytes(peer_pub_raw)
        shared_secret = self._x25519_priv.exchange(peer_pub)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=raw_psk_32bytes,
            info=b"wg-qkd-p2p-aead",
        )
        return hkdf.derive(shared_secret)

    def register_peer(
        self,
        peer_node: str,
        peer_public_key: str,
        peer_overlay_ip: str,
        underlay_endpoint: str,
    ) -> PeerTunnelState:
        """Register or update a peer in the WireGuard tunnel table."""
        with self._lock:
            existing_ep = self._direct_endpoints.get(peer_node)
            preserve_roamed = False
            if existing_ep and existing_ep != underlay_endpoint:
                try:
                    ex_h, ex_p = self._parse_endpoint(existing_ep)
                    _new_h, new_p = self._parse_endpoint(underlay_endpoint)
                    if ex_p > 0 and ex_p != new_p and ex_h not in ("127.0.0.1", "::1", "0.0.0.0"):
                        preserve_roamed = True
                except Exception:
                    pass
            if not preserve_roamed:
                self._direct_endpoints[peer_node] = underlay_endpoint
            if peer_node in self._peers:
                state = self._peers[peer_node]
                state.peer_public_key = peer_public_key
                state.peer_overlay_ip = peer_overlay_ip
                if state.route_mode == RouteMode.DIRECT_P2P and not preserve_roamed:
                    state.underlay_endpoint = underlay_endpoint
                return state

            default_aead = self._derive_session_aead_key(peer_public_key, b"\x00" * 32)
            self._session_aead_keys[peer_node] = default_aead
            state = PeerTunnelState(
                peer_node=peer_node,
                peer_public_key=peer_public_key,
                peer_overlay_ip=peer_overlay_ip,
                underlay_endpoint=underlay_endpoint,
                route_mode=RouteMode.DIRECT_P2P,
                via_relay_node=None,
                current_psk_b64=None,
                current_psk_fingerprint=None,
                psk_epoch=0,
                last_psk_rotated_at=0.0,
                tx_bytes=0,
                rx_bytes=0,
            )
            self._peers[peer_node] = state
            return state

    def get_peer_state(self, peer_node: str) -> PeerTunnelState | None:
        with self._lock:
            return self._peers.get(peer_node)

    def list_peers(self) -> dict[str, PeerTunnelState]:
        with self._lock:
            return dict(self._peers)

    def inject_preshared_key(
        self,
        peer_node: str,
        peer_public_key: str,
        raw_key_32bytes: bytes,
        epoch: int,
    ) -> dict[str, Any]:
        """Inject a 32-byte (256-bit) BB84 symmetric key into the WireGuard PresharedKey slot."""
        if not isinstance(raw_key_32bytes, (bytes, bytearray)) or len(raw_key_32bytes) != 32:
            raise ValueError("WireGuard PSK must be exactly 32 bytes (256 bits)")

        raw_key = bytes(raw_key_32bytes)
        psk_b64 = base64.b64encode(raw_key).decode("ascii")
        psk_fingerprint = hashlib.sha256(raw_key).hexdigest()[:16]
        wg_cmd = [
            "wg",
            "set",
            self.interface_name,
            "peer",
            peer_public_key,
            "preshared-key",
            "/dev/stdin",
        ]

        if self.backend_mode == "KERNEL_WG":
            subprocess.run(wg_cmd, input=psk_b64.encode("ascii"), check=True, capture_output=True)

        aead_key = self._derive_session_aead_key(peer_public_key, raw_key)
        rotated_at = time.time()

        with self._lock:
            if peer_node not in self._peers:
                self.register_peer(
                    peer_node=peer_node,
                    peer_public_key=peer_public_key,
                    peer_overlay_ip="0.0.0.0",
                    underlay_endpoint=f"{self.bind_host}:0",
                )
            state = self._peers[peer_node]
            state.peer_public_key = peer_public_key
            state.current_psk_b64 = psk_b64
            state.current_psk_fingerprint = psk_fingerprint
            state.psk_epoch = epoch
            state.last_psk_rotated_at = rotated_at
            self._session_aead_keys[peer_node] = aead_key

        return {
            "node_id": self.node_id,
            "peer_node": peer_node,
            "interface": self.interface_name,
            "backend_mode": self.backend_mode,
            "wg_command": " ".join(wg_cmd),
            "psk_epoch": epoch,
            "psk_fingerprint_sha256": psk_fingerprint,
            "rotated_at": rotated_at,
        }

    def apply_route_directive(self, directive: RouteDirective) -> bool:
        """Apply a Controller RouteDirective (DIRECT_P2P, RELAY_P2P, or QUARANTINED) for a target peer."""
        if directive.source_node != self.node_id:
            return False

        with self._lock:
            state = self._peers.get(directive.target_node)
            if state is None:
                return False

            state.route_mode = directive.route_mode
            if directive.route_mode == RouteMode.DIRECT_P2P:
                direct_ep = self._direct_endpoints.get(directive.target_node, directive.next_hop_endpoint)
                state.underlay_endpoint = direct_ep
                state.via_relay_node = None
            elif directive.route_mode == RouteMode.RELAY_P2P:
                state.underlay_endpoint = directive.next_hop_endpoint
                state.via_relay_node = directive.next_hop_node
            elif directive.route_mode == RouteMode.QUARANTINED:
                state.via_relay_node = None
            return True

    def send_overlay_packet(
        self,
        target_node: str,
        payload: bytes,
        timeout: float = 2.0,
        max_retries: int = 3,
        allow_quarantined_probe: bool = False,
        relay_endpoint_override: str | None = None,
        relay_node_override: str | None = None,
    ) -> dict[str, Any]:
        """Encrypt and transmit an overlay data-plane packet over UDP (direct or P2P relay) with auto-retry."""
        with self._lock:
            state = self._peers.get(target_node)
            if state is None:
                raise KeyError(f"Unknown WireGuard peer: {target_node}")
            if state.route_mode == RouteMode.QUARANTINED and not allow_quarantined_probe:
                raise PermissionError(f"Link {self.node_id} -> {target_node} is QUARANTINED due to security policy")
            aead_key = self._session_aead_keys.get(target_node)
            if aead_key is None:
                raise PermissionError(f"No active WireGuard AEAD session key for peer {target_node}")

            if relay_endpoint_override and relay_node_override:
                route_mode = RouteMode.RELAY_P2P
                via_relay = relay_node_override
                next_hop_ep = relay_endpoint_override
            elif state.route_mode == RouteMode.QUARANTINED:
                route_mode = RouteMode.DIRECT_P2P
                via_relay = None
                next_hop_ep = self._direct_endpoints.get(target_node, state.underlay_endpoint)
            else:
                route_mode = state.route_mode
                via_relay = state.via_relay_node
                next_hop_ep = state.underlay_endpoint
            direct_ep = self._direct_endpoints.get(target_node, state.underlay_endpoint)
            psk_epoch = state.psk_epoch
            psk_fingerprint = state.current_psk_fingerprint
        packet_id = secrets.token_hex(8)
        nonce = secrets.token_bytes(12)
        aad_obj = {
            "psk_epoch": psk_epoch,
            "source_node": self.node_id,
            "target_node": target_node,
        }
        aad = json.dumps(aad_obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
        cipher = ChaCha20Poly1305(aead_key)
        ciphertext = cipher.encrypt(nonce, payload, aad)

        envelope = {
            "type": "WG_DATA",
            "packet_id": packet_id,
            "source_node": self.node_id,
            "target_node": target_node,
            "route_mode": route_mode.value,
            "via_relay_node": via_relay,
            "final_endpoint": direct_ep,
            "origin_endpoint": f"{self.bind_host}:{self._bound_port}",
            "psk_epoch": psk_epoch,
            "nonce_b64": base64.b64encode(nonce).decode("ascii"),
            "aad_b64": base64.b64encode(aad).decode("ascii"),
            "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
        }
        raw_datagram = json.dumps(envelope, separators=(",", ":")).encode("utf-8")

        ack_event = threading.Event()
        ack_holder: dict[str, Any] = {}
        with self._lock:
            self._pending_acks[packet_id] = (ack_event, ack_holder)

        max_attempts = max(1, int(max_retries))
        per_attempt_timeout = max(0.15, float(timeout) / max_attempts)
        start_ts = time.perf_counter()
        try:
            dest_host, dest_port = self._parse_endpoint(next_hop_ep)
            for _attempt in range(1, max_attempts + 1):
                with self._send_lock:
                    self._udp_sock.sendto(raw_datagram, (dest_host, dest_port))
                with self._lock:
                    self._peers[target_node].tx_bytes += len(raw_datagram)
                if ack_event.wait(timeout=per_attempt_timeout):
                    break

            if not ack_event.is_set():
                raise TimeoutError(
                    f"WireGuard overlay packet to {target_node} timed out after {timeout}s ({max_attempts} attempts)"
                )

            rtt_ms = (time.perf_counter() - start_ts) * 1000.0
            if ack_holder.get("type") == "WG_AUTH_FAIL":
                if allow_quarantined_probe:
                    return {
                        "status": "AUTH_PROBE_REPLY",
                        "delivered": False,
                        "reachable": True,
                        "packet_id": packet_id,
                        "source_node": self.node_id,
                        "target_node": target_node,
                        "route_mode": route_mode.value,
                        "via_relay_node": ack_holder.get("relayed_by") or via_relay,
                        "psk_epoch": psk_epoch,
                        "psk_fingerprint": psk_fingerprint,
                        "rtt_ms": rtt_ms,
                        "payload_bytes": len(payload),
                        "wire_bytes": len(raw_datagram),
                    }
                raise PermissionError(
                    f"WireGuard AEAD decryption failed at {target_node}: {ack_holder.get('reason', 'PSK_MISMATCH')}"
                )

            return {
                "status": "DELIVERED",
                "delivered": True,
                "packet_id": packet_id,
                "source_node": self.node_id,
                "target_node": target_node,
                "route_mode": route_mode.value,
                "via_relay_node": ack_holder.get("relayed_by") or via_relay,
                "psk_epoch": psk_epoch,
                "psk_fingerprint": psk_fingerprint,
                "rtt_ms": rtt_ms,
                "payload_bytes": len(payload),
                "wire_bytes": len(raw_datagram),
            }
        finally:
            with self._lock:
                self._pending_acks.pop(packet_id, None)

    def _send_unkeyed_ping_probe(self, target_node: str, timeout: float = 0.6) -> tuple[float, int]:
        """Send a lightweight UDP WG_PING probe to target_node and wait for WG_ACK when AEAD session is unavailable."""
        with self._lock:
            state = self._peers.get(target_node)
            if state is None:
                raise KeyError(f"Unknown WireGuard peer: {target_node}")
            ep = self._direct_endpoints.get(target_node) or state.underlay_endpoint
        if not ep or ep.endswith(":0"):
            raise TimeoutError(f"No valid endpoint for peer {target_node}")
        dest_host, dest_port = self._parse_endpoint(ep)
        if dest_port <= 0:
            raise TimeoutError(f"Invalid port for peer {target_node}: {ep}")

        packet_id = secrets.token_hex(8)
        ping_pkt = json.dumps(
            {
                "type": "WG_PING",
                "packet_id": packet_id,
                "source_node": self.node_id,
                "target_node": target_node,
                "timestamp": time.time(),
            },
            separators=(",", ":"),
        ).encode("utf-8")

        ack_event = threading.Event()
        ack_holder: dict[str, Any] = {}
        with self._lock:
            self._pending_acks[packet_id] = (ack_event, ack_holder)
        start_ts = time.perf_counter()
        try:
            with self._send_lock:
                self._udp_sock.sendto(ping_pkt, (dest_host, dest_port))
            with self._lock:
                if target_node in self._peers:
                    self._peers[target_node].tx_bytes += len(ping_pkt)
            if not ack_event.wait(timeout=max(0.1, float(timeout))):
                raise TimeoutError(f"UDP WG_PING to {target_node} timed out after {timeout}s")
            rtt_ms = (time.perf_counter() - start_ts) * 1000.0
            return rtt_ms, len(ping_pkt) + 128
        finally:
            with self._lock:
                self._pending_acks.pop(packet_id, None)

    def probe_peer_link(
        self,
        target_node: str,
        count: int = 3,
        timeout: float = 0.6,
        probe_payload: bytes = b"QKD-SDWAN-P2P-PROBE",
    ) -> dict[str, Any]:
        """Measure real peer link RTT, jitter, packet loss, and wire throughput via multi-packet UDP probes."""
        sent = max(1, int(count))
        rtts: list[float] = []
        total_wire_bytes = 0
        last_delivery: dict[str, Any] | None = None

        with self._lock:
            relay_fallbacks: list[tuple[str, str]] = [
                (pid, self._direct_endpoints.get(pid, pstate.underlay_endpoint))
                for pid, pstate in self._peers.items()
                if pid != target_node and pstate.route_mode != RouteMode.QUARANTINED
            ]

        for _ in range(sent):
            probed_ok = False
            try:
                res = self.send_overlay_packet(
                    target_node=target_node,
                    payload=probe_payload,
                    timeout=timeout,
                    max_retries=1,
                    allow_quarantined_probe=True,
                )
                rtt = float(res["rtt_ms"])
                rtts.append(rtt)
                total_wire_bytes += int(res.get("wire_bytes", len(probe_payload) + 256)) + 160
                last_delivery = res
                probed_ok = True
            except PermissionError:
                try:
                    rtt, wbytes = self._send_unkeyed_ping_probe(target_node, timeout=timeout)
                    rtts.append(rtt)
                    total_wire_bytes += wbytes
                    probed_ok = True
                except Exception:
                    pass
            except Exception:
                pass

            if not probed_ok and relay_fallbacks:
                for rel_node, rel_ep in relay_fallbacks:
                    if not rel_ep or rel_ep.endswith(":0"):
                        continue
                    try:
                        res = self.send_overlay_packet(
                            target_node=target_node,
                            payload=probe_payload,
                            timeout=timeout,
                            max_retries=1,
                            allow_quarantined_probe=True,
                            relay_endpoint_override=rel_ep,
                            relay_node_override=rel_node,
                        )
                        rtt = float(res["rtt_ms"])
                        rtts.append(rtt)
                        total_wire_bytes += int(res.get("wire_bytes", len(probe_payload) + 256)) + 160
                        last_delivery = res
                        break
                    except Exception:
                        continue

        received = len(rtts)
        packet_loss_pct = round(((sent - received) / float(sent)) * 100.0, 2)
        if received == 0:
            return {
                "reachable": False,
                "latency_ms": 0.0,
                "jitter_ms": 0.0,
                "packet_loss_pct": 100.0,
                "throughput_mbps": 0.0,
                "probes_sent": sent,
                "probes_received": 0,
                "last_delivery": None,
            }

        latency_ms = round(sum(rtts) / float(received), 3)
        if received > 1:
            jitter_ms = round(
                sum(abs(rtts[i] - rtts[i - 1]) for i in range(1, received)) / float(received - 1),
                3,
            )
        else:
            jitter_ms = 0.0

        total_wire_bits = float(total_wire_bytes) * 8.0
        total_sec = sum(rtts) / 1000.0
        throughput_mbps = round((total_wire_bits / max(1e-6, total_sec)) / 1e6, 3)
        return {
            "reachable": True,
            "latency_ms": latency_ms,
            "jitter_ms": jitter_ms,
            "packet_loss_pct": packet_loss_pct,
            "throughput_mbps": throughput_mbps,
            "probes_sent": sent,
            "probes_received": received,
            "last_delivery": last_delivery,
        }
    def send_keepalive(self, peer_node: str | None = None) -> int:
        """Send lightweight UDP keepalive datagrams to registered peers to maintain NAT port mappings."""
        with self._lock:
            targets: list[tuple[str, str]] = []
            for pid, state in self._peers.items():
                if peer_node is not None and pid != peer_node:
                    continue
                if state.route_mode == RouteMode.QUARANTINED:
                    continue
                ep = state.underlay_endpoint or self._direct_endpoints.get(pid)
                if ep and not ep.endswith(":0"):
                    targets.append((pid, ep))

        sent_count = 0
        for _pid, ep in targets:
            try:
                dest_host, dest_port = self._parse_endpoint(ep)
                if dest_port <= 0:
                    continue
                pkt = json.dumps(
                    {
                        "type": "WG_KEEPALIVE",
                        "source_node": self.node_id,
                        "timestamp": time.time(),
                    },
                    separators=(",", ":"),
                ).encode("utf-8")
                with self._send_lock:
                    self._udp_sock.sendto(pkt, (dest_host, dest_port))
                sent_count += 1
            except Exception:
                pass
        return sent_count

    def _udp_receive_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                datagram, sender_addr = self._udp_sock.recvfrom(65535)
            except (socket.timeout, TimeoutError, ConnectionResetError):
                continue
            except OSError:
                break

            try:
                msg = json.loads(datagram.decode("utf-8"))
            except Exception:
                continue

            msg_type = msg.get("type")
            if msg_type in ("WG_ACK", "WG_AUTH_FAIL"):
                self._handle_ack_or_fail(msg, datagram)
            elif msg_type == "WG_DATA":
                self._handle_data_packet(msg, datagram, sender_addr)
            elif msg_type == "WG_PING":
                src_id = str(msg.get("source_node", "")).strip()
                pkt_id = str(msg.get("packet_id", "")).strip()
                if src_id and sender_addr[0] not in ("127.0.0.1", "::1", "0.0.0.0"):
                    live_ep = f"{sender_addr[0]}:{sender_addr[1]}"
                    with self._lock:
                        self._direct_endpoints[src_id] = live_ep
                        if src_id in self._peers and self._peers[src_id].route_mode == RouteMode.DIRECT_P2P:
                            self._peers[src_id].underlay_endpoint = live_ep
                ack_pkt = json.dumps(
                    {
                        "type": "WG_ACK",
                        "packet_id": pkt_id,
                        "source_node": src_id,
                        "responder_node": self.node_id,
                        "timestamp": time.time(),
                    },
                    separators=(",", ":"),
                ).encode("utf-8")
                with self._send_lock:
                    self._udp_sock.sendto(ack_pkt, sender_addr)
                continue
            elif msg_type == "WG_KEEPALIVE":
                src_id = str(msg.get("source_node", "")).strip()
                if src_id and sender_addr[0] not in ("127.0.0.1", "::1", "0.0.0.0"):
                    live_ep = f"{sender_addr[0]}:{sender_addr[1]}"
                    with self._lock:
                        self._direct_endpoints[src_id] = live_ep
                        if src_id in self._peers and self._peers[src_id].route_mode == RouteMode.DIRECT_P2P:
                            self._peers[src_id].underlay_endpoint = live_ep
                continue

    def _handle_ack_or_fail(self, msg: dict[str, Any], raw_datagram: bytes) -> None:
        target_origin = msg.get("source_node")
        if target_origin and target_origin != self.node_id:
            with self._lock:
                learned_ep = self._direct_endpoints.get(str(target_origin))
            origin_ep = msg.get("relay_return_endpoint") or learned_ep or msg.get("origin_endpoint")
            if origin_ep:
                host, port = self._parse_endpoint(str(origin_ep))
                with self._send_lock:
                    self._udp_sock.sendto(raw_datagram, (host, port))
            return
        packet_id = str(msg.get("packet_id", ""))
        with self._lock:
            entry = self._pending_acks.get(packet_id)
            peer_node = str(msg.get("responder_node", ""))
            if peer_node in self._peers:
                self._peers[peer_node].rx_bytes += len(raw_datagram)
            if entry is not None:
                ev, holder = entry
                holder.update(msg)
                ev.set()

    def _record_decrypted_payload(self, msg: dict[str, Any], plaintext: bytes) -> None:
        if plaintext.startswith((b"QKD-SDWAN-P2P-PROBE", b"SCENARIO-")):
            return
        relayed_by = msg.get("relayed_by")
        effective_mode = "RELAY_P2P" if relayed_by else str(msg.get("route_mode", "DIRECT_P2P"))
        app_msg: P2PDataMessage | None = None

        try:
            decoded_json = json.loads(plaintext.decode("utf-8"))
            if isinstance(decoded_json, dict) and decoded_json.get("type") == "P2P_APP_MESSAGE":
                inner = dict(decoded_json.get("message", {}))
                inner["via_relay_node"] = relayed_by or inner.get("via_relay_node")
                inner["route_mode"] = effective_mode
                app_msg = P2PDataMessage.from_dict(inner)
        except Exception:
            app_msg = None

        if app_msg is None:
            app_msg = P2PDataMessage(
                message_id=str(msg.get("packet_id", secrets.token_hex(6))),
                source_node=str(msg.get("source_node", "")),
                target_node=self.node_id,
                content_type="raw",
                filename=None,
                payload_b64=base64.b64encode(plaintext).decode("ascii"),
                psk_epoch=int(msg.get("psk_epoch", 0)),
                route_mode=effective_mode,
                via_relay_node=str(relayed_by) if relayed_by else None,
                timestamp=time.time(),
            )
        if not app_msg.verify_integrity():
            return

        with self._lock:
            self._inbox_messages.append(app_msg)
            callbacks = list(self._message_callbacks)

        for cb in callbacks:
            try:
                cb(app_msg)
            except Exception:
                pass
    def _handle_data_packet(
        self,
        msg: dict[str, Any],
        raw_datagram: bytes,
        sender_addr: tuple[str, int],
    ) -> None:
        target_node = str(msg.get("target_node", ""))
        source_node = str(msg.get("source_node", ""))
        packet_id = str(msg.get("packet_id", ""))

        if target_node != self.node_id:
            with self._lock:
                self.relay_forwarded_packets += 1
                if source_node in self._peers:
                    self._peers[source_node].rx_bytes += len(raw_datagram)
                if target_node in self._peers:
                    self._peers[target_node].tx_bytes += len(raw_datagram)
                final_ep = self._direct_endpoints.get(target_node) or msg.get("final_endpoint")

            if final_ep:
                msg["relayed_by"] = self.node_id
                msg["relay_return_endpoint"] = f"{sender_addr[0]}:{sender_addr[1]}"
                forwarded_bytes = json.dumps(msg, separators=(",", ":")).encode("utf-8")
                dest_host, dest_port = self._parse_endpoint(str(final_ep))
                with self._send_lock:
                    self._udp_sock.sendto(forwarded_bytes, (dest_host, dest_port))
            return
        with self._lock:
            aead_key = self._session_aead_keys.get(source_node)
            if source_node in self._peers:
                self._peers[source_node].rx_bytes += len(raw_datagram)

        nonce = base64.b64decode(str(msg.get("nonce_b64", "")).encode("ascii"))
        aad = base64.b64decode(str(msg.get("aad_b64", "")).encode("ascii"))
        ciphertext = base64.b64decode(str(msg.get("ciphertext_b64", "")).encode("ascii"))

        reply_ep = msg.get("origin_endpoint")
        reply_addr = self._parse_endpoint(str(reply_ep)) if reply_ep else sender_addr
        if msg.get("relayed_by"):
            reply_addr = sender_addr
        elif reply_addr[1] <= 0:
            reply_addr = sender_addr
        elif reply_addr[0] == "127.0.0.1" and sender_addr[0] not in ("127.0.0.1", "::1"):
            reply_addr = (sender_addr[0], reply_addr[1])
        if aead_key is None:
            with self._lock:
                self.auth_failure_count += 1
            fail_pkt = {
                "type": "WG_AUTH_FAIL",
                "packet_id": packet_id,
                "source_node": source_node,
                "responder_node": self.node_id,
                "origin_endpoint": msg.get("origin_endpoint"),
                "relay_return_endpoint": msg.get("relay_return_endpoint"),
                "relayed_by": msg.get("relayed_by"),
                "reason": "UNKNOWN_PEER_SESSION",
            }
            with self._send_lock:
                self._udp_sock.sendto(json.dumps(fail_pkt).encode("utf-8"), reply_addr)
            return

        try:
            cipher = ChaCha20Poly1305(aead_key)
            _plaintext = cipher.decrypt(nonce, ciphertext, aad)
        except InvalidTag:
            with self._lock:
                self.auth_failure_count += 1
            fail_pkt = {
                "type": "WG_AUTH_FAIL",
                "packet_id": packet_id,
                "source_node": source_node,
                "responder_node": self.node_id,
                "origin_endpoint": msg.get("origin_endpoint"),
                "relay_return_endpoint": msg.get("relay_return_endpoint"),
                "relayed_by": msg.get("relayed_by"),
                "reason": "PSK_AEAD_TAG_MISMATCH",
            }
            with self._send_lock:
                self._udp_sock.sendto(json.dumps(fail_pkt).encode("utf-8"), reply_addr)
            return


        if not msg.get("relayed_by"):
            live_endpoint = f"{sender_addr[0]}:{sender_addr[1]}"
            if sender_addr[0] not in ("127.0.0.1", "::1", "0.0.0.0"):
                with self._lock:
                    self._direct_endpoints[source_node] = live_endpoint
                    if source_node in self._peers and self._peers[source_node].route_mode == RouteMode.DIRECT_P2P:
                        self._peers[source_node].underlay_endpoint = live_endpoint
                reply_addr = sender_addr
            else:
                with self._lock:
                    if source_node in self._peers and self._peers[source_node].underlay_endpoint.endswith(":0"):
                        self._direct_endpoints[source_node] = live_endpoint
                        if self._peers[source_node].route_mode == RouteMode.DIRECT_P2P:
                            self._peers[source_node].underlay_endpoint = live_endpoint
        is_duplicate = False
        with self._lock:
            if packet_id and packet_id in self._seen_packet_set:
                is_duplicate = True
            elif packet_id:
                self._seen_packet_set.add(packet_id)
                self._seen_packet_ids.append(packet_id)
                if len(self._seen_packet_ids) > 2048:
                    oldest = self._seen_packet_ids.pop(0)
                    self._seen_packet_set.discard(oldest)

        if not is_duplicate:
            self._record_decrypted_payload(msg, _plaintext)

        ack_pkt = {
            "type": "WG_ACK",
            "packet_id": packet_id,
            "source_node": source_node,
            "responder_node": self.node_id,
            "origin_endpoint": msg.get("origin_endpoint"),
            "relay_return_endpoint": msg.get("relay_return_endpoint"),
            "relayed_by": msg.get("relayed_by"),
            "timestamp": time.time(),
        }
        ack_bytes = json.dumps(ack_pkt, separators=(",", ":")).encode("utf-8")
        with self._lock:
            if source_node in self._peers:
                self._peers[source_node].tx_bytes += len(ack_bytes)
        with self._send_lock:
            self._udp_sock.sendto(ack_bytes, reply_addr)
    def close(self) -> None:
        """Stop the UDP listener thread and close the underlying socket."""
        self._stop_event.set()
        try:
            self._udp_sock.close()
        except OSError:
            pass
        if self._listener_thread.is_alive():
            self._listener_thread.join(timeout=0.5)
