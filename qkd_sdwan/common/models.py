"""Shared data models and protocol schemas for the QKD-SDWAN PoC."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from enum import Enum
import hashlib
import hmac
import time
from typing import Any

class LinkStatus(str, Enum):
    """Security and underlay health classification for a P2P SD-WAN link."""

    HEALTHY = "HEALTHY"
    DEGRADED_UNDERLAY = "DEGRADED_UNDERLAY"
    EAVESDROPPING_SUSPECTED = "EAVESDROPPING_SUSPECTED"
    COMPROMISED_BLOCKED = "COMPROMISED_BLOCKED"
    OFFLINE_DOWN = "OFFLINE_DOWN"


class RouteMode(str, Enum):
    """Overlay forwarding mode for a P2P SD-WAN endpoint pair."""

    DIRECT_P2P = "DIRECT_P2P"
    RELAY_P2P = "RELAY_P2P"
    QUARANTINED = "QUARANTINED"


def _require_field(cls_name: str, data: dict[str, Any], field: str) -> Any:
    if not isinstance(data, dict) or field not in data or data[field] is None:
        raise ValueError(f"Missing or invalid field in {cls_name}: {field}")
    val = data[field]
    if isinstance(val, str) and not val.strip():
        raise ValueError(f"Missing or invalid field in {cls_name}: {field}")
    return val


def _coerce_str(cls_name: str, data: dict[str, Any], field: str, allow_empty: bool = False) -> str:
    if not isinstance(data, dict) or field not in data or data[field] is None:
        raise ValueError(f"Missing or invalid field in {cls_name}: {field}")
    val = data[field]
    if not isinstance(val, str):
        raise ValueError(f"Missing or invalid field in {cls_name}: {field}")
    if not allow_empty and not val.strip():
        raise ValueError(f"Missing or invalid field in {cls_name}: {field}")
    return val


def _coerce_int(cls_name: str, data: dict[str, Any], field: str) -> int:
    val = _require_field(cls_name, data, field)
    if isinstance(val, bool):
        raise ValueError(f"Missing or invalid field in {cls_name}: {field}")
    try:
        return int(val)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Missing or invalid field in {cls_name}: {field}") from exc


def _coerce_float(cls_name: str, data: dict[str, Any], field: str) -> float:
    val = _require_field(cls_name, data, field)
    if isinstance(val, bool):
        raise ValueError(f"Missing or invalid field in {cls_name}: {field}")
    try:
        return float(val)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Missing or invalid field in {cls_name}: {field}") from exc


def _coerce_bool(cls_name: str, data: dict[str, Any], field: str) -> bool:
    val = _require_field(cls_name, data, field)
    if isinstance(val, bool):
        return val
    raise ValueError(f"Missing or invalid field in {cls_name}: {field}")


@dataclass
class NodeRegistration:
    """Identity and network endpoint registration for an SD-WAN peer."""

    node_id: str
    overlay_ip: str
    underlay_host: str
    wg_port: int
    qkd_port: int
    wg_public_key: str
    auth_token_id: str
    registered_at: float
    lan_host: str | None = None
    status: str = "ONLINE"
    last_seen: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "node_id": self.node_id,
            "overlay_ip": self.overlay_ip,
            "underlay_host": self.underlay_host,
            "wg_port": self.wg_port,
            "qkd_port": self.qkd_port,
            "wg_public_key": self.wg_public_key,
            "auth_token_id": self.auth_token_id,
            "registered_at": self.registered_at,
            "status": self.status,
            "last_seen": self.last_seen if self.last_seen > 0.0 else self.registered_at,
        }
        if self.lan_host:
            out["lan_host"] = self.lan_host
        return out

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "NodeRegistration":
        cls_name = cls.__name__
        raw_lan = data.get("lan_host")
        lan_host = str(raw_lan).strip() if isinstance(raw_lan, str) and raw_lan.strip() else None
        reg_at = _coerce_float(cls_name, data, "registered_at")
        raw_status = str(data.get("status", "ONLINE") or "ONLINE").strip().upper()
        status = raw_status if raw_status in ("ONLINE", "OFFLINE") else "ONLINE"
        raw_last_seen = data.get("last_seen")
        try:
            last_seen = float(raw_last_seen) if raw_last_seen is not None else reg_at
        except (TypeError, ValueError):
            last_seen = reg_at
        return cls(
            node_id=_coerce_str(cls_name, data, "node_id"),
            overlay_ip=_coerce_str(cls_name, data, "overlay_ip"),
            underlay_host=_coerce_str(cls_name, data, "underlay_host"),
            wg_port=_coerce_int(cls_name, data, "wg_port"),
            qkd_port=_coerce_int(cls_name, data, "qkd_port"),
            wg_public_key=_coerce_str(cls_name, data, "wg_public_key"),
            auth_token_id=_coerce_str(cls_name, data, "auth_token_id"),
            registered_at=reg_at,
            lan_host=lan_host,
            status=status,
            last_seen=last_seen if last_seen > 0.0 else reg_at,
        )

@dataclass
class LinkTelemetry:
    """Periodic underlay quality and BB84 quantum channel metrics for a directed peer link."""

    source_node: str
    target_node: str
    timestamp: float
    latency_ms: float
    jitter_ms: float
    packet_loss_pct: float
    throughput_mbps: float
    qber: float
    qber_delta: float
    key_rate_bps: float
    psk_epoch: int
    handshake_age_s: float
    qkd_abort_count: int

    def to_feature_vector(self) -> list[float]:
        """Return the 6-dimensional feature vector consumed by IsolationForestDetector."""
        return [
            float(self.qber),
            float(self.qber_delta),
            float(self.key_rate_bps),
            float(self.latency_ms),
            float(self.jitter_ms),
            float(self.packet_loss_pct),
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_node": self.source_node,
            "target_node": self.target_node,
            "timestamp": self.timestamp,
            "latency_ms": self.latency_ms,
            "jitter_ms": self.jitter_ms,
            "packet_loss_pct": self.packet_loss_pct,
            "throughput_mbps": self.throughput_mbps,
            "qber": self.qber,
            "qber_delta": self.qber_delta,
            "key_rate_bps": self.key_rate_bps,
            "psk_epoch": self.psk_epoch,
            "handshake_age_s": self.handshake_age_s,
            "qkd_abort_count": self.qkd_abort_count,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "LinkTelemetry":
        cls_name = cls.__name__
        return cls(
            source_node=_coerce_str(cls_name, data, "source_node"),
            target_node=_coerce_str(cls_name, data, "target_node"),
            timestamp=_coerce_float(cls_name, data, "timestamp"),
            latency_ms=_coerce_float(cls_name, data, "latency_ms"),
            jitter_ms=_coerce_float(cls_name, data, "jitter_ms"),
            packet_loss_pct=_coerce_float(cls_name, data, "packet_loss_pct"),
            throughput_mbps=_coerce_float(cls_name, data, "throughput_mbps"),
            qber=_coerce_float(cls_name, data, "qber"),
            qber_delta=_coerce_float(cls_name, data, "qber_delta"),
            key_rate_bps=_coerce_float(cls_name, data, "key_rate_bps"),
            psk_epoch=_coerce_int(cls_name, data, "psk_epoch"),
            handshake_age_s=_coerce_float(cls_name, data, "handshake_age_s"),
            qkd_abort_count=_coerce_int(cls_name, data, "qkd_abort_count"),
        )


@dataclass
class RouteDirective:
    """Controller-issued routing and re-keying policy for a P2P node pair."""

    source_node: str
    target_node: str
    route_mode: RouteMode
    next_hop_node: str
    next_hop_endpoint: str
    anomaly_score: float
    link_status: LinkStatus
    force_rekey: bool
    reason: str
    updated_at: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_node": self.source_node,
            "target_node": self.target_node,
            "route_mode": self.route_mode.value if isinstance(self.route_mode, RouteMode) else str(self.route_mode),
            "next_hop_node": self.next_hop_node,
            "next_hop_endpoint": self.next_hop_endpoint,
            "anomaly_score": self.anomaly_score,
            "link_status": self.link_status.value if isinstance(self.link_status, LinkStatus) else str(self.link_status),
            "force_rekey": self.force_rekey,
            "reason": self.reason,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RouteDirective":
        cls_name = cls.__name__
        raw_mode = _require_field(cls_name, data, "route_mode")
        try:
            route_mode = raw_mode if isinstance(raw_mode, RouteMode) else RouteMode(str(raw_mode))
        except ValueError as exc:
            raise ValueError(f"Missing or invalid field in {cls_name}: route_mode") from exc

        raw_status = _require_field(cls_name, data, "link_status")
        try:
            link_status = raw_status if isinstance(raw_status, LinkStatus) else LinkStatus(str(raw_status))
        except ValueError as exc:
            raise ValueError(f"Missing or invalid field in {cls_name}: link_status") from exc

        return cls(
            source_node=_coerce_str(cls_name, data, "source_node"),
            target_node=_coerce_str(cls_name, data, "target_node"),
            route_mode=route_mode,
            next_hop_node=_coerce_str(cls_name, data, "next_hop_node", allow_empty=(route_mode == RouteMode.QUARANTINED)),
            next_hop_endpoint=_coerce_str(
                cls_name, data, "next_hop_endpoint", allow_empty=(route_mode == RouteMode.QUARANTINED)
            ),
            anomaly_score=_coerce_float(cls_name, data, "anomaly_score"),
            link_status=link_status,
            force_rekey=_coerce_bool(cls_name, data, "force_rekey"),
            reason=_coerce_str(cls_name, data, "reason"),
            updated_at=_coerce_float(cls_name, data, "updated_at"),
        )


@dataclass
class BB84SessionResult:
    """Outcome of a single P2P BB84 quantum key distribution session."""

    session_id: str
    peer_node: str
    epoch: int
    raw_Exported_qubits: int
    transmitted_qubits: int
    sifted_key_bits: int
    measured_qber: float
    corrected_errors: int
    final_key_bytes: bytes | None
    psk_fingerprint_sha256: str | None
    aborted: bool
    abort_reason: str | None
    duration_ms: float
    key_rate_bps: float

    @property
    def raw_exported_qubits(self) -> int:
        return self.raw_Exported_qubits

    def to_summary_dict(self) -> dict[str, Any]:
        """Return non-secret telemetry summary (never exports final_key_bytes)."""
        return {
            "session_id": self.session_id,
            "peer_node": self.peer_node,
            "epoch": self.epoch,
            "raw_Exported_qubits": self.raw_Exported_qubits,
            "transmitted_qubits": self.transmitted_qubits,
            "sifted_key_bits": self.sifted_key_bits,
            "measured_qber": self.measured_qber,
            "corrected_errors": self.corrected_errors,
            "psk_fingerprint_sha256": self.psk_fingerprint_sha256,
            "aborted": self.aborted,
            "abort_reason": self.abort_reason,
            "duration_ms": self.duration_ms,
            "key_rate_bps": self.key_rate_bps,
        }

    @classmethod
    def from_summary_dict(cls, data: dict[str, Any]) -> "BB84SessionResult":
        cls_name = cls.__name__
        raw_qubits = data.get("raw_Exported_qubits", data.get("raw_exported_qubits", 0))
        return cls(
            session_id=_coerce_str(cls_name, data, "session_id"),
            peer_node=_coerce_str(cls_name, data, "peer_node"),
            epoch=_coerce_int(cls_name, data, "epoch"),
            raw_Exported_qubits=int(raw_qubits),
            transmitted_qubits=_coerce_int(cls_name, data, "transmitted_qubits"),
            sifted_key_bits=_coerce_int(cls_name, data, "sifted_key_bits"),
            measured_qber=_coerce_float(cls_name, data, "measured_qber"),
            corrected_errors=_coerce_int(cls_name, data, "corrected_errors"),
            final_key_bytes=None,
            psk_fingerprint_sha256=str(data["psk_fingerprint_sha256"]) if data.get("psk_fingerprint_sha256") else None,
            aborted=_coerce_bool(cls_name, data, "aborted"),
            abort_reason=str(data["abort_reason"]) if data.get("abort_reason") else None,
            duration_ms=_coerce_float(cls_name, data, "duration_ms"),
            key_rate_bps=_coerce_float(cls_name, data, "key_rate_bps"),
        )


@dataclass
class EnrollmentToken:
    """Join token used for zero-touch endpoint auto-enrollment with the Central Controller."""

    token_id: str
    secret_token: str
    label: str
    max_uses: int
    used_count: int
    expires_at: float
    revoked: bool
    created_at: float

    def is_valid(self, now: float | None = None) -> bool:
        current_time = time.time() if now is None else now
        return (not self.revoked) and (self.used_count < self.max_uses) and (current_time < self.expires_at)

    def to_dict(self, redact_secret: bool = False) -> dict[str, Any]:
        secret_val = self.secret_token
        if redact_secret:
            if len(secret_val) >= 10:
                secret_val = f"{secret_val[:6]}...{secret_val[-4:]}"
            else:
                secret_val = "***"
        return {
            "token_id": self.token_id,
            "secret_token": secret_val,
            "label": self.label,
            "max_uses": self.max_uses,
            "used_count": self.used_count,
            "expires_at": self.expires_at,
            "revoked": self.revoked,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EnrollmentToken":
        cls_name = cls.__name__
        return cls(
            token_id=_coerce_str(cls_name, data, "token_id"),
            secret_token=_coerce_str(cls_name, data, "secret_token"),
            label=_coerce_str(cls_name, data, "label"),
            max_uses=_coerce_int(cls_name, data, "max_uses"),
            used_count=_coerce_int(cls_name, data, "used_count"),
            expires_at=_coerce_float(cls_name, data, "expires_at"),
            revoked=_coerce_bool(cls_name, data, "revoked"),
            created_at=_coerce_float(cls_name, data, "created_at"),
        )


@dataclass
class P2PDataMessage:
    """Application-layer encrypted P2P message or file payload exchanged over the WireGuard overlay."""

    message_id: str
    source_node: str
    target_node: str
    content_type: str
    filename: str | None
    payload_b64: str
    psk_epoch: int
    route_mode: str
    via_relay_node: str | None
    timestamp: float
    payload_sha256: str = ""

    def __post_init__(self) -> None:
        if not self.payload_sha256:
            raw = base64.b64decode(self.payload_b64.encode("ascii"))
            self.payload_sha256 = hashlib.sha256(raw).hexdigest()

    def verify_integrity(self) -> bool:
        try:
            raw = base64.b64decode(self.payload_b64.encode("ascii"))
        except Exception:
            return False
        actual = hashlib.sha256(raw).hexdigest()
        return hmac.compare_digest(actual, self.payload_sha256)

    def decode_payload(self, verify: bool = True) -> bytes:
        raw = base64.b64decode(self.payload_b64.encode("ascii"))
        if (
            verify
            and self.payload_sha256
            and not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), self.payload_sha256)
        ):
            raise ValueError("P2PDataMessage payload SHA-256 integrity check failed")
        return raw

    def decode_text(self, verify: bool = True) -> str:
        return self.decode_payload(verify=verify).decode("utf-8", errors="replace")

    def to_dict(self) -> dict[str, Any]:
        return {
            "message_id": self.message_id,
            "source_node": self.source_node,
            "target_node": self.target_node,
            "content_type": self.content_type,
            "filename": self.filename,
            "payload_b64": self.payload_b64,
            "psk_epoch": self.psk_epoch,
            "route_mode": self.route_mode,
            "via_relay_node": self.via_relay_node,
            "timestamp": self.timestamp,
            "payload_sha256": self.payload_sha256,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "P2PDataMessage":
        cls_name = cls.__name__
        raw_filename = data.get("filename") if isinstance(data, dict) else None
        raw_relay = data.get("via_relay_node") if isinstance(data, dict) else None
        payload_b64 = _coerce_str(cls_name, data, "payload_b64", allow_empty=True)
        try:
            base64.b64decode(payload_b64.encode("ascii"), validate=True)
        except Exception as exc:
            raise ValueError(f"Invalid Base64 payload_b64 in {cls_name}") from exc
        raw_sha256 = str(data.get("payload_sha256", "") or "") if isinstance(data, dict) else ""
        return cls(
            message_id=_coerce_str(cls_name, data, "message_id"),
            source_node=_coerce_str(cls_name, data, "source_node"),
            target_node=_coerce_str(cls_name, data, "target_node"),
            content_type=_coerce_str(cls_name, data, "content_type"),
            filename=str(raw_filename) if raw_filename is not None else None,
            payload_b64=payload_b64,
            psk_epoch=_coerce_int(cls_name, data, "psk_epoch"),
            route_mode=_coerce_str(cls_name, data, "route_mode"),
            via_relay_node=str(raw_relay) if raw_relay is not None else None,
            timestamp=_coerce_float(cls_name, data, "timestamp"),
            payload_sha256=raw_sha256,
        )
