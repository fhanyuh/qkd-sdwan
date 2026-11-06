"""Machine Learning anomaly detection (Isolation Forest) and P2P overlay route optimization."""

from __future__ import annotations

from dataclasses import dataclass
import math
import random
import statistics
import time
from typing import Any

from qkd_sdwan.common.models import (
    LinkStatus,
    LinkTelemetry,
    NodeRegistration,
    RouteDirective,
    RouteMode,
)

EULER_MASCHERONI = 0.5772156649


def bst_normalization_factor(n: int) -> float:
    """Compute the average path length c(n) of unsuccessful searches in a Binary Search Tree."""
    if n <= 1:
        return 1.0
    if n == 2:
        return 1.0
    harmonic = math.log(n - 1.0) + EULER_MASCHERONI
    return 2.0 * harmonic - (2.0 * (n - 1.0) / float(n))


@dataclass
class _IsolationNode:
    """Internal split or external leaf node of an Isolation Tree."""

    size: int
    split_attr: int | None = None
    split_val: float | None = None
    left: "_IsolationNode | None" = None
    right: "_IsolationNode | None" = None


class _IsolationTree:
    """Single randomized binary isolation tree."""

    def __init__(self, height_limit: int) -> None:
        self.height_limit = height_limit
        self.root: _IsolationNode | None = None

    def fit(self, samples: list[list[float]], rng: random.Random) -> "_IsolationTree":
        self.root = self._build(samples, current_height=0, rng=rng)
        return self

    def _build(
        self,
        samples: list[list[float]],
        current_height: int,
        rng: random.Random,
    ) -> _IsolationNode:
        n_samples = len(samples)
        if current_height >= self.height_limit or n_samples <= 1:
            return _IsolationNode(size=n_samples)

        n_dims = len(samples[0])
        candidate_dims = list(range(n_dims))
        rng.shuffle(candidate_dims)

        chosen_dim: int | None = None
        min_v = 0.0
        max_v = 0.0
        for dim in candidate_dims:
            col = [row[dim] for row in samples]
            lo, hi = min(col), max(col)
            if hi > lo + 1e-12:
                chosen_dim = dim
                min_v, max_v = lo, hi
                break

        if chosen_dim is None:
            return _IsolationNode(size=n_samples)

        split_val = rng.uniform(min_v, max_v)
        left_samples = [row for row in samples if row[chosen_dim] < split_val]
        right_samples = [row for row in samples if row[chosen_dim] >= split_val]

        if not left_samples or not right_samples:
            return _IsolationNode(size=n_samples)

        return _IsolationNode(
            size=n_samples,
            split_attr=chosen_dim,
            split_val=split_val,
            left=self._build(left_samples, current_height + 1, rng),
            right=self._build(right_samples, current_height + 1, rng),
        )

    def path_length(self, x: list[float]) -> float:
        node = self.root
        depth = 0.0
        while node is not None and node.split_attr is not None and node.split_val is not None:
            depth += 1.0
            if x[node.split_attr] < node.split_val:
                node = node.left
            else:
                node = node.right
        if node is not None and node.size > 1:
            depth += bst_normalization_factor(node.size)
        return depth


class IsolationForestDetector:
    """6D Isolation Forest detector for quantum eavesdropping and WAN underlay anomalies."""

    def __init__(
        self,
        n_estimators: int = 64,
        max_samples: int = 128,
        seed: int = 42,
    ) -> None:
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.height_limit = int(math.ceil(math.log2(max(2, max_samples))))
        self._trees: list[_IsolationTree] = []
        self._feature_means: list[float] = []
        self._feature_stds: list[float] = []
        self.bootstrap_baseline(seed=seed)

    def bootstrap_baseline(self, seed: int = 42) -> None:
        """Deterministically train the Isolation Forest on normal P2P SD-WAN + QKD baseline distributions."""
        rng = random.Random(seed)
        pool_size = max(512, self.max_samples * 4)
        baseline_pool: list[list[float]] = []

        for _ in range(pool_size):
            qber = rng.uniform(0.01, 0.035)
            qber_delta = rng.uniform(-0.008, 0.008)
            key_rate_bps = rng.uniform(3500.0, 9000.0)
            latency_ms = rng.uniform(3.0, 28.0)
            jitter_ms = rng.uniform(0.2, 4.5)
            packet_loss_pct = rng.uniform(0.0, 0.8)
            baseline_pool.append(
                [qber, qber_delta, key_rate_bps, latency_ms, jitter_ms, packet_loss_pct]
            )

        n_dims = 6
        self._feature_means = [
            statistics.fmean(row[d] for row in baseline_pool) for d in range(n_dims)
        ]
        self._feature_stds = [
            max(1e-6, statistics.pstdev(row[d] for row in baseline_pool)) for d in range(n_dims)
        ]

        self._trees = []
        for _ in range(self.n_estimators):
            subsample = rng.sample(baseline_pool, self.max_samples)
            tree = _IsolationTree(height_limit=self.height_limit).fit(subsample, rng)
            self._trees.append(tree)

    def raw_isolation_score(self, x: list[float]) -> float:
        """Compute s(x, n) = 2^(-E(h(x)) / c(n)) in (0, 1]."""
        if not self._trees:
            self.bootstrap_baseline()
        avg_path = sum(tree.path_length(x) for tree in self._trees) / float(len(self._trees))
        cn = bst_normalization_factor(self.max_samples)
        score = 2.0 ** (-(avg_path / cn))
        return max(0.01, min(0.999, score))

    def evaluate_telemetry(self, telemetry: LinkTelemetry) -> tuple[float, LinkStatus, str]:
        """Evaluate a LinkTelemetry report and return (anomaly_score, link_status, reason)."""
        features = telemetry.to_feature_vector()
        if_score = self.raw_isolation_score(features)

        # Compute directional z-scores on upper-bound degradation/security metrics
        # Features: [qber, qber_delta, key_rate_bps, latency_ms, jitter_ms, packet_loss_pct]
        z_qber = max(0.0, (telemetry.qber - self._feature_means[0]) / self._feature_stds[0])
        z_qber_delta = max(0.0, (telemetry.qber_delta - self._feature_means[1]) / self._feature_stds[1])
        z_latency = max(0.0, (telemetry.latency_ms - self._feature_means[3]) / self._feature_stds[3])
        z_jitter = max(0.0, (telemetry.jitter_ms - self._feature_means[4]) / self._feature_stds[4])
        z_loss = max(0.0, (telemetry.packet_loss_pct - self._feature_means[5]) / self._feature_stds[5])

        max_z = max(z_qber, z_qber_delta, z_latency, z_jitter, z_loss)
        # Calibrate combined score so in-distribution baseline sits ~0.38-0.48 and anomalies exceed 0.65+
        z_boost = min(0.42, (max(0.0, max_z - 1.8) / 10.0) * 0.42)
        if telemetry.qkd_abort_count > 0 or telemetry.qber > 0.11:
            z_boost = max(z_boost, 0.38)
        elif telemetry.qber >= 0.065:
            z_boost = max(z_boost, 0.24)
        elif telemetry.packet_loss_pct > 3.0 or telemetry.latency_ms > 80.0:
            z_boost = max(z_boost, 0.21)

        anomaly_score = round(min(0.99, max(0.05, if_score * 0.78 + z_boost)), 4)

        # Classification rules per architectural specification
        if telemetry.qber > 0.11 or telemetry.qkd_abort_count > 0:
            status = LinkStatus.COMPROMISED_BLOCKED
            reason = (
                f"Quantum eavesdropping abort threshold breached "
                f"(QBER={telemetry.qber:.4f}, aborts={telemetry.qkd_abort_count}, score={anomaly_score:.3f})"
            )
        elif 0.065 <= telemetry.qber <= 0.11 or (anomaly_score >= 0.65 and telemetry.qber_delta > 0.03):
            status = LinkStatus.EAVESDROPPING_SUSPECTED
            reason = (
                f"Elevated QBER anomaly indicates partial intercept-resend eavesdropping "
                f"(QBER={telemetry.qber:.4f}, delta={telemetry.qber_delta:+.4f}, score={anomaly_score:.3f})"
            )
        elif (
            telemetry.qber < 0.065
            and (
                anomaly_score >= 0.62
                or telemetry.packet_loss_pct > 3.0
                or telemetry.latency_ms > 80.0
            )
        ):
            status = LinkStatus.DEGRADED_UNDERLAY
            reason = (
                f"WAN underlay degradation with clean quantum channel "
                f"(latency={telemetry.latency_ms:.1f}ms, loss={telemetry.packet_loss_pct:.2f}%, "
                f"QBER={telemetry.qber:.4f}, score={anomaly_score:.3f})"
            )
        else:
            status = LinkStatus.HEALTHY
            reason = (
                f"Quantum and underlay metrics within normal P2P baseline "
                f"(QBER={telemetry.qber:.4f}, latency={telemetry.latency_ms:.1f}ms, score={anomaly_score:.3f})"
            )

        return anomaly_score, status, reason


class OverlayRouteOptimizer:
    """Multi-objective graph optimizer preserving peer-to-peer SD-WAN data-plane topology."""

    def __init__(self, hysteresis_margin: float = 15.0) -> None:
        self.hysteresis_margin = hysteresis_margin

    def compute_link_cost(
        self,
        telemetry: LinkTelemetry,
        anomaly_score: float,
        status: LinkStatus,
    ) -> float:
        """Compute multi-objective link cost for a directed P2P edge (u, v)."""
        if status == LinkStatus.COMPROMISED_BLOCKED:
            return 1e6

        cost = (
            1.0 * telemetry.latency_ms
            + 2.5 * telemetry.jitter_ms
            + 18.0 * telemetry.packet_loss_pct
            + 1200.0 * max(0.0, telemetry.qber - 0.04)
            + 150.0 * max(0.0, anomaly_score - 0.55)
        )
        return round(cost, 4)

    @staticmethod
    def _lookup_edge(
        u: str,
        v: str,
        link_metrics: dict[tuple[str, str], tuple[LinkTelemetry, float, LinkStatus]],
    ) -> tuple[LinkTelemetry, float, LinkStatus] | None:
        if (u, v) in link_metrics:
            return link_metrics[(u, v)]
        if (v, u) in link_metrics:
            return link_metrics[(v, u)]
        return None

    def compute_directives(
        self,
        nodes: dict[str, NodeRegistration],
        link_metrics: dict[tuple[str, str], tuple[LinkTelemetry, float, LinkStatus]],
    ) -> list[RouteDirective]:
        """Compute optimal P2P routing directives (DIRECT_P2P, RELAY_P2P, or QUARANTINED) for all active links."""
        directives: list[RouteDirective] = []
        now = time.time()

        for (u, v), (telemetry, anomaly_score, status) in link_metrics.items():
            if u == v:
                continue

            target_reg = nodes.get(v)
            direct_endpoint = f"{target_reg.underlay_host}:{target_reg.wg_port}" if target_reg else "127.0.0.1:0"
            direct_cost = self.compute_link_cost(telemetry, anomaly_score, status)

            # Priority 1: Keep direct P2P communication whenever link is HEALTHY
            if status == LinkStatus.HEALTHY:
                directives.append(
                    RouteDirective(
                        source_node=u,
                        target_node=v,
                        route_mode=RouteMode.DIRECT_P2P,
                        next_hop_node=v,
                        next_hop_endpoint=direct_endpoint,
                        anomaly_score=anomaly_score,
                        link_status=status,
                        force_rekey=False,
                        reason=f"Direct P2P link healthy (cost={direct_cost:.1f})",
                        updated_at=now,
                    )
                )
                continue

            # Priority 2: Search for a healthy trusted P2P relay node w in V \ {u, v}
            best_relay: str | None = None
            best_relay_cost = float("inf")

            candidate_nodes = set(nodes.keys()) | {
                n for pair in link_metrics.keys() for n in pair
            }
            for w in sorted(candidate_nodes):
                if w in (u, v):
                    continue
                edge_uw = self._lookup_edge(u, w, link_metrics)
                edge_wv = self._lookup_edge(w, v, link_metrics)
                if edge_uw is None or edge_wv is None:
                    continue

                tel_uw, score_uw, status_uw = edge_uw
                tel_wv, score_wv, status_wv = edge_wv
                if status_uw != LinkStatus.HEALTHY or status_wv != LinkStatus.HEALTHY:
                    continue

                relay_cost = (
                    self.compute_link_cost(tel_uw, score_uw, status_uw)
                    + self.compute_link_cost(tel_wv, score_wv, status_wv)
                )
                if relay_cost + self.hysteresis_margin < direct_cost and relay_cost < best_relay_cost:
                    best_relay = w
                    best_relay_cost = relay_cost

            force_rekey = status in (
                LinkStatus.EAVESDROPPING_SUSPECTED,
                LinkStatus.COMPROMISED_BLOCKED,
            )

            if best_relay is not None:
                relay_reg = nodes.get(best_relay)
                relay_endpoint = (
                    f"{relay_reg.underlay_host}:{relay_reg.wg_port}"
                    if relay_reg
                    else direct_endpoint
                )
                directives.append(
                    RouteDirective(
                        source_node=u,
                        target_node=v,
                        route_mode=RouteMode.RELAY_P2P,
                        next_hop_node=best_relay,
                        next_hop_endpoint=relay_endpoint,
                        anomaly_score=anomaly_score,
                        link_status=status,
                        force_rekey=force_rekey,
                        reason=(
                            f"Rerouted via P2P relay {best_relay} due to {status.value} "
                            f"(relay_cost={best_relay_cost:.1f} < direct_cost={direct_cost:.1f})"
                        ),
                        updated_at=now,
                    )
                )
            elif status == LinkStatus.COMPROMISED_BLOCKED:
                directives.append(
                    RouteDirective(
                        source_node=u,
                        target_node=v,
                        route_mode=RouteMode.QUARANTINED,
                        next_hop_node="",
                        next_hop_endpoint="",
                        anomaly_score=anomaly_score,
                        link_status=status,
                        force_rekey=True,
                        reason="Direct quantum channel compromised and no healthy P2P relay available",
                        updated_at=now,
                    )
                )
            else:
                directives.append(
                    RouteDirective(
                        source_node=u,
                        target_node=v,
                        route_mode=RouteMode.DIRECT_P2P,
                        next_hop_node=v,
                        next_hop_endpoint=direct_endpoint,
                        anomaly_score=anomaly_score,
                        link_status=status,
                        force_rekey=force_rekey,
                        reason=f"Retaining direct P2P ({status.value}); no lower-cost healthy relay found",
                        updated_at=now,
                    )
                )

        return directives
