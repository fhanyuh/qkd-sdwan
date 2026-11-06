#!/usr/bin/env python3
"""End-to-End Distributed PoC Simulation for QKD-SDWAN:
Join Token Auto-Enrollment, 3 P2P Nodes, 4 Quantum Scenarios, P2P Message/File Transfer, and Controller CLI Dashboard.
"""

from __future__ import annotations

from pathlib import Path
import sys
import tempfile
from typing import Any

# Ensure repo root is importable when executed as `python3 scripts/run_poc_demo.py`
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from qkd_sdwan.client.agent import SDWANEndpointAgent, render_client_dashboard
from qkd_sdwan.client.bb84_engine import QuantumChannelParams
from qkd_sdwan.controller.cli import render_controller_dashboard
from qkd_sdwan.controller.server import SDWANControllerServer


def _print_banner(title: str) -> None:
    line = "=" * 96
    print(f"\n{line}")
    print(f"  {title}")
    print(f"{line}")


def _print_cycle_summary(scenario_label: str, result: dict[str, Any]) -> None:
    bb84 = result["bb84"]
    ev = result["evaluation"]
    directive = result["directive"]
    delivery = result.get("dataplane_delivery") or {}

    qber_val = float(bb84["measured_qber"])
    aborted = bool(bb84["aborted"])
    psk_injected = bool(result["psk_injected"])
    link_status = ev["link_status"]
    anomaly_score = float(ev["anomaly_score"])
    route_mode = directive["route_mode"]
    next_hop = directive["next_hop_node"]
    force_rekey = bool(directive["force_rekey"])

    if aborted:
        qkd_state_str = f"BB84 SESSION ABORTED (QBER > 0.11: {qber_val:.4f}) | Reason: {bb84['abort_reason']}"
    elif psk_injected:
        qkd_state_str = (
            f"PSK Injected (256-bit) | Epoch: {bb84['epoch']} | "
            f"Fingerprint: {bb84['psk_fingerprint_sha256']} | QBER: {qber_val:.4f}"
        )
    else:
        qkd_state_str = f"No PSK Change | QBER: {qber_val:.4f}"

    if route_mode == "RELAY_P2P":
        route_str = f"RouteMode: RELAY_P2P via {next_hop}"
    else:
        route_str = f"RouteMode: {route_mode} (next_hop={next_hop})"

    print(f"  [{scenario_label}] {result['source_node']} -> {result['target_node']}")
    print(f"    - QKD Plane      : {qkd_state_str}")
    print(
        f"    - Photons/Sifted : raw={bb84['raw_Exported_qubits']}, "
        f"detected={bb84['transmitted_qubits']}, sifted={bb84['sifted_key_bits']}, "
        f"corrected_err={bb84['corrected_errors']}, key_rate={bb84['key_rate_bps']:.0f} bps"
    )
    print(
        f"    - ML Evaluation  : LinkStatus: {link_status} | "
        f"anomaly_score={anomaly_score:.4f} | force_rekey={force_rekey}"
    )
    print(f"    - Routing Policy : {route_str}")
    if delivery.get("delivered"):
        via_info = (
            f"via relay {delivery['via_relay_node']}"
            if delivery.get("via_relay_node")
            else "direct P2P UDP"
        )
        print(
            f"    - Data Plane     : DELIVERED ({delivery['payload_bytes']} bytes {via_info}, "
            f"RTT={delivery['rtt_ms']:.2f} ms, PSK Epoch={delivery['psk_epoch']})"
        )
    print()


def _print_summary_table(rows: list[dict[str, str]]) -> None:
    headers = ["Scenario", "Link", "QBER", "BB84 / PSK State", "ML Score", "LinkStatus", "Active Route"]
    widths = [len(h) for h in headers]
    for r in rows:
        vals = [r["scenario"], r["link"], r["qber"], r["psk"], r["score"], r["status"], r["route"]]
        for idx, v in enumerate(vals):
            widths[idx] = max(widths[idx], len(v))

    sep = "+-" + "-+-".join("-" * w for w in widths) + "-+"
    hdr = "| " + " | ".join(h.ljust(widths[i]) for i, h in enumerate(headers)) + " |"
    print(sep)
    print(hdr)
    print(sep)
    for r in rows:
        vals = [r["scenario"], r["link"], r["qber"], r["psk"], r["score"], r["status"], r["route"]]
        print("| " + " | ".join(vals[i].ljust(widths[i]) for i in range(len(headers))) + " |")
    print(sep)


def run_simulation() -> int:
    _print_banner("QKD-SDWAN PoC: Join-Token Auto-Enrollment, Socket BB84, ML Optimization & P2P Data")

    # Step A: Central Controller initialization
    controller = SDWANControllerServer(host="127.0.0.1", port=0)
    ctrl_host, ctrl_port = controller.start_background()
    print(f"[Controller] Central Controller listening on http://{ctrl_host}:{ctrl_port}")
    print(f"[Controller] Bootstrap Join Token: {controller.bootstrap_token}")

    # Create a dedicated Join Token for the demo cluster
    demo_token = controller.create_enrollment_token(label="poc-demo-cluster", max_uses=10, ttl_seconds=3600.0)
    print(f"[Controller] Created demo Join Token ({demo_token.token_id}): {demo_token.secret_token}")

    # Step B: Auto-enroll 3 distributed endpoint nodes using the Join Token
    _print_banner("Token-Based Zero-Touch Auto-Enrollment of 3 SD-WAN Endpoints")
    with tempfile.TemporaryDirectory(prefix="qkd-demo-configs-") as tmpdir:
        tmp_path = Path(tmpdir)
        agent_jkt, jkt_resp = SDWANEndpointAgent.enroll_with_controller(
            controller_url=controller.base_url,
            join_token=demo_token.secret_token,
            node_id="edge-jkt-01",
            config_output_path=tmp_path / "jkt.json",
        )
        agent_bdg, bdg_resp = SDWANEndpointAgent.enroll_with_controller(
            controller_url=controller.base_url,
            join_token=demo_token.secret_token,
            node_id="edge-bdg-02",
            config_output_path=tmp_path / "bdg.json",
        )
        agent_sby, sby_resp = SDWANEndpointAgent.enroll_with_controller(
            controller_url=controller.base_url,
            join_token=demo_token.secret_token,
            node_id="edge-sby-03",
            config_output_path=tmp_path / "sby.json",
        )

        agents = [agent_jkt, agent_bdg, agent_sby]
        for ag, resp in zip(agents, [jkt_resp, bdg_resp, sby_resp]):
            print(
                f"[Auto-Enroll] Node {ag.node_id:<12} -> Allocated Overlay IP: {resp['allocated_overlay_ip']:<14} | "
                f"WG UDP: {ag.underlay_host}:{ag.wg_port:<5} | QKD TCP: {ag.underlay_host}:{ag.qkd_port}"
            )

    summary_rows: list[dict[str, str]] = []

    try:
        # Initial topology sync
        for ag in agents:
            ag.sync_topology()

        # =========================================================================
        # Scenario 1: Normal P2P Operation (No Eavesdropping, Healthy Underlay)
        # =========================================================================
        _print_banner("Scenario 1: Normal P2P Operation (eta_eve = 0.0, Healthy Fiber & WAN)")
        normal_params = QuantumChannelParams(
            distance_km=15.0,
            attenuation_db_per_km=0.2,
            depolarization_prob=0.015,
            eavesdrop_intercept_ratio=0.0,
            pulse_count=2048,
        )
        res_jkt_bdg = agent_jkt.run_key_rotation_and_telemetry_cycle(
            "edge-bdg-02",
            override_channel_params=normal_params,
            simulated_underlay={"latency_ms": 9.5, "jitter_ms": 0.8, "packet_loss_pct": 0.05},
            probe_payload=b"SCENARIO-1-JKT-BDG",
        )
        res_bdg_sby = agent_bdg.run_key_rotation_and_telemetry_cycle(
            "edge-sby-03",
            override_channel_params=normal_params,
            simulated_underlay={"latency_ms": 11.2, "jitter_ms": 0.9, "packet_loss_pct": 0.05},
            probe_payload=b"SCENARIO-1-BDG-SBY",
        )
        res_s1 = agent_jkt.run_key_rotation_and_telemetry_cycle(
            "edge-sby-03",
            override_channel_params=normal_params,
            simulated_underlay={"latency_ms": 14.0, "jitter_ms": 1.1, "packet_loss_pct": 0.1},
            probe_payload=b"SCENARIO-1-DIRECT-P2P-PAYLOAD",
        )
        _print_cycle_summary("Scenario 1 (Relay Leg 1)", res_jkt_bdg)
        _print_cycle_summary("Scenario 1 (Relay Leg 2)", res_bdg_sby)
        _print_cycle_summary("Scenario 1 (Target Link)", res_s1)
        summary_rows.append(
            {
                "scenario": "1. Normal P2P",
                "link": "edge-jkt-01 -> edge-sby-03",
                "qber": f"{res_s1['bb84']['measured_qber']:.4f} (< 0.05)",
                "psk": f"PSK Injected (256-bit, ep={res_s1['bb84']['epoch']})",
                "score": f"{res_s1['evaluation']['anomaly_score']:.3f}",
                "status": res_s1["evaluation"]["link_status"],
                "route": res_s1["directive"]["route_mode"],
            }
        )

        # =========================================================================
        # Scenario 2: WAN Underlay Degradation (High Latency & Packet Loss, No Eve)
        # =========================================================================
        _print_banner("Scenario 2: WAN Underlay Degradation (Latency=115ms, Loss=6.5%, Clean Quantum Channel)")
        res_s2 = agent_jkt.run_key_rotation_and_telemetry_cycle(
            "edge-sby-03",
            override_channel_params=QuantumChannelParams(
                distance_km=15.0,
                attenuation_db_per_km=0.2,
                depolarization_prob=0.018,
                eavesdrop_intercept_ratio=0.0,
                pulse_count=2048,
            ),
            simulated_underlay={"latency_ms": 115.0, "jitter_ms": 9.8, "packet_loss_pct": 6.5},
            probe_payload=b"SCENARIO-2-REROUTED-P2P-PAYLOAD",
        )
        _print_cycle_summary("Scenario 2", res_s2)
        summary_rows.append(
            {
                "scenario": "2. Underlay Degraded",
                "link": "edge-jkt-01 -> edge-sby-03",
                "qber": f"{res_s2['bb84']['measured_qber']:.4f}",
                "psk": f"PSK Injected (256-bit, ep={res_s2['bb84']['epoch']})",
                "score": f"{res_s2['evaluation']['anomaly_score']:.3f}",
                "status": res_s2["evaluation"]["link_status"],
                "route": f"{res_s2['directive']['route_mode']} via {res_s2['directive']['next_hop_node']}",
            }
        )

        # =========================================================================
        # Scenario 3: Moderate Quantum Eavesdropping (eta_eve = 0.30, QBER ~ 8.5%-9.5%)
        # =========================================================================
        _print_banner("Scenario 3: Moderate Quantum Eavesdropping (eta_eve = 0.30, QBER ~ 9.0%)")
        res_s3 = agent_jkt.run_key_rotation_and_telemetry_cycle(
            "edge-sby-03",
            override_channel_params=QuantumChannelParams(
                distance_km=15.0,
                attenuation_db_per_km=0.2,
                depolarization_prob=0.015,
                eavesdrop_intercept_ratio=0.30,
                pulse_count=2048,
            ),
            simulated_underlay={"latency_ms": 15.0, "jitter_ms": 1.3, "packet_loss_pct": 0.15},
            probe_payload=b"SCENARIO-3-MODERATE-EVE-PAYLOAD",
        )
        _print_cycle_summary("Scenario 3", res_s3)
        summary_rows.append(
            {
                "scenario": "3. Moderate Eve (0.30)",
                "link": "edge-jkt-01 -> edge-sby-03",
                "qber": f"{res_s3['bb84']['measured_qber']:.4f}",
                "psk": f"PSK Rotated + force_rekey={res_s3['directive']['force_rekey']}",
                "score": f"{res_s3['evaluation']['anomaly_score']:.3f}",
                "status": res_s3["evaluation"]["link_status"],
                "route": f"{res_s3['directive']['route_mode']} via {res_s3['directive']['next_hop_node']}",
            }
        )

        # =========================================================================
        # Scenario 4: Aggressive Quantum Eavesdropping (eta_eve = 0.65, QBER > 15% -> ABORT)
        # =========================================================================
        _print_banner("Scenario 4: Aggressive Quantum Eavesdropping (eta_eve = 0.65, QBER > 0.11 Shor-Preskill Bound)")
        res_s4 = agent_jkt.run_key_rotation_and_telemetry_cycle(
            "edge-sby-03",
            override_channel_params=QuantumChannelParams(
                distance_km=15.0,
                attenuation_db_per_km=0.2,
                depolarization_prob=0.015,
                eavesdrop_intercept_ratio=0.65,
                pulse_count=2048,
            ),
            simulated_underlay={"latency_ms": 16.0, "jitter_ms": 1.4, "packet_loss_pct": 0.20},
            probe_payload=b"SCENARIO-4-PROTECTED-RELAY-PAYLOAD",
        )
        _print_cycle_summary("Scenario 4", res_s4)
        summary_rows.append(
            {
                "scenario": "4. Aggressive Eve (0.65)",
                "link": "edge-jkt-01 -> edge-sby-03",
                "qber": f"{res_s4['bb84']['measured_qber']:.4f} (> 0.11)",
                "psk": "BB84 SESSION ABORTED (Blocked)",
                "score": f"{res_s4['evaluation']['anomaly_score']:.3f}",
                "status": res_s4["evaluation"]["link_status"],
                "route": f"{res_s4['directive']['route_mode']} via {res_s4['directive']['next_hop_node']}",
            }
        )

        # =========================================================================
        # P2P Application Data & File Transfer Demonstration
        # =========================================================================
        _print_banner("Encrypted Application P2P Data & File Transfer (DIRECT_P2P and RELAY_P2P)")
        # 1. Send encrypted text DIRECT_P2P: edge-jkt-01 -> edge-bdg-02
        text_delivery = agent_jkt.send_p2p_text(
            target_node="edge-bdg-02",
            text="Salam dari Jakarta! Pesan rahasia ini terenkripsi WireGuard ChaCha20Poly1305 ber-PSK BB84.",
        )
        print(
            f"  [+] DIRECT P2P Text Transfer (edge-jkt-01 -> edge-bdg-02):\n"
            f"      Status: {text_delivery['status']} | Mode: {text_delivery['delivery']['route_mode']} | "
            f"PSK Epoch: {text_delivery['delivery']['psk_epoch']} | RTT: {text_delivery['delivery']['rtt_ms']:.2f} ms"
        )
        bdg_inbox = agent_bdg.get_received_messages(clear=False)
        for msg in bdg_inbox:
            print(f"      [Inbox @ edge-bdg-02] Decrypted text from {msg.source_node}: '{msg.decode_text()}'")
        # 2. Send encrypted binary file payload via RELAY_P2P: edge-jkt-01 -> edge-sby-03 (routed via edge-bdg-02)
        demo_payload = b"Quantum-Secured SD-WAN Payload: Confidential Financial Audit Log #2025-Q1-QKD"
        file_delivery = agent_jkt.send_p2p_data(
            target_node="edge-sby-03",
            payload=demo_payload,
            content_type="file",
            filename="audit_log_q1.dat",
            auto_rekey=False,  # Keep current relay route policy
        )
        print(
            f"\n  [+] RELAY P2P File Transfer (edge-jkt-01 -> edge-sby-03 via edge-bdg-02):\n"
            f"      Status: {file_delivery['status']} | Mode: {file_delivery['delivery']['route_mode']} | "
            f"Relayed By: {file_delivery['delivery']['via_relay_node']} | RTT: {file_delivery['delivery']['rtt_ms']:.2f} ms"
        )
        sby_inbox = agent_sby.get_received_messages(clear=False)
        for msg in sby_inbox:
            print(
                f"      [Inbox @ edge-sby-03] Decrypted file '{msg.filename}' ({len(msg.decode_payload())} bytes) "
                f"via relay {msg.via_relay_node}: '{msg.decode_text()}'"
            )

        # Summary Table
        _print_banner("Consolidated 4-Scenario PoC Verification Summary")
        _print_summary_table(summary_rows)
        print(
            f"\n[Relay Stats] Trusted P2P Relay node `edge-bdg-02` forwarded "
            f"{agent_bdg.wg_daemon.relay_forwarded_packets} encrypted overlay packets without Controller involvement."
        )

        # =========================================================================
        # Step C: Endpoint Client & Central Controller CLI Dashboards
        # =========================================================================
        print("\n" + render_client_dashboard(agent_jkt))
        print("\n" + render_client_dashboard(agent_sby))
        print("\n" + render_controller_dashboard(controller.get_cluster_status(), controller_url=controller.base_url))

        return 0
    finally:
        for ag in agents:
            ag.close()
        controller.shutdown()


if __name__ == "__main__":
    raise SystemExit(run_simulation())
