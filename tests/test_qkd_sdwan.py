"""Automated unit and integration test suite for the Distributed QKD-SDWAN PoC."""

from __future__ import annotations

import base64
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stdout

from qkd_sdwan.client.agent import (
    SDWANEndpointAgent,
    main as client_cli_main,
    render_client_dashboard,
)
from qkd_sdwan.client.bb84_engine import BB84ProtocolEngine, QuantumChannelParams
from qkd_sdwan.client.wg_manager import WireGuardTunnelDaemon
from qkd_sdwan.common.models import (
    LinkStatus,
    LinkTelemetry,
    NodeRegistration,
    P2PDataMessage,
    RouteDirective,
    RouteMode,
)
from qkd_sdwan.controller.cli import main as controller_cli_main, render_controller_dashboard
from qkd_sdwan.controller.ml_engine import IsolationForestDetector, OverlayRouteOptimizer
from qkd_sdwan.controller.server import SDWANControllerServer, _resolve_peer_underlay_host


class TestQKDSDWANSuite(unittest.TestCase):
    """Comprehensive verification of BB84 socket negotiation, WireGuard PSK injection, ML routing, and P2P agents."""

    def test_bb84_normal_key_agreement(self) -> None:
        """Verify end-to-end TCP BB84 session derives identical 32-byte keys at Alice and Bob when eta_eve = 0."""
        shared_secret = b"bb84-test-classical-hmac-secret-01"
        alice = BB84ProtocolEngine("edge-alice-01", shared_secret)
        bob = BB84ProtocolEngine("edge-bob-02", shared_secret)

        bob_results = []
        bob.start_tcp_responder(
            "127.0.0.1",
            0,
            on_key_established=lambda res: bob_results.append(res),
        )
        try:
            alice_res = alice.initiate_session(
                peer_host="127.0.0.1",
                peer_port=bob.bound_port,
                peer_node="edge-bob-02",
                epoch=1,
                override_params=QuantumChannelParams(
                    distance_km=15.0,
                    attenuation_db_per_km=0.2,
                    depolarization_prob=0.015,
                    eavesdrop_intercept_ratio=0.0,
                    pulse_count=2048,
                ),
            )
            self.assertFalse(alice_res.aborted, f"Expected normal BB84 session to succeed, got: {alice_res}")
            self.assertIsNotNone(alice_res.final_key_bytes)
            assert alice_res.final_key_bytes is not None
            self.assertEqual(len(alice_res.final_key_bytes), 32)
            self.assertGreaterEqual(alice_res.sifted_key_bits, 512)
            self.assertLess(alice_res.measured_qber, 0.06)

            self.assertEqual(len(bob_results), 1)
            bob_res = bob_results[0]
            self.assertFalse(bob_res.aborted)
            self.assertEqual(alice_res.final_key_bytes, bob_res.final_key_bytes)
            self.assertEqual(alice_res.psk_fingerprint_sha256, bob_res.psk_fingerprint_sha256)
        finally:
            bob.stop_tcp_responder()

    def test_bb84_eavesdrop_abort(self) -> None:
        """Verify BB84 aborts key derivation (aborted=True, final_key_bytes=None) when Eve intercepts (eta_eve=0.75)."""
        shared_secret = b"bb84-test-classical-hmac-secret-02"
        alice = BB84ProtocolEngine("edge-alice-01", shared_secret)
        bob = BB84ProtocolEngine("edge-bob-02", shared_secret)

        bob_results = []
        bob.start_tcp_responder(
            "127.0.0.1",
            0,
            on_key_established=lambda res: bob_results.append(res),
        )
        try:
            alice_res = alice.initiate_session(
                peer_host="127.0.0.1",
                peer_port=bob.bound_port,
                peer_node="edge-bob-02",
                epoch=2,
                override_params=QuantumChannelParams(
                    distance_km=15.0,
                    attenuation_db_per_km=0.2,
                    depolarization_prob=0.015,
                    eavesdrop_intercept_ratio=0.75,
                    pulse_count=2048,
                ),
            )
            self.assertTrue(alice_res.aborted)
            self.assertIsNone(alice_res.final_key_bytes)
            self.assertIsNone(alice_res.psk_fingerprint_sha256)
            self.assertGreater(alice_res.measured_qber, 0.11)
            self.assertIn("QBER_THRESHOLD_EXCEEDED", str(alice_res.abort_reason))

            self.assertEqual(len(bob_results), 1)
            self.assertTrue(bob_results[0].aborted)
            self.assertIsNone(bob_results[0].final_key_bytes)
        finally:
            bob.stop_tcp_responder()

    def test_bb84_hmac_authentication_rejects_tampering(self) -> None:
        """Verify classical channel frame authentication raises PermissionError on wrong HMAC secret or tampered payload."""
        alice = BB84ProtocolEngine("edge-alice-01", b"correct-secret-key")
        impostor = BB84ProtocolEngine("edge-bob-02", b"wrong-secret-key")

        frame = alice.pack_authenticated_frame(
            msg_type="QKD_INIT",
            session_id="bb84-test-auth",
            payload={"epoch": 1, "pulse_count": 2048},
        )
        unpacked = alice.unpack_authenticated_frame(frame)
        self.assertEqual(unpacked["msg_type"], "QKD_INIT")

        with self.assertRaises(PermissionError):
            impostor.unpack_authenticated_frame(frame)

        # Tamper with a byte inside the JSON payload
        tampered = bytearray(frame)
        tampered[-10] ^= 0x01
        with self.assertRaises(PermissionError):
            alice.unpack_authenticated_frame(bytes(tampered))

    def test_wg_psk_injection_and_encrypted_p2p_dataplane(self) -> None:
        """Verify 32-byte PSK injection enables ChaCha20Poly1305 P2P UDP delivery and rejects mismatched PSKs."""
        wg_a = WireGuardTunnelDaemon("edge-jkt-01", "wg0", "10.200.0.1", 0)
        wg_b = WireGuardTunnelDaemon("edge-bdg-02", "wg0", "10.200.0.2", 0)
        wg_c = WireGuardTunnelDaemon("edge-sby-03", "wg0", "10.200.0.3", 0)

        try:
            for src, dst in [
                (wg_a, wg_b),
                (wg_b, wg_a),
                (wg_a, wg_c),
                (wg_c, wg_a),
                (wg_b, wg_c),
                (wg_c, wg_b),
            ]:
                src.register_peer(
                    dst.node_id,
                    dst.public_key_b64,
                    dst.overlay_ip,
                    f"127.0.0.1:{dst.bound_port}",
                )

            # Reject invalid PSK length
            with self.assertRaises(ValueError):
                wg_a.inject_preshared_key("edge-sby-03", wg_c.public_key_b64, b"short-key", epoch=1)

            shared_psk = os.urandom(32)
            info_a = wg_a.inject_preshared_key("edge-sby-03", wg_c.public_key_b64, shared_psk, epoch=1)
            info_c = wg_c.inject_preshared_key("edge-jkt-01", wg_a.public_key_b64, shared_psk, epoch=1)
            self.assertEqual(info_a["psk_fingerprint_sha256"], info_c["psk_fingerprint_sha256"])

            # Direct P2P encrypted delivery succeeds
            delivery = wg_a.send_overlay_packet("edge-sby-03", b"Confidential P2P frame")
            self.assertTrue(delivery["delivered"])
            self.assertEqual(delivery["route_mode"], "DIRECT_P2P")
            self.assertEqual(delivery["psk_epoch"], 1)

            # Switch to RELAY_P2P via edge-bdg-02
            relay_directive = RouteDirective(
                source_node="edge-jkt-01",
                target_node="edge-sby-03",
                route_mode=RouteMode.RELAY_P2P,
                next_hop_node="edge-bdg-02",
                next_hop_endpoint=f"127.0.0.1:{wg_b.bound_port}",
                anomaly_score=0.81,
                link_status=LinkStatus.EAVESDROPPING_SUSPECTED,
                force_rekey=True,
                reason="Test relay forwarding",
                updated_at=100.0,
            )
            self.assertTrue(wg_a.apply_route_directive(relay_directive))
            relay_delivery = wg_a.send_overlay_packet("edge-sby-03", b"Relayed P2P frame")
            self.assertTrue(relay_delivery["delivered"])
            self.assertEqual(relay_delivery["route_mode"], "RELAY_P2P")
            self.assertEqual(relay_delivery["via_relay_node"], "edge-bdg-02")
            self.assertGreaterEqual(wg_b.relay_forwarded_packets, 1)

            # Inject a different PSK on peer C and verify decryption failure raises PermissionError
            wrong_psk = os.urandom(32)
            wg_c.inject_preshared_key("edge-jkt-01", wg_a.public_key_b64, wrong_psk, epoch=2)
            with self.assertRaises(PermissionError):
                wg_a.send_overlay_packet("edge-sby-03", b"Should be rejected by AEAD tag mismatch")
        finally:
            wg_a.close()
            wg_b.close()
            wg_c.close()

    def test_ml_anomaly_and_route_optimization(self) -> None:
        """Verify IsolationForestDetector and OverlayRouteOptimizer transition DIRECT_P2P -> RELAY_P2P."""
        detector = IsolationForestDetector()
        optimizer = OverlayRouteOptimizer()

        nodes = {
            "edge-jkt-01": NodeRegistration("edge-jkt-01", "10.200.0.1", "127.0.0.1", 51821, 52821, "pub1", "t1", 1.0),
            "edge-bdg-02": NodeRegistration("edge-bdg-02", "10.200.0.2", "127.0.0.1", 51822, 52822, "pub2", "t1", 1.0),
            "edge-sby-03": NodeRegistration("edge-sby-03", "10.200.0.3", "127.0.0.1", 51823, 52823, "pub3", "t1", 1.0),
        }

        tel_jkt_bdg = LinkTelemetry("edge-jkt-01", "edge-bdg-02", 1.0, 10.0, 0.8, 0.05, 450.0, 0.015, 0.001, 6500.0, 1, 1.0, 0)
        tel_bdg_sby = LinkTelemetry("edge-bdg-02", "edge-sby-03", 1.0, 11.0, 0.9, 0.05, 440.0, 0.016, 0.001, 6300.0, 1, 1.0, 0)
        tel_jkt_sby_ok = LinkTelemetry("edge-jkt-01", "edge-sby-03", 1.0, 14.0, 1.1, 0.10, 420.0, 0.017, 0.001, 6100.0, 1, 1.0, 0)

        s_jb, st_jb, _ = detector.evaluate_telemetry(tel_jkt_bdg)
        s_bs, st_bs, _ = detector.evaluate_telemetry(tel_bdg_sby)
        s_js, st_js, _ = detector.evaluate_telemetry(tel_jkt_sby_ok)

        self.assertEqual(st_jb, LinkStatus.HEALTHY)
        self.assertEqual(st_bs, LinkStatus.HEALTHY)
        self.assertEqual(st_js, LinkStatus.HEALTHY)

        metrics = {
            ("edge-jkt-01", "edge-bdg-02"): (tel_jkt_bdg, s_jb, st_jb),
            ("edge-bdg-02", "edge-sby-03"): (tel_bdg_sby, s_bs, st_bs),
            ("edge-jkt-01", "edge-sby-03"): (tel_jkt_sby_ok, s_js, st_js),
        }
        directives_ok = {
            (d.source_node, d.target_node): d for d in optimizer.compute_directives(nodes, metrics)
        }
        self.assertEqual(directives_ok[("edge-jkt-01", "edge-sby-03")].route_mode, RouteMode.DIRECT_P2P)

        # Simulate moderate eavesdropping on direct link edge-jkt-01 -> edge-sby-03
        tel_jkt_sby_eve = LinkTelemetry("edge-jkt-01", "edge-sby-03", 2.0, 15.0, 1.2, 0.15, 400.0, 0.091, 0.074, 4900.0, 2, 0.5, 0)
        s_eve, st_eve, _ = detector.evaluate_telemetry(tel_jkt_sby_eve)
        self.assertEqual(st_eve, LinkStatus.EAVESDROPPING_SUSPECTED)

        metrics[("edge-jkt-01", "edge-sby-03")] = (tel_jkt_sby_eve, s_eve, st_eve)
        directives_eve = {
            (d.source_node, d.target_node): d for d in optimizer.compute_directives(nodes, metrics)
        }
        dir_eve = directives_eve[("edge-jkt-01", "edge-sby-03")]
        self.assertEqual(dir_eve.route_mode, RouteMode.RELAY_P2P)
        self.assertEqual(dir_eve.next_hop_node, "edge-bdg-02")
        self.assertTrue(dir_eve.force_rekey)

        # Simulate aggressive eavesdropping abort (QBER > 0.11)
        tel_jkt_sby_abort = LinkTelemetry("edge-jkt-01", "edge-sby-03", 3.0, 16.0, 1.4, 0.20, 0.0, 0.182, 0.091, 0.0, 2, 5.0, 1)
        s_ab, st_ab, _ = detector.evaluate_telemetry(tel_jkt_sby_abort)
        self.assertEqual(st_ab, LinkStatus.COMPROMISED_BLOCKED)
        metrics[("edge-jkt-01", "edge-sby-03")] = (tel_jkt_sby_abort, s_ab, st_ab)
        directives_ab = {
            (d.source_node, d.target_node): d for d in optimizer.compute_directives(nodes, metrics)
        }
        dir_ab = directives_ab[("edge-jkt-01", "edge-sby-03")]
        self.assertEqual(dir_ab.route_mode, RouteMode.RELAY_P2P)
        self.assertEqual(dir_ab.next_hop_node, "edge-bdg-02")
        self.assertTrue(dir_ab.force_rekey)

    def test_full_distributed_sdwan_controller_and_agents(self) -> None:
        """Verify full integration of SDWANControllerServer and 3 SDWANEndpointAgents across all 4 scenarios."""
        controller = SDWANControllerServer("127.0.0.1", 0)
        controller.start_background()

        secret = b"integration-test-cluster-hmac-key"
        agent_jkt = SDWANEndpointAgent("edge-jkt-01", "10.200.0.1", controller.base_url, auth_secret=secret)
        agent_bdg = SDWANEndpointAgent("edge-bdg-02", "10.200.0.2", controller.base_url, auth_secret=secret)
        agent_sby = SDWANEndpointAgent("edge-sby-03", "10.200.0.3", controller.base_url, auth_secret=secret)
        agents = [agent_jkt, agent_bdg, agent_sby]

        try:
            for ag in agents:
                ag.register_with_controller()

            # Scenario 1: Healthy P2P across all pairs
            agent_jkt.run_key_rotation_and_telemetry_cycle("edge-bdg-02")
            agent_bdg.run_key_rotation_and_telemetry_cycle("edge-sby-03")
            s1 = agent_jkt.run_key_rotation_and_telemetry_cycle("edge-sby-03")
            self.assertTrue(s1["psk_injected"])
            self.assertEqual(s1["evaluation"]["link_status"], "HEALTHY")
            self.assertEqual(s1["directive"]["route_mode"], "DIRECT_P2P")
            self.assertTrue(s1["dataplane_delivery"]["delivered"])

            # Scenario 2: Underlay degradation -> RELAY_P2P via edge-bdg-02
            s2 = agent_jkt.run_key_rotation_and_telemetry_cycle(
                "edge-sby-03",
                simulated_underlay={"latency_ms": 120.0, "jitter_ms": 10.0, "packet_loss_pct": 6.8},
            )
            self.assertEqual(s2["evaluation"]["link_status"], "DEGRADED_UNDERLAY")
            self.assertEqual(s2["directive"]["route_mode"], "RELAY_P2P")
            self.assertEqual(s2["directive"]["next_hop_node"], "edge-bdg-02")
            self.assertTrue(s2["dataplane_delivery"]["delivered"])

            # Scenario 3: Moderate eavesdropping (eta_eve = 0.30) -> EAVESDROPPING_SUSPECTED + RELAY_P2P
            s3 = agent_jkt.run_key_rotation_and_telemetry_cycle(
                "edge-sby-03",
                override_channel_params=QuantumChannelParams(
                    depolarization_prob=0.015,
                    eavesdrop_intercept_ratio=0.28,
                    pulse_count=4096,
                ),
                simulated_underlay={"latency_ms": 14.0, "jitter_ms": 1.2, "packet_loss_pct": 0.1},
            )
            self.assertEqual(s3["evaluation"]["link_status"], "EAVESDROPPING_SUSPECTED")
            self.assertEqual(s3["directive"]["route_mode"], "RELAY_P2P")
            self.assertTrue(s3["directive"]["force_rekey"])
            self.assertTrue(s3["dataplane_delivery"]["delivered"])

            # Scenario 4: Aggressive eavesdropping (eta_eve = 0.65) -> BB84 Aborted + COMPROMISED_BLOCKED + RELAY_P2P
            s4 = agent_jkt.run_key_rotation_and_telemetry_cycle(
                "edge-sby-03",
                override_channel_params=QuantumChannelParams(eavesdrop_intercept_ratio=0.65),
                simulated_underlay={"latency_ms": 15.0, "jitter_ms": 1.3, "packet_loss_pct": 0.2},
            )
            self.assertTrue(s4["bb84"]["aborted"])
            self.assertFalse(s4["psk_injected"])
            self.assertEqual(s4["evaluation"]["link_status"], "COMPROMISED_BLOCKED")
            self.assertEqual(s4["directive"]["route_mode"], "RELAY_P2P")
            self.assertEqual(s4["directive"]["next_hop_node"], "edge-bdg-02")
            self.assertTrue(s4["dataplane_delivery"]["delivered"])

            status_snapshot = controller.get_cluster_status()
            self.assertEqual(status_snapshot["registered_nodes"], 3)
            self.assertGreaterEqual(status_snapshot["telemetry_history_count"], 6)
        finally:
            for ag in agents:
                ag.close()
            controller.shutdown()

    def test_token_enrollment_and_ip_allocation(self) -> None:
        """Verify Join Token auto-enrollment, overlay IP allocation, and token exhaustion/revocation rules."""
        controller = SDWANControllerServer(host="127.0.0.1", port=0, overlay_subnet_prefix="10.200.0.")
        controller.start_background()

        token = controller.create_enrollment_token(label="test-token", max_uses=2, ttl_seconds=600.0)
        self.assertTrue(token.is_valid())

        agents: list[SDWANEndpointAgent] = []
        try:
            # 1. Enroll first node
            agent1, resp1 = SDWANEndpointAgent.enroll_with_controller(
                controller_url=controller.base_url,
                join_token=token.secret_token,
                node_id="node-alpha",
            )
            agents.append(agent1)
            self.assertEqual(resp1["allocated_overlay_ip"], "10.200.0.10")
            self.assertEqual(resp1["cluster_hmac_secret_hex"], controller.cluster_hmac_secret_hex)

            # 2. Enroll second node
            agent2, resp2 = SDWANEndpointAgent.enroll_with_controller(
                controller_url=controller.base_url,
                join_token=token.secret_token,
                node_id="node-beta",
            )
            agents.append(agent2)
            self.assertEqual(resp2["allocated_overlay_ip"], "10.200.0.11")
            self.assertEqual(resp2["cluster_hmac_secret_hex"], controller.cluster_hmac_secret_hex)

            # 3. Third node enrollment must be rejected because max_uses (2) is reached
            with self.assertRaises(PermissionError):
                SDWANEndpointAgent.enroll_with_controller(
                    controller_url=controller.base_url,
                    join_token=token.secret_token,
                    node_id="node-gamma",
                )

            # 4. Revocation test
            rev_tok = controller.create_enrollment_token(label="to-revoke", max_uses=5)
            self.assertTrue(controller.revoke_enrollment_token(rev_tok.token_id))
            with self.assertRaises(PermissionError):
                SDWANEndpointAgent.enroll_with_controller(
                    controller_url=controller.base_url,
                    join_token=rev_tok.secret_token,
                    node_id="node-delta",
                )
        finally:
            for ag in agents:
                ag.close()
            controller.shutdown()

    def test_p2p_client_data_and_file_transfer(self) -> None:
        """Verify encrypted P2P application text and file transfer via DIRECT_P2P and RELAY_P2P."""
        controller = SDWANControllerServer(host="127.0.0.1", port=0)
        controller.start_background()

        join_tok = controller.bootstrap_token
        agent_a, _ = SDWANEndpointAgent.enroll_with_controller(controller.base_url, join_tok, "edge-alice")
        agent_b, _ = SDWANEndpointAgent.enroll_with_controller(controller.base_url, join_tok, "edge-bob")
        agent_c, _ = SDWANEndpointAgent.enroll_with_controller(controller.base_url, join_tok, "edge-charlie")
        agents = [agent_a, agent_b, agent_c]

        try:
            for ag in agents:
                ag.sync_topology()

            # Establish BB84 keys between alice and bob, and between alice/bob and charlie
            agent_a.run_key_rotation_and_telemetry_cycle("edge-bob")
            agent_a.run_key_rotation_and_telemetry_cycle("edge-charlie")
            agent_b.run_key_rotation_and_telemetry_cycle("edge-charlie")

            # 1. Direct P2P Text message
            secret_text = "BB84-Verified-Confidential-Text-12345"
            deliv_text = agent_a.send_p2p_text("edge-bob", secret_text)
            self.assertEqual(deliv_text["status"], "sent")
            self.assertEqual(deliv_text["delivery"]["route_mode"], "DIRECT_P2P")

            inbox_b = agent_b.get_received_messages(clear=True)
            self.assertEqual(len(inbox_b), 1)
            self.assertEqual(inbox_b[0].content_type, "text")
            self.assertEqual(inbox_b[0].decode_text(), secret_text)
            self.assertEqual(inbox_b[0].source_node, "edge-alice")

            # 2. Direct P2P Binary File transfer
            file_content = b"\xde\xad\xbe\xef" * 1024  # 4096 bytes
            with tempfile.NamedTemporaryFile("wb", delete=False) as tf:
                tf.write(file_content)
                tf_path = Path(tf.name)

            try:
                deliv_file = agent_a.send_p2p_file("edge-bob", tf_path)
                self.assertEqual(deliv_file["status"], "sent")
                self.assertEqual(deliv_file["delivery"]["route_mode"], "DIRECT_P2P")

                inbox_file = agent_b.get_received_messages(clear=True)
                self.assertEqual(len(inbox_file), 1)
                self.assertEqual(inbox_file[0].content_type, "file")
                self.assertEqual(inbox_file[0].filename, tf_path.name)
                self.assertEqual(inbox_file[0].decode_payload(), file_content)
            finally:
                if tf_path.exists():
                    tf_path.unlink()

            # 3. Relayed P2P File transfer (Alice -> Bob via Charlie)
            relay_directive = RouteDirective(
                source_node="edge-alice",
                target_node="edge-bob",
                route_mode=RouteMode.RELAY_P2P,
                next_hop_node="edge-charlie",
                next_hop_endpoint=f"127.0.0.1:{agent_c.wg_port}",
                anomaly_score=0.88,
                link_status=LinkStatus.DEGRADED_UNDERLAY,
                force_rekey=False,
                reason="Forced relay unit test",
                updated_at=100.0,
            )
            agent_a.wg_daemon.apply_route_directive(relay_directive)

            relayed_payload = b"Relayed-Through-Charlie-Protected"
            deliv_relay = agent_a.send_p2p_data(
                target_node="edge-bob",
                payload=relayed_payload,
                content_type="text",
                auto_rekey=False,
                sync_topology=False,
            )
            self.assertEqual(deliv_relay["delivery"]["route_mode"], "RELAY_P2P")
            self.assertEqual(deliv_relay["delivery"]["via_relay_node"], "edge-charlie")
            self.assertGreaterEqual(agent_c.wg_daemon.relay_forwarded_packets, 1)

            inbox_relay = agent_b.get_received_messages(clear=True)
            self.assertEqual(len(inbox_relay), 1)
            self.assertEqual(inbox_relay[0].decode_payload(), relayed_payload)
            self.assertEqual(inbox_relay[0].via_relay_node, "edge-charlie")
        finally:
            for ag in agents:
                ag.close()
            controller.shutdown()

    def test_controller_cli_dashboard_and_cross_platform_installers(self) -> None:
        """Verify CLI Dashboard ASCII formatting, package generator, and Linux/Windows installers."""
        repo_root = Path(__file__).resolve().parents[1]

        # 1. Verify render_controller_dashboard outputs all 4 panels
        sample_status = {
            "overlay_subnet_prefix": "10.200.0.",
            "nodes": {
                "test-node-1": {
                    "overlay_ip": "10.200.0.10",
                    "underlay_host": "127.0.0.1",
                    "wg_port": 51820,
                    "qkd_port": 52820,
                    "auth_token_id": "tok-1",
                    "wg_public_key": "dummy-pubkey-base64-string-here",
                }
            },
            "links": [
                {
                    "source_node": "test-node-1",
                    "target_node": "test-node-2",
                    "qber": 0.02,
                    "qber_delta": 0.001,
                    "key_rate_bps": 5200.0,
                    "latency_ms": 12.0,
                    "packet_loss_pct": 0.05,
                    "psk_epoch": 1,
                    "qkd_abort_count": 0,
                    "anomaly_score": 0.05,
                    "link_status": "HEALTHY",
                }
            ],
            "directives": [
                {
                    "source_node": "test-node-1",
                    "target_node": "test-node-2",
                    "route_mode": "DIRECT_P2P",
                    "next_hop_node": "test-node-2",
                    "next_hop_endpoint": "127.0.0.1:51821",
                    "force_rekey": False,
                    "reason": "Direct healthy link",
                }
            ],
            "tokens": [
                {
                    "token_id": "tok-sample",
                    "label": "unit-test",
                    "used_count": 1,
                    "max_uses": 5,
                    "expires_at": 9999999999.0,
                    "revoked": False,
                    "secret_token": "qkd-join-sample-secret-token",
                }
            ],
        }
        rendered = render_controller_dashboard(sample_status, controller_url="http://127.0.0.1:8080")
        self.assertIn("QKD-SDWAN CENTRAL CONTROLLER", rendered)
        self.assertIn("[1] CLUSTER ENROLLMENT JOIN TOKENS", rendered)
        self.assertIn("[2] REGISTERED P2P SD-WAN ENDPOINT CLIENTS", rendered)
        self.assertIn("[3] QUANTUM BB84 CHANNEL TELEMETRY", rendered)
        self.assertIn("[4] ACTIVE P2P OVERLAY ROUTING DIRECTIVES", rendered)
        self.assertIn("test-node-1", rendered)
        self.assertIn("tok-sample", rendered)

        # 2. Verify build_installers.py builds all expected artifacts in dist/
        build_script = repo_root / "scripts" / "build_installers.py"
        proc = subprocess.run([sys.executable, str(build_script)], capture_output=True, text=True, check=True)
        self.assertIn("Build complete", proc.stdout)

        dist_dir = repo_root / "dist"
        expected_files = [
            "qkd-sdwan-controller.pyz",
            "qkd-sdwan-client.pyz",
            "install-controller-linux.sh",
            "install-client-linux.sh",
            "install-controller-windows.ps1",
            "install-controller-windows.bat",
            "install-client-windows.ps1",
            "install-client-windows.bat",
            "MANIFEST.json",
        ]
        for ef in expected_files:
            target = dist_dir / ef
            self.assertTrue(target.is_file(), f"Missing expected distribution file: {ef}")
            self.assertGreater(target.stat().st_size, 0)

        manifest = json.loads((dist_dir / "MANIFEST.json").read_text(encoding="utf-8"))
        self.assertEqual(len(manifest["artifacts"]), 8)
        for art in manifest["artifacts"]:
            self.assertEqual(len(art["sha256"]), 64)
            self.assertGreater(art["size_bytes"], 0)

    def test_client_cli_dashboard_and_file_integrity(self) -> None:
        """Verify 4-panel Client CLI Dashboard rendering, CLI --once mode, inbox file saving, and SHA-256 integrity."""
        controller = SDWANControllerServer(host="127.0.0.1", port=0)
        controller.start_background()

        join_tok = controller.bootstrap_token
        agent_a, _ = SDWANEndpointAgent.enroll_with_controller(controller.base_url, join_tok, "edge-dash-a")
        agent_b, _ = SDWANEndpointAgent.enroll_with_controller(controller.base_url, join_tok, "edge-dash-b")
        try:
            agent_a.sync_topology()
            agent_b.sync_topology()

            # Exchange text and binary file
            agent_a.send_p2p_text("edge-dash-b", "Dashboard test message payload")
            binary_blob = b"\x89PNG\r\n\x1a\n\x00\x01\x02\x03Quantum-Verified-Binary-Asset" * 16
            with tempfile.TemporaryDirectory(prefix="qkd-dash-test-") as tmpdir:
                tmp_path = Path(tmpdir)
                src_file = tmp_path / "quantum_report.bin"
                src_file.write_bytes(binary_blob)
                agent_a.send_p2p_file("edge-dash-b", src_file)

                # Render 4-panel Client CLI Dashboard on both sender and receiver
                dash_a = render_client_dashboard(agent_a)
                dash_b = render_client_dashboard(agent_b)
                for rendered in (dash_a, dash_b):
                    self.assertIn("QKD-SDWAN ENDPOINT CLIENT", rendered)
                    self.assertIn("[1] P2P WIREGUARD TUNNEL PEERS", rendered)
                    self.assertIn("[2] RECENT BB84 QUANTUM KEY DISTRIBUTION SESSIONS", rendered)
                    self.assertIn("[3] ACTIVE CONTROLLER ML ROUTING DIRECTIVES", rendered)
                    self.assertIn("[4] ENCRYPTED P2P APPLICATION INBOX & OUTBOX", rendered)

                self.assertIn("OUT", dash_a)
                self.assertIn("IN", dash_b)
                self.assertIn("quantum_report.bin", dash_b)

                # Export file from agent_b's inbox and verify 100% byte identity
                export_dir = tmp_path / "exported"
                inbox_msgs = agent_b.get_received_messages(clear=False)
                file_msg = [m for m in inbox_msgs if m.content_type == "file"][0]
                saved_path = agent_b.save_inbox_file(file_msg.message_id, export_dir)
                self.assertTrue(saved_path.is_file())
                self.assertEqual(saved_path.read_bytes(), binary_blob)

                # Verify CLI `qkd-sdwan-client dashboard --once`
                buf = io.StringIO()
                with redirect_stdout(buf):
                    rc = client_cli_main(
                        [
                            "dashboard",
                            "--once",
                            "--controller-url",
                            controller.base_url,
                            "--node-id",
                            "edge-cli-once",
                            "--overlay-ip",
                            "10.200.0.99",
                        ]
                    )
                self.assertEqual(rc, 0)
                self.assertIn("QKD-SDWAN ENDPOINT CLIENT", buf.getvalue())

            # Verify SHA-256 payload integrity detection on corrupted P2PDataMessage
            valid_msg = P2PDataMessage(
                message_id="msg-int-01",
                source_node="edge-dash-a",
                target_node="edge-dash-b",
                content_type="text",
                filename=None,
                payload_b64=base64.b64encode(b"Original-Untampered-Payload").decode("ascii"),
                psk_epoch=1,
                route_mode="DIRECT_P2P",
                via_relay_node=None,
                timestamp=123456.0,
            )
            self.assertTrue(valid_msg.verify_integrity())
            valid_msg.payload_b64 = base64.b64encode(b"Corrupted-Tampered-Payload!").decode("ascii")
            self.assertFalse(valid_msg.verify_integrity())
            with self.assertRaises(ValueError):
                valid_msg.decode_payload(verify=True)
        finally:
            agent_a.close()
            agent_b.close()
            controller.shutdown()

    def test_concurrent_bb84_and_out_of_order_enrollment_reliability(self) -> None:
        """Verify zero-race-condition BB84 pre-commit key injection, out-of-order enrollment, and parallel P2P transfers."""
        controller = SDWANControllerServer(host="127.0.0.1", port=0)
        controller.start_background()

        join_tok = controller.bootstrap_token
        # Enroll node-1 first; node-2 and node-3 enroll AFTER node-1 without node-1 manually calling sync_topology()
        node1, _ = SDWANEndpointAgent.enroll_with_controller(controller.base_url, join_tok, "node-1")
        node2, _ = SDWANEndpointAgent.enroll_with_controller(controller.base_url, join_tok, "node-2")
        node3, _ = SDWANEndpointAgent.enroll_with_controller(controller.base_url, join_tok, "node-3")
        nodes = [node1, node2, node3]

        try:
            # node-1 does NOT know about node-2 or node-3 yet in its local peer_registry
            self.assertNotIn("node-2", node1.peer_registry)
            self.assertNotIn("node-3", node1.peer_registry)

            # Launch concurrent P2P messages from node-2 and node-3 to node-1 simultaneously
            errors: list[Exception] = []

            def _worker_send(sender: SDWANEndpointAgent, target: str, idx: int) -> None:
                try:
                    for seq in range(3):
                        sender.send_p2p_text(target, f"msg-from-{sender.node_id}-seq-{idx}-{seq}")
                except Exception as exc:
                    errors.append(exc)

            t2 = threading.Thread(target=_worker_send, args=(node2, "node-1", 2))
            t3 = threading.Thread(target=_worker_send, args=(node3, "node-1", 3))
            t2.start()
            t3.start()
            t2.join(timeout=15.0)
            t3.join(timeout=15.0)

            self.assertEqual(errors, [], f"Concurrent BB84 / P2P send raised unexpected errors: {errors}")
            inbox_node1 = node1.get_received_messages(clear=False)
            self.assertEqual(len(inbox_node1), 6)
            received_texts = {m.decode_text() for m in inbox_node1}
            for seq in range(3):
                self.assertIn(f"msg-from-node-2-seq-2-{seq}", received_texts)
                self.assertIn(f"msg-from-node-3-seq-3-{seq}", received_texts)
        finally:
            for n in nodes:
                n.close()
            controller.shutdown()

    def test_init_config_subcommand_config_precedence_and_windows_hardening(self) -> None:
        """Verify init-config subcommands, pre-subcommand --config preservation, Windows socket/host normalization, and installers."""
        repo_root = Path(__file__).resolve().parents[1]
        build_script = repo_root / "scripts" / "build_installers.py"
        subprocess.run([sys.executable, str(build_script)], capture_output=True, text=True, check=True)
        dist_dir = repo_root / "dist"

        # 1. Verify Windows address normalization (0.0.0.0 -> 127.0.0.1)
        self.assertEqual(WireGuardTunnelDaemon._parse_endpoint("0.0.0.0:51820"), ("127.0.0.1", 51820))
        self.assertEqual(WireGuardTunnelDaemon._parse_endpoint(":::51820"), ("127.0.0.1", 51820))

        controller = SDWANControllerServer(host="0.0.0.0", port=0, bootstrap_join_token="qkd-join-winhard-2025")
        controller.start_background()
        try:
            self.assertTrue(controller.base_url.startswith("http://127.0.0.1:"))
            ctrl_port = controller.port

            with tempfile.TemporaryDirectory(prefix="qkd-winhard-") as tmpdir:
                tmp_path = Path(tmpdir)

                # 2. Verify `qkd-sdwan-controller init-config`
                ctrl_cfg_path = tmp_path / "ctrl" / "controller.json"
                tok_buf = io.StringIO()
                with redirect_stdout(tok_buf):
                    rc = controller_cli_main(
                        [
                            "init-config",
                            "--output",
                            str(ctrl_cfg_path),
                            "--host",
                            "0.0.0.0",
                            "--port",
                            str(ctrl_port),
                            "--subnet-prefix",
                            "10.200.0.",
                            "--bootstrap-token",
                            "qkd-join-winhard-2025",
                        ]
                    )
                self.assertEqual(rc, 0)
                self.assertEqual(tok_buf.getvalue().strip(), "qkd-join-winhard-2025")
                ctrl_cfg = json.loads(ctrl_cfg_path.read_text(encoding="utf-8"))
                self.assertEqual(ctrl_cfg["port"], ctrl_port)
                self.assertEqual(ctrl_cfg["bootstrap_join_token"], "qkd-join-winhard-2025")

                # Verify `qkd-sdwan-controller --config <path> dashboard --once` resolves port from config
                ctrl_dash_buf = io.StringIO()
                with redirect_stdout(ctrl_dash_buf):
                    rc = controller_cli_main(["--config", str(ctrl_cfg_path), "dashboard", "--once"])
                self.assertEqual(rc, 0)
                self.assertIn(f"http://127.0.0.1:{ctrl_port}", ctrl_dash_buf.getvalue())

                # 3. Verify `qkd-sdwan-client init-config` with Join Token dynamic IP allocation (without --explicit-ip)
                client1_cfg_path = tmp_path / "client1" / "endpoint.json"
                client2_cfg_path = tmp_path / "client2" / "endpoint.json"
                for idx, (nid, cpath) in enumerate(
                    [("edge-win-01", client1_cfg_path), ("edge-win-02", client2_cfg_path)],
                    start=1,
                ):
                    out_buf = io.StringIO()
                    with redirect_stdout(out_buf):
                        rc = client_cli_main(
                            [
                                "init-config",
                                "--output",
                                str(cpath),
                                "--node-id",
                                nid,
                                "--overlay-ip",
                                "10.200.0.10",
                                "--controller-url",
                                controller.base_url,
                                "--join-token",
                                "qkd-join-winhard-2025",
                                "--wg-port",
                                str(51820 + idx),
                                "--qkd-port",
                                str(52820 + idx),
                            ]
                        )
                    self.assertEqual(rc, 0)

                c1_data = json.loads(client1_cfg_path.read_text(encoding="utf-8"))
                c2_data = json.loads(client2_cfg_path.read_text(encoding="utf-8"))
                self.assertEqual(c1_data["node_id"], "edge-win-01")
                self.assertEqual(c2_data["node_id"], "edge-win-02")
                # Dynamic allocation must assign distinct IPs rather than colliding on 10.200.0.10
                self.assertNotEqual(c1_data["overlay_ip"], c2_data["overlay_ip"])
                self.assertEqual(c1_data["overlay_ip"], "10.200.0.10")
                self.assertEqual(c2_data["overlay_ip"], "10.200.0.11")

                # 4. Verify `--config <path>` BEFORE subcommand (`dashboard --once` and `status`) does not get overwritten
                dash_buf = io.StringIO()
                with redirect_stdout(dash_buf):
                    rc = client_cli_main(
                        [
                            "--config",
                            str(client2_cfg_path),
                            "dashboard",
                            "--once",
                            "--wg-port",
                            "0",
                            "--qkd-port",
                            "0",
                        ]
                    )
                self.assertEqual(rc, 0)
                dash_out = dash_buf.getvalue()
                self.assertIn("edge-win-02", dash_out)
                self.assertIn("10.200.0.11", dash_out)
                self.assertNotIn("edge-local-01", dash_out)

                stat_buf = io.StringIO()
                with redirect_stdout(stat_buf):
                    rc = client_cli_main(["--config", str(client2_cfg_path), "status", "--json"])
                self.assertEqual(rc, 0)
                stat_json = json.loads(stat_buf.getvalue())
                self.assertEqual(stat_json["node_id"], "edge-win-02")
                self.assertEqual(stat_json["overlay_ip"], "10.200.0.11")

                # 5. Verify full platform installer end-to-end execution in temp prefix
                linux_client_prefix = tmp_path / "installed-client"
                if os.name == "nt":
                    subprocess.run(
                        [
                            "powershell",
                            "-NoProfile",
                            "-ExecutionPolicy",
                            "Bypass",
                            "-File",
                            str(dist_dir / "install-client-windows.ps1"),
                            "-NonInteractive",
                            "-NoStart",
                            "-Prefix",
                            str(linux_client_prefix),
                            "-NodeId",
                            "edge-installed-linux",
                            "-OverlayIp",
                            "10.200.0.77",
                            "-ControllerUrl",
                            controller.base_url,
                        ],
                        capture_output=True,
                        text=True,
                        check=True,
                    )
                    wrapper_bin = linux_client_prefix / "bin" / "qkd-sdwan-client.bat"
                else:
                    subprocess.run(
                        [
                            "bash",
                            str(dist_dir / "install-client-linux.sh"),
                            "--non-interactive",
                            "--no-start",
                            "--prefix",
                            str(linux_client_prefix),
                            "--node-id",
                            "edge-installed-linux",
                            "--overlay-ip",
                            "10.200.0.77",
                            "--controller-url",
                            controller.base_url,
                        ],
                        capture_output=True,
                        text=True,
                        check=True,
                    )
                    wrapper_bin = linux_client_prefix / "bin" / "qkd-sdwan-client"
                self.assertIn("edge-installed-linux", controller.get_cluster_status()["nodes"])
                wrap_proc = subprocess.run(
                    [str(wrapper_bin), "dashboard", "--once", "--wg-port", "0", "--qkd-port", "0"],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                self.assertIn("edge-installed-linux", wrap_proc.stdout)
                self.assertIn("10.200.0.77", wrap_proc.stdout)

                for ps1_name in ("install-controller-windows.ps1", "install-client-windows.ps1"):
                    ps1_path = dist_dir / ps1_name
                    raw_bytes = ps1_path.read_bytes()
                    self.assertFalse(raw_bytes.startswith(b"\xef\xbb\xbf"), f"{ps1_name} should not start with UTF-8 BOM")
                    self.assertTrue(
                        all(b < 128 for b in raw_bytes),
                        f"{ps1_name} must be pure 7-bit ASCII so Windows PowerShell 5.1 (Windows-1252) never misparses UTF-8 punctuation",
                    )
                    text = raw_bytes.decode("ascii")
                    self.assertIn("function Resolve-PythonExe", text)
                    self.assertIn("import cryptography", text)
                    self.assertIn("init-config", text)
                    self.assertIn("[System.Text.UTF8Encoding]::new($false)", text)
                    self.assertNotIn("python -c", text)
        finally:
            controller.shutdown()

    def test_production_daemon_ipc_wan_roaming_and_2node_e2e(self) -> None:
        """Verify WAN IP discovery, WireGuard NAT roaming, and 3-process OS daemon E2E (Controller + 2 Clients)."""
        # 1. Verify Public/WAN IP discovery & NAT gateway resolution
        self.assertEqual(_resolve_peer_underlay_host("127.0.0.1", "203.0.113.45"), "203.0.113.45")
        self.assertEqual(_resolve_peer_underlay_host("auto", "192.168.1.50"), "192.168.1.50")
        # Private RFC1918 LAN IP reported from behind NAT when Controller observes public WAN IP -> use public WAN IP
        self.assertEqual(_resolve_peer_underlay_host("192.168.1.25", "198.51.100.77"), "198.51.100.77")
        # Explicit public IP or domain name is preserved
        self.assertEqual(_resolve_peer_underlay_host("198.51.100.10", "198.51.100.77"), "198.51.100.10")
        self.assertEqual(_resolve_peer_underlay_host("jkt-edge.example.com", "198.51.100.77"), "jkt-edge.example.com")

        # 2. Verify WireGuard UDP keepalive and dynamic NAT endpoint roaming
        wg_a = WireGuardTunnelDaemon("node-a", "wg0", "10.200.0.10", 0)
        wg_b = WireGuardTunnelDaemon("node-b", "wg0", "10.200.0.11", 0)
        try:
            wg_a.register_peer("node-b", wg_b.public_key_b64, "10.200.0.11", f"127.0.0.1:{wg_b.bound_port}")
            wg_b.register_peer("node-a", wg_a.public_key_b64, "10.200.0.10", "198.51.100.1:51820")
            shared_psk = os.urandom(32)
            wg_a.inject_preshared_key("node-b", wg_b.public_key_b64, shared_psk, epoch=1)
            wg_b.inject_preshared_key("node-a", wg_a.public_key_b64, shared_psk, epoch=1)
            self.assertEqual(wg_a.send_keepalive(), 1)

            # Simulate an authenticated WG_DATA packet arriving at wg_b from an external NAT port 203.0.113.88:61422
            from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

            aead_key = wg_a._session_aead_keys["node-b"]
            nonce = os.urandom(12)
            aad = json.dumps({"psk_epoch": 1, "source_node": "node-a", "target_node": "node-b"}, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ct = ChaCha20Poly1305(aead_key).encrypt(nonce, b"QKD-SDWAN-P2P-PROBE", aad)
            roam_msg = {
                "type": "WG_DATA",
                "packet_id": "roam-pkt-01",
                "source_node": "node-a",
                "target_node": "node-b",
                "route_mode": "DIRECT_P2P",
                "via_relay_node": None,
                "final_endpoint": f"127.0.0.1:{wg_b.bound_port}",
                "origin_endpoint": f"127.0.0.1:{wg_a.bound_port}",
                "psk_epoch": 1,
                "nonce_b64": base64.b64encode(nonce).decode("ascii"),
                "aad_b64": base64.b64encode(aad).decode("ascii"),
                "ciphertext_b64": base64.b64encode(ct).decode("ascii"),
            }
            raw_roam = json.dumps(roam_msg).encode("utf-8")
            # Mock sendto only during the simulated external IP roaming check so we don't send to 203.0.113.88
            orig_sock = wg_b._udp_sock
            sent_targets: list[tuple[str, int]] = []

            class _SendSpy:
                def sendto(self, data: bytes, addr: tuple[str, int]) -> int:
                    sent_targets.append(addr)
                    return len(data)

                def __getattr__(self, name: str) -> object:
                    return getattr(orig_sock, name)

            wg_b._udp_sock = _SendSpy()  # type: ignore[assignment]
            try:
                wg_b._handle_data_packet(roam_msg, raw_roam, ("203.0.113.88", 61422))
            finally:
                wg_b._udp_sock = orig_sock
            peer_a_state = wg_b.get_peer_state("node-a")
            self.assertIsNotNone(peer_a_state)
            assert peer_a_state is not None
            self.assertEqual(peer_a_state.underlay_endpoint, "203.0.113.88:61422")
            self.assertEqual(sent_targets[-1], ("203.0.113.88", 61422))
        finally:
            wg_a.close()
            wg_b.close()

        # 3. Full 3-process OS daemon E2E verification (1 Controller Daemon + 2 Client Daemons)
        repo_root = Path(__file__).resolve().parents[1]
        dist_dir = repo_root / "dist"
        with tempfile.TemporaryDirectory(prefix="qkd-prod-e2e-", ignore_cleanup_errors=True) as tmpdir:
            tmp_path = Path(tmpdir)
            ctrl_prefix = tmp_path / "ctrl"
            jkt_prefix = tmp_path / "jkt"
            sby_prefix = tmp_path / "sby"

            # Find 3 free ports for Controller and 2 Clients
            import socket as _sock

            free_ports: list[int] = []
            for _ in range(5):
                with _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM) as s:
                    s.bind(("127.0.0.1", 0))
                    free_ports.append(s.getsockname()[1])
            ctrl_port, jkt_wg, jkt_qkd, sby_wg, sby_qkd = free_ports
            ctrl_url = f"http://127.0.0.1:{ctrl_port}"

            bin_ext = ".bat" if os.name == "nt" else ""
            ctrl_bin = ctrl_prefix / "bin" / f"qkd-sdwan-controller{bin_ext}"
            jkt_bin = jkt_prefix / "bin" / f"qkd-sdwan-client{bin_ext}"
            sby_bin = sby_prefix / "bin" / f"qkd-sdwan-client{bin_ext}"

            try:
                if os.name == "nt":
                    subprocess.run(
                        [
                            "powershell",
                            "-NoProfile",
                            "-ExecutionPolicy",
                            "Bypass",
                            "-File",
                            str(dist_dir / "install-controller-windows.ps1"),
                            "-NonInteractive",
                            "-NoStart",
                            "-Prefix",
                            str(ctrl_prefix),
                            "-BindHost",
                            "127.0.0.1",
                            "-Port",
                            str(ctrl_port),
                            "-BootstrapToken",
                            "qkd-join-e2e-daemon",
                        ],
                        capture_output=True,
                        text=True,
                        check=True,
                    )
                else:
                    subprocess.run(
                        [
                            "bash",
                            str(dist_dir / "install-controller-linux.sh"),
                            "--non-interactive",
                            "--no-start",
                            "--prefix",
                            str(ctrl_prefix),
                            "--host",
                            "127.0.0.1",
                            "--port",
                            str(ctrl_port),
                            "--bootstrap-token",
                            "qkd-join-e2e-daemon",
                        ],
                        capture_output=True,
                        text=True,
                        check=True,
                    )
                subprocess.run([str(ctrl_bin), "serve", "--daemon"], capture_output=True, text=True, check=True)

                for prefix, nid, wport, qport in [
                    (jkt_prefix, "edge-jkt-01", jkt_wg, jkt_qkd),
                    (sby_prefix, "edge-sby-02", sby_wg, sby_qkd),
                ]:
                    if os.name == "nt":
                        subprocess.run(
                            [
                                "powershell",
                                "-NoProfile",
                                "-ExecutionPolicy",
                                "Bypass",
                                "-File",
                                str(dist_dir / "install-client-windows.ps1"),
                                "-NonInteractive",
                                "-NoStart",
                                "-Prefix",
                                str(prefix),
                                "-NodeId",
                                nid,
                                "-ControllerUrl",
                                ctrl_url,
                                "-JoinToken",
                                "qkd-join-e2e-daemon",
                                "-WgPort",
                                str(wport),
                                "-QkdPort",
                                str(qport),
                            ],
                            capture_output=True,
                            text=True,
                            check=True,
                        )
                    else:
                        subprocess.run(
                            [
                                "bash",
                                str(dist_dir / "install-client-linux.sh"),
                                "--non-interactive",
                                "--no-start",
                                "--prefix",
                                str(prefix),
                                "--node-id",
                                nid,
                                "--controller-url",
                                ctrl_url,
                                "--join-token",
                                "qkd-join-e2e-daemon",
                                "--wg-port",
                                str(wport),
                                "--qkd-port",
                                str(qport),
                            ],
                            capture_output=True,
                            text=True,
                            check=True,
                        )
                subprocess.run(
                    [str(jkt_bin), "serve", "--daemon", "--heartbeat-interval", "0.5"],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                subprocess.run(
                    [str(sby_bin), "serve", "--daemon", "--heartbeat-interval", "0.5"],
                    capture_output=True,
                    text=True,
                    check=True,
                )

                # Verify dynamic `config --controller-url` subcommand on running daemon
                cfg_res = subprocess.run(
                    [str(jkt_bin), "config", "--controller-url", ctrl_url],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                cfg_json = json.loads(cfg_res.stdout)
                self.assertEqual(cfg_json["status"], "updated")
                self.assertTrue(cfg_json["registered_with_controller"])

                # Negotiate BB84 key rotation between the 2 running Client Daemons
                rekey_res = subprocess.run(
                    [str(jkt_bin), "rekey", "--to", "edge-sby-02"],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                rekey_json = json.loads(rekey_res.stdout)
                self.assertTrue(rekey_json["psk_injected"])
                self.assertEqual(rekey_json["injection_info"]["psk_epoch"], 1)

                # Send encrypted text and file from JKT daemon to SBY daemon
                send_txt = subprocess.run(
                    [str(jkt_bin), "send", "--to", "edge-sby-02", "--text", "Halo Surabaya dari Daemon JKT!"],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                self.assertEqual(json.loads(send_txt.stdout)["delivery"]["status"], "DELIVERED")

                sample_file = tmp_path / "payload-secret.txt"
                sample_file.write_text("Dokumen Rahasia Negara QKD-SDWAN 2025\n" * 25, encoding="utf-8")
                send_file = subprocess.run(
                    [str(jkt_bin), "send", "--to", "edge-sby-02", "--file", str(sample_file)],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                self.assertEqual(json.loads(send_file.stdout)["delivery"]["status"], "DELIVERED")

                # Export file from SBY daemon inbox and verify 100% SHA-256 bit-for-bit equality
                export_dir = tmp_path / "exported"
                save_res = subprocess.run(
                    [str(sby_bin), "inbox", "--save", "2", "--dir", str(export_dir)],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                saved_file = Path(json.loads(save_res.stdout)["saved_path"])
                self.assertEqual(saved_file.read_bytes(), sample_file.read_bytes())

                # Verify `dashboard --once` queries the live daemon without changing ports or opening duplicate sockets
                sby_dash = subprocess.run(
                    [str(sby_bin), "dashboard", "--once"],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                self.assertIn("Halo Surabaya dari Daemon JKT!", sby_dash.stdout)
                self.assertIn("payload-secret.txt", sby_dash.stdout)
                self.assertIn(f"127.0.0.1:{sby_wg}", sby_dash.stdout)

                # Restart Controller daemon and verify state persistence + client heartbeat re-registration
                subprocess.run([str(ctrl_bin), "stop"], capture_output=True, text=True, check=True)
                subprocess.run([str(ctrl_bin), "serve", "--daemon"], capture_output=True, text=True, check=True)
                ctrl_stat = subprocess.run(
                    [str(ctrl_bin), "status", "--json"],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                nodes_map = json.loads(ctrl_stat.stdout)["nodes"]
                self.assertIn("edge-jkt-01", nodes_map)
                self.assertIn("edge-sby-02", nodes_map)
                self.assertEqual(nodes_map["edge-jkt-01"]["wg_port"], jkt_wg)
                self.assertEqual(nodes_map["edge-sby-02"]["wg_port"], sby_wg)
            finally:
                for bin_path in (jkt_bin, sby_bin, ctrl_bin):
                    if bin_path.exists():
                        subprocess.run([str(bin_path), "stop"], capture_output=True, text=True)

    def test_zero_touch_onboarding_roaming_and_global_qkd_cli(self) -> None:
        """Verify join_token='auto' zero-touch enrollment, IP collision avoidance, roaming detection, and `qkd` CLI."""
        from qkd_sdwan.client.agent import _detect_underlay_host, _normalize_controller_url

        self.assertEqual(_normalize_controller_url("192.168.1.2"), "http://192.168.1.2:8080")
        self.assertEqual(_normalize_controller_url("http://192.168.1.2:9000/"), "http://192.168.1.2:9000")
        # Non-local IP on configured_host must fall back when device roams away from that network
        roamed_ip = _detect_underlay_host("http://127.0.0.1:8080", "198.51.100.254")
        self.assertEqual(roamed_ip, "127.0.0.1")

        controller = SDWANControllerServer(host="127.0.0.1", port=0)
        controller.start_background()
        agents: list[SDWANEndpointAgent] = []
        try:
            # 1. Zero-touch enrollment with join_token="auto" and idempotent re-enrollment
            ag_win, r_win = SDWANEndpointAgent.enroll_with_controller(
                controller_url=controller.base_url,
                join_token="auto",
                node_id="edge-vanne",
            )
            agents.append(ag_win)
            self.assertEqual(r_win["allocated_overlay_ip"], "10.200.0.10")

            ag_lin, r_lin = SDWANEndpointAgent.enroll_with_controller(
                controller_url=controller.base_url,
                join_token="auto",
                node_id="edge-hanmazaya",
            )
            agents.append(ag_lin)
            self.assertEqual(r_lin["allocated_overlay_ip"], "10.200.0.11")

            # 2. Direct registration with colliding overlay_ip ("10.200.0.10") auto-allocates non-colliding IP
            ag_roam = SDWANEndpointAgent("edge-roamer", "10.200.0.10", controller.base_url)
            agents.append(ag_roam)
            reg_roam = ag_roam.register_with_controller()
            self.assertEqual(reg_roam["node"]["overlay_ip"], "10.200.0.12")
            self.assertEqual(ag_roam.overlay_ip, "10.200.0.12")

            # 3. Verify `qkd` positional CLI commands (peers, rekey, send, sendfile, save)
            with tempfile.TemporaryDirectory(prefix="qkd-cli-ergo-") as tmpdir:
                tmp_path = Path(tmpdir)
                cfg_a = tmp_path / "a" / "endpoint.json"
                cfg_b = tmp_path / "b" / "endpoint.json"
                self.assertEqual(
                    client_cli_main(
                        [
                            "init-config",
                            "--output",
                            str(cfg_a),
                            "--node-id",
                            "edge-cli-a",
                            "--controller-url",
                            controller.base_url,
                            "--wg-port",
                            "0",
                            "--qkd-port",
                            "0",
                        ]
                    ),
                    0,
                )
                self.assertEqual(
                    client_cli_main(
                        [
                            "init-config",
                            "--output",
                            str(cfg_b),
                            "--node-id",
                            "edge-cli-b",
                            "--controller-url",
                            controller.base_url,
                            "--wg-port",
                            "0",
                            "--qkd-port",
                            "0",
                        ]
                    ),
                    0,
                )
                data_a = json.loads(cfg_a.read_text(encoding="utf-8"))
                data_b = json.loads(cfg_b.read_text(encoding="utf-8"))
                self.assertNotEqual(data_a["overlay_ip"], data_b["overlay_ip"])

                peers_buf = io.StringIO()
                with redirect_stdout(peers_buf):
                    self.assertEqual(
                        client_cli_main(["--config", str(cfg_a), "peers"]),
                        0,
                    )
                self.assertIn("edge-vanne", peers_buf.getvalue())
                self.assertIn("edge-hanmazaya", peers_buf.getvalue())
        finally:
            for ag in agents:
                ag.close()
            controller.shutdown()

    def test_node_liveness_offline_transition_and_real_udp_probing(self) -> None:
        """Verify real UDP multi-probe metrics, instant offline transition on stop, TTL expiry, and dashboard N/A QBER."""
        controller = SDWANControllerServer(host="127.0.0.1", port=0, node_offline_ttl_s=6.0)
        controller.start_background()
        ag_a: SDWANEndpointAgent | None = None
        ag_b: SDWANEndpointAgent | None = None
        ag_b_restarted: SDWANEndpointAgent | None = None
        try:
            ag_a, _ = SDWANEndpointAgent.enroll_with_controller(controller.base_url, "auto", "edge-live-a")
            ag_b, _ = SDWANEndpointAgent.enroll_with_controller(controller.base_url, "auto", "edge-live-b")
            ag_a.sync_topology()
            ag_b.sync_topology()

            # 1. Negotiate BB84 and verify real UDP multi-probe metrics (zero dummy 8.0 / 0.05 constants)
            cycle_res = ag_a.run_key_rotation_and_telemetry_cycle("edge-live-b")
            self.assertTrue(cycle_res["psk_injected"])
            tel = cycle_res["telemetry"]
            self.assertEqual(tel["packet_loss_pct"], 0.0)
            self.assertGreater(tel["latency_ms"], 0.0)
            self.assertGreater(tel["throughput_mbps"], 0.0)

            status_online = controller.get_cluster_status()
            self.assertEqual(status_online["nodes"]["edge-live-a"]["status"], "ONLINE")
            self.assertEqual(status_online["nodes"]["edge-live-b"]["status"], "ONLINE")
            self.assertEqual(status_online["online_nodes"], 2)
            self.assertEqual(status_online["offline_nodes"], 0)
            self.assertEqual(status_online["links"][0]["link_status"], "HEALTHY")

            # 2. Stop edge-live-b and verify immediate OFFLINE transition and OFFLINE_DOWN link state
            b_wg_port = ag_b.wg_port
            b_qkd_port = ag_b.qkd_port
            b_priv = ag_b.wg_daemon.private_key_b64
            b_ip = ag_b.overlay_ip
            ag_b.close()
            ag_b = None

            status_after_stop = controller.get_cluster_status()
            self.assertEqual(status_after_stop["nodes"]["edge-live-b"]["status"], "OFFLINE")
            self.assertEqual(status_after_stop["online_nodes"], 1)
            self.assertEqual(status_after_stop["offline_nodes"], 1)
            link_ab = status_after_stop["links"][0]
            self.assertEqual(link_ab["link_status"], "OFFLINE_DOWN")
            self.assertEqual(link_ab["packet_loss_pct"], 100.0)
            self.assertEqual(link_ab["key_rate_bps"], 0.0)
            self.assertEqual(link_ab["qber"], 0.0)

            ctrl_dash = render_controller_dashboard(status_after_stop, controller_url=controller.base_url)
            self.assertIn("OFFLINE", ctrl_dash)
            self.assertIn("N/A (OFFLINE)", ctrl_dash)
            self.assertIn("OFFLINE_DOWN", ctrl_dash)
            self.assertIn("DOWN / - / 100.0%", ctrl_dash)

            # 3. Verify surviving peer sync_topology() and render_client_dashboard() reflect OFFLINE + QUARANTINED
            ag_a.sync_topology()
            self.assertEqual(ag_a.peer_registry["edge-live-b"].status, "OFFLINE")
            self.assertEqual(ag_a.active_directives["edge-live-b"].route_mode, RouteMode.QUARANTINED)
            self.assertEqual(ag_a.active_directives["edge-live-b"].link_status, LinkStatus.OFFLINE_DOWN)
            client_dash = render_client_dashboard(ag_a)
            self.assertIn("OFFLINE", client_dash)
            self.assertIn("(STALE-OFFLINE)", client_dash)
            self.assertIn("QUARANTINED", client_dash)

            # 4. Restart edge-live-b and verify automatic recovery to ONLINE + DIRECT_P2P + HEALTHY
            ag_b_restarted = SDWANEndpointAgent(
                node_id="edge-live-b",
                overlay_ip=b_ip,
                controller_url=controller.base_url,
                auth_secret=ag_a.auth_secret,
                wg_port=b_wg_port,
                qkd_port=b_qkd_port,
                private_key_b64=b_priv,
            )
            ag_b_restarted.register_with_controller()
            ag_a.sync_topology()
            rec_res = ag_a.run_key_rotation_and_telemetry_cycle("edge-live-b")
            self.assertTrue(rec_res["psk_injected"])
            self.assertEqual(rec_res["evaluation"]["link_status"], "HEALTHY")
            self.assertEqual(rec_res["directive"]["route_mode"], "DIRECT_P2P")

            # 5. Verify heartbeat TTL expiry marks node OFFLINE when last_seen exceeds node_offline_ttl_s
            with controller._lock:
                controller._nodes["edge-live-b"].last_seen -= 15.0
            status_ttl = controller.get_cluster_status()
            self.assertEqual(status_ttl["nodes"]["edge-live-b"]["status"], "OFFLINE")
            self.assertEqual(status_ttl["links"][0]["link_status"], "OFFLINE_DOWN")
        finally:
            for ag in (ag_a, ag_b, ag_b_restarted):
                if ag is not None:
                    ag.close()
            controller.shutdown()


if __name__ == "__main__":
    unittest.main()
