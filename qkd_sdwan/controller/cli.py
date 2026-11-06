"""CLI entrypoint, token management console, and ASCII CLI Dashboard for the QKD-SDWAN Central Controller."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets
import time
from typing import Any
import urllib.error
import urllib.request

from qkd_sdwan.controller.server import SDWANControllerServer


def _http_json(
    url: str,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    data_bytes = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Accept": "application/json"}
    if data_bytes is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data_bytes, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(err_body)
            msg = parsed.get("error", err_body)
        except Exception:
            msg = err_body or str(exc)
        raise RuntimeError(f"HTTP {exc.code}: {msg}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Controller unreachable at {url}: {exc}") from exc


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


def render_controller_dashboard(
    cluster_status: dict[str, Any],
    controller_url: str = "http://127.0.0.1:8080",
) -> str:
    """Render a 4-panel ASCII CLI Dashboard for the Central Controller."""
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    nodes_dict: dict[str, dict[str, Any]] = cluster_status.get("nodes", {}) or {}
    links_list: list[dict[str, Any]] = cluster_status.get("links", []) or []
    directives_list: list[dict[str, Any]] = cluster_status.get("directives", []) or []
    tokens_list: list[dict[str, Any]] = cluster_status.get("tokens", []) or []
    subnet_prefix = cluster_status.get("overlay_subnet_prefix", "10.200.0.")

    lines: list[str] = []
    banner = "=" * 116
    lines.append(banner)
    lines.append(" QKD-SDWAN CENTRAL CONTROLLER — INTERACTIVE CLI DASHBOARD (BB84 QKD + ISOLATION FOREST ML) ")
    lines.append(banner)
    lines.append(
        f" Controller URL : {controller_url:<34} | Timestamp          : {now_str}"
    )
    lines.append(
        f" Overlay Subnet : {subnet_prefix + '0/24':<34} | Registered Nodes   : {len(nodes_dict)}"
    )
    lines.append(
        f" Active Links   : {len(links_list):<34} | Routing Directives : {len(directives_list)}"
    )
    lines.append("-" * 116)

    # Panel 1: Join Tokens
    lines.append("[1] CLUSTER ENROLLMENT JOIN TOKENS (Token-Based Zero-Touch Client Onboarding)")
    now_ts = time.time()
    token_rows: list[list[str]] = []
    for tok in tokens_list:
        revoked = bool(tok.get("revoked", False))
        used = int(tok.get("used_count", 0))
        max_uses = int(tok.get("max_uses", 0))
        expires_at = float(tok.get("expires_at", 0.0))
        if revoked:
            status_str = "REVOKED"
        elif used >= max_uses:
            status_str = "EXHAUSTED"
        elif now_ts >= expires_at:
            status_str = "EXPIRED"
        else:
            status_str = "ACTIVE"
        ttl_rem = max(0, int(expires_at - now_ts))
        token_rows.append(
            [
                str(tok.get("token_id", "")),
                str(tok.get("label", "")),
                f"{used}/{max_uses}",
                f"{ttl_rem}s",
                status_str,
                str(tok.get("secret_token", "")),
            ]
        )
    lines.extend(
        _format_ascii_table(
            ["Token ID", "Label", "Uses", "TTL Rem", "Status", "Join Token (for Client Enrollment)"],
            token_rows,
        )
    )
    lines.append("")

    # Panel 2: Registered P2P Endpoints
    lines.append("[2] REGISTERED P2P SD-WAN ENDPOINT CLIENTS")
    node_rows: list[list[str]] = []
    for nid, ninfo in sorted(nodes_dict.items()):
        pub_key = str(ninfo.get("wg_public_key", ""))
        short_pub = f"{pub_key[:20]}..." if len(pub_key) > 23 else pub_key
        node_rows.append(
            [
                nid,
                str(ninfo.get("overlay_ip", "")),
                f"{ninfo.get('underlay_host', '127.0.0.1')}:{ninfo.get('wg_port', 0)}",
                str(ninfo.get("qkd_port", 0)),
                str(ninfo.get("auth_token_id", "")),
                short_pub,
            ]
        )
    lines.extend(
        _format_ascii_table(
            [
                "Node ID",
                "Overlay IP",
                "Underlay WG Endpoint",
                "QKD Port",
                "Auth Token ID",
                "WG X25519 Public Key",
            ],
            node_rows,
        )
    )
    lines.append("")

    # Panel 3: Quantum BB84 & ML Anomaly Monitor
    lines.append("[3] QUANTUM BB84 CHANNEL TELEMETRY & ISOLATION FOREST ANOMALY MONITOR")
    link_rows: list[list[str]] = []
    for lk in links_list:
        pair_str = f"{lk.get('source_node', '')} -> {lk.get('target_node', '')}"
        qber_pct = f"{float(lk.get('qber', 0.0)) * 100:.2f}%"
        dqber_pct = f"{float(lk.get('qber_delta', 0.0)) * 100:+.2f}%"
        krate = f"{float(lk.get('key_rate_bps', 0.0)):.0f}"
        rtts = f"{float(lk.get('latency_ms', 0.0)):.1f}ms / {float(lk.get('packet_loss_pct', 0.0)):.1f}%"
        epoch = str(lk.get("psk_epoch", 0))
        aborts = str(lk.get("qkd_abort_count", 0))
        score = f"{float(lk.get('anomaly_score', 0.0)):.3f}"
        lstatus = str(lk.get("link_status", "UNKNOWN"))
        link_rows.append([pair_str, qber_pct, dqber_pct, krate, rtts, epoch, aborts, score, lstatus])
    lines.extend(
        _format_ascii_table(
            [
                "Directed Link",
                "QBER",
                "Delta QBER",
                "Key Rate (bps)",
                "RTT / Loss",
                "PSK Epoch",
                "Aborts",
                "ML Score",
                "LinkStatus",
            ],
            link_rows,
        )
    )
    lines.append("")

    # Panel 4: Active P2P Overlay Routing Directives
    lines.append("[4] ACTIVE P2P OVERLAY ROUTING DIRECTIVES (DIRECT_P2P vs RELAY_P2P)")
    dir_rows: list[list[str]] = []
    for d in directives_list:
        pair_str = f"{d.get('source_node', '')} -> {d.get('target_node', '')}"
        rmode = str(d.get("route_mode", ""))
        nhop = str(d.get("next_hop_node", "")) or "-"
        nep = str(d.get("next_hop_endpoint", "")) or "-"
        rekey = "YES" if d.get("force_rekey") else "NO"
        reason = str(d.get("reason", ""))
        if len(reason) > 48:
            reason = reason[:45] + "..."
        dir_rows.append([pair_str, rmode, nhop, nep, rekey, reason])
    lines.extend(
        _format_ascii_table(
            ["Source -> Target", "RouteMode", "Next Hop", "Next Hop Endpoint", "Force Rekey", "Reason"],
            dir_rows,
        )
    )
    lines.append(banner)
    return "\n".join(lines)


def build_controller_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="qkd-sdwan-controller",
        description="QKD-SDWAN Central Controller Server, Token Manager, and Interactive CLI Dashboard.",
    )
    parser.add_argument("--config", type=Path, help="Path to JSON controller configuration file")
    parser.add_argument("--host", default=None, help="Bind IP address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=None, help="Bind HTTP port (default: 8080)")
    parser.add_argument("--subnet-prefix", default=None, help="Overlay IPv4 /24 prefix (default: 10.200.0.)")
    parser.add_argument("--bootstrap-token", default=None, help="Custom initial Join Token string")
    parser.add_argument("--dashboard", action="store_true", help="Launch interactive CLI dashboard while serving")
    parser.add_argument("--check-config", action="store_true", help="Validate configuration and exit")

    subparsers = parser.add_subparsers(dest="subcommand")

    # subcommand: serve
    serve_p = subparsers.add_parser("serve", help="Start the Central Controller HTTP server")
    serve_p.add_argument("--config", type=Path, default=argparse.SUPPRESS, help="Path to JSON controller configuration file")
    serve_p.add_argument("--host", default=argparse.SUPPRESS, help="Bind IP address (default: 127.0.0.1)")
    serve_p.add_argument("--port", type=int, default=argparse.SUPPRESS, help="Bind HTTP port (default: 8080)")
    serve_p.add_argument("--subnet-prefix", default=argparse.SUPPRESS, help="Overlay IPv4 /24 prefix (default: 10.200.0.)")
    serve_p.add_argument("--bootstrap-token", default=argparse.SUPPRESS, help="Custom initial Join Token string")
    serve_p.add_argument("--dashboard", action="store_true", default=argparse.SUPPRESS, help="Run interactive CLI dashboard console")
    serve_p.add_argument("--check-config", action="store_true", default=argparse.SUPPRESS, help="Validate configuration and exit")

    # subcommand: init-config
    init_p = subparsers.add_parser("init-config", help="Generate initial controller.json configuration and bootstrap Join Token")
    init_p.add_argument("--output", type=Path, required=True, help="Output path for controller.json")
    init_p.add_argument("--host", default="0.0.0.0", help="Bind IP address (default: 0.0.0.0)")
    init_p.add_argument("--port", type=int, default=8080, help="Bind HTTP port (default: 8080)")
    init_p.add_argument("--subnet-prefix", default="10.200.0.", help="Overlay IPv4 /24 prefix (default: 10.200.0.)")
    init_p.add_argument("--bootstrap-token", default="", help="Optional custom bootstrap Join Token")

    # subcommand: dashboard
    dash_p = subparsers.add_parser("dashboard", help="Display the Controller CLI Dashboard")
    dash_p.add_argument("--config", type=Path, default=argparse.SUPPRESS, help="Path to JSON controller configuration file")
    dash_p.add_argument("--controller-url", default=None, help="Controller base URL")
    dash_p.add_argument("--once", action="store_true", help="Print a single dashboard snapshot and exit")
    dash_p.add_argument("--interval", type=float, default=2.0, help="Refresh interval in seconds (default: 2.0)")

    # subcommand: token
    tok_p = subparsers.add_parser("token", help="Manage client enrollment Join Tokens")
    tok_p.add_argument("--config", type=Path, default=argparse.SUPPRESS, help="Path to JSON controller configuration file")
    tok_p.add_argument("--controller-url", default=None, help="Controller base URL")
    tok_sub = tok_p.add_subparsers(dest="token_action")

    tok_create = tok_sub.add_parser("create", help="Create a new enrollment Join Token")
    tok_create.add_argument("--config", type=Path, default=argparse.SUPPRESS, help="Path to JSON controller configuration file")
    tok_create.add_argument("--controller-url", default=None, help="Controller base URL")
    tok_create.add_argument("--label", default="cli-token", help="Descriptive token label")
    tok_create.add_argument("--max-uses", type=int, default=10, help="Maximum node enrollments allowed")
    tok_create.add_argument("--ttl", type=float, default=86400.0, help="Token validity TTL in seconds")
    tok_create.add_argument("--custom-token", default=None, help="Optional custom token secret string")

    tok_list = tok_sub.add_parser("list", help="List all enrollment Join Tokens")
    tok_list.add_argument("--config", type=Path, default=argparse.SUPPRESS, help="Path to JSON controller configuration file")
    tok_list.add_argument("--controller-url", default=None, help="Controller base URL")

    tok_revoke = tok_sub.add_parser("revoke", help="Revoke an enrollment Join Token by ID")
    tok_revoke.add_argument("--config", type=Path, default=argparse.SUPPRESS, help="Path to JSON controller configuration file")
    tok_revoke.add_argument("--controller-url", default=None, help="Controller base URL")
    tok_revoke.add_argument("--token-id", required=True, help="Token ID to revoke (e.g. tok-a1b2c3d4)")

    # subcommand: status
    stat_p = subparsers.add_parser("status", help="Query cluster status from a running Controller")
    stat_p.add_argument("--config", type=Path, default=argparse.SUPPRESS, help="Path to JSON controller configuration file")
    stat_p.add_argument("--controller-url", default=None, help="Controller base URL")
    stat_p.add_argument("--json", action="store_true", help="Output raw JSON cluster status")

    return parser


def _load_controller_config(args: argparse.Namespace) -> dict[str, Any]:
    cfg: dict[str, Any] = {
        "host": "127.0.0.1",
        "port": 8080,
        "overlay_subnet_prefix": "10.200.0.",
        "cluster_hmac_secret_hex": None,
        "bootstrap_join_token": None,
    }
    config_path: Path | None = getattr(args, "config", None)
    if config_path is None:
        env_cfg = os.environ.get("QKD_SDWAN_CONTROLLER_CONFIG")
        if env_cfg:
            config_path = Path(env_cfg)
    if config_path and config_path.exists():
        loaded = json.loads(config_path.read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            cfg.update(loaded)

    if getattr(args, "host", None) is not None:
        cfg["host"] = args.host
    if getattr(args, "port", None) is not None:
        cfg["port"] = int(args.port)
    if getattr(args, "subnet_prefix", None) is not None:
        cfg["overlay_subnet_prefix"] = args.subnet_prefix
    if getattr(args, "bootstrap_token", None) is not None:
        cfg["bootstrap_join_token"] = args.bootstrap_token

    return cfg


def _resolve_controller_url(args: argparse.Namespace) -> str:
    explicit_url = getattr(args, "controller_url", None)
    if explicit_url:
        return str(explicit_url)
    cfg = _load_controller_config(args)
    raw_host = str(cfg.get("host", "127.0.0.1")).strip()
    host = "127.0.0.1" if raw_host in ("0.0.0.0", "::", "") else raw_host
    return f"http://{host}:{int(cfg.get('port', 8080))}"


def _run_init_config(args: argparse.Namespace) -> int:
    out_path: Path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    token = (getattr(args, "bootstrap_token", "") or "").strip() or f"qkd-join-{secrets.token_hex(12)}"
    secret_hex = secrets.token_hex(32)
    cfg = {
        "host": str(getattr(args, "host", None) or "0.0.0.0"),
        "port": int(getattr(args, "port", None) or 8080),
        "overlay_subnet_prefix": str(getattr(args, "subnet_prefix", None) or "10.200.0."),
        "cluster_hmac_secret_hex": secret_hex,
        "bootstrap_join_token": token,
        "generated_at": time.time(),
    }
    out_path.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
    print(token)
    return 0


def _run_serve(args: argparse.Namespace) -> int:
    cfg = _load_controller_config(args)
    if getattr(args, "check_config", False):
        print(
            json.dumps(
                {
                    "status": "config_valid",
                    "host": cfg["host"],
                    "port": int(cfg["port"]),
                    "overlay_subnet_prefix": cfg["overlay_subnet_prefix"],
                },
                indent=2,
            )
        )
        return 0

    server = SDWANControllerServer(
        host=str(cfg["host"]),
        port=int(cfg["port"]),
        overlay_subnet_prefix=str(cfg.get("overlay_subnet_prefix", "10.200.0.")),
        cluster_hmac_secret_hex=cfg.get("cluster_hmac_secret_hex"),
        bootstrap_join_token=cfg.get("bootstrap_join_token"),
    )
    bound_host, bound_port = server.start_background()
    display_host = "127.0.0.1" if bound_host == "0.0.0.0" else bound_host
    ctrl_url = f"http://{display_host}:{bound_port}"

    print("=" * 96)
    print(f" QKD-SDWAN Central Controller started on http://{bound_host}:{bound_port}")
    print(f" Bootstrap Join Token : {server.bootstrap_token}")
    print(
        f" Enroll Client Cmd    : qkd-sdwan-client enroll --controller-url {ctrl_url} "
        f"--join-token {server.bootstrap_token} --node-id edge-node-01"
    )
    print("=" * 96)

    try:
        if getattr(args, "dashboard", False):
            while True:
                print("\n" + render_controller_dashboard(server.get_cluster_status(), controller_url=ctrl_url))
                print("Dashboard Actions: [r] Refresh  [t] Create Join Token  [x] Revoke Token  [q] Stop Server & Quit")
                try:
                    choice = input("controller> ").strip().lower()
                except EOFError:
                    break
                if choice in ("q", "quit", "exit"):
                    break
                if choice == "t":
                    label = input("  Token label [branch-office]: ").strip() or "branch-office"
                    uses_raw = input("  Max uses [10]: ").strip() or "10"
                    tok = server.create_enrollment_token(label=label, max_uses=max(1, int(uses_raw)))
                    print(f"  [+] Created Join Token ({tok.token_id}): {tok.secret_token}")
                elif choice == "x":
                    tid = input("  Token ID to revoke: ").strip()
                    if server.revoke_enrollment_token(tid):
                        print(f"  [+] Revoked token {tid}")
                    else:
                        print(f"  [!] Token not found: {tid}")
        else:
            while True:
                time.sleep(1.0)
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
    return 0


def _run_dashboard(args: argparse.Namespace) -> int:
    url = _resolve_controller_url(args).rstrip("/")
    if args.once:
        status = _http_json(f"{url}/api/v1/cluster/status")
        print(render_controller_dashboard(status, controller_url=url))
        return 0

    try:
        while True:
            status = _http_json(f"{url}/api/v1/cluster/status")
            print("\033[2J\033[H", end="")
            print(render_controller_dashboard(status, controller_url=url))
            print(f"Refreshing every {args.interval:.1f}s (Press Ctrl+C to exit)...")
            time.sleep(max(0.2, float(args.interval)))
    except KeyboardInterrupt:
        return 0


def _run_token(args: argparse.Namespace) -> int:
    action = getattr(args, "token_action", None) or "list"
    url = _resolve_controller_url(args).rstrip("/")

    if action == "create":
        resp = _http_json(
            f"{url}/api/v1/tokens/create",
            method="POST",
            payload={
                "label": args.label,
                "max_uses": args.max_uses,
                "ttl_seconds": args.ttl,
                "custom_token": args.custom_token,
            },
        )
        tok = resp.get("token", {})
        print(f"Created Join Token ID : {tok.get('token_id')}")
        print(f"Label                 : {tok.get('label')}")
        print(f"Max Uses              : {tok.get('max_uses')}")
        print(f"Join Token Secret     : {tok.get('secret_token')}")
        return 0

    if action == "revoke":
        resp = _http_json(
            f"{url}/api/v1/tokens/revoke",
            method="POST",
            payload={"token_id": args.token_id},
        )
        print(json.dumps(resp, indent=2))
        return 0

    resp = _http_json(f"{url}/api/v1/tokens")
    tokens = resp.get("tokens", [])
    rows = [
        [
            str(t.get("token_id", "")),
            str(t.get("label", "")),
            f"{t.get('used_count', 0)}/{t.get('max_uses', 0)}",
            "REVOKED" if t.get("revoked") else "ACTIVE",
            str(t.get("secret_token", "")),
        ]
        for t in tokens
    ]
    print("\n".join(_format_ascii_table(["Token ID", "Label", "Uses", "Status", "Join Token"], rows)))
    return 0


def _run_status(args: argparse.Namespace) -> int:
    url = _resolve_controller_url(args).rstrip("/")
    status = _http_json(f"{url}/api/v1/cluster/status")
    if getattr(args, "json", False):
        print(json.dumps(status, indent=2))
    else:
        print(render_controller_dashboard(status, controller_url=url))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_controller_parser()
    args = parser.parse_args(argv)
    sub = getattr(args, "subcommand", None)

    if sub in (None, "serve"):
        return _run_serve(args)
    if sub == "init-config":
        return _run_init_config(args)
    if sub == "dashboard":
        return _run_dashboard(args)
    if sub == "token":
        return _run_token(args)
    if sub == "status":
        return _run_status(args)
    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
