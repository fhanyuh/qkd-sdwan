#!/usr/bin/env python3
"""Cross-platform packaging and installer builder for QKD-SDWAN Central Controller and Endpoint Client."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import zipapp


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def build_pyz_archives(repo_root: Path, dist_dir: Path) -> tuple[Path, Path]:
    src_pkg = repo_root / "qkd_sdwan"
    if not src_pkg.is_dir():
        raise FileNotFoundError(f"Source package not found at {src_pkg}")

    controller_pyz = dist_dir / "qkd-sdwan-controller.pyz"
    client_pyz = dist_dir / "qkd-sdwan-client.pyz"

    with tempfile.TemporaryDirectory(prefix="qkd-build-") as tmp:
        tmp_path = Path(tmp)
        stage_pkg = tmp_path / "qkd_sdwan"
        shutil.copytree(src_pkg, stage_pkg)

        # Build Controller portable .pyz
        zipapp.create_archive(
            source=tmp_path,
            target=controller_pyz,
            interpreter="/usr/bin/env python3",
            main="qkd_sdwan.controller.cli:main",
            compressed=True,
        )

        # Build Client portable .pyz
        zipapp.create_archive(
            source=tmp_path,
            target=client_pyz,
            interpreter="/usr/bin/env python3",
            main="qkd_sdwan.client.agent:main",
            compressed=True,
        )

    controller_pyz.chmod(0o755)
    client_pyz.chmod(0o755)
    return controller_pyz, client_pyz


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    scripts_dir = repo_root / "scripts"
    dist_dir = repo_root / "dist"
    dist_dir.mkdir(parents=True, exist_ok=True)

    print(f"[build_installers] Building portable .pyz archives in {dist_dir}...")
    ctrl_pyz, client_pyz = build_pyz_archives(repo_root, dist_dir)
    print(f"  [+] Built {ctrl_pyz.name} ({ctrl_pyz.stat().st_size} bytes)")
    print(f"  [+] Built {client_pyz.name} ({client_pyz.stat().st_size} bytes)")

    # 1. Linux Controller installer
    sh_ctrl = dist_dir / "install-controller-linux.sh"
    shutil.copy2(scripts_dir / "install_controller.sh", sh_ctrl)
    sh_ctrl.chmod(0o755)

    # 2. Linux Client installer
    sh_client = dist_dir / "install-client-linux.sh"
    shutil.copy2(scripts_dir / "install_client.sh", sh_client)
    sh_client.chmod(0o755)

    # 3. Windows Controller PowerShell & Batch installer
    ps1_ctrl = dist_dir / "install-controller-windows.ps1"
    shutil.copy2(scripts_dir / "install_controller.ps1", ps1_ctrl)
    bat_ctrl = dist_dir / "install-controller-windows.bat"
    bat_ctrl.write_text(
        "@echo off\r\n"
        'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install-controller-windows.ps1" %*\r\n',
        encoding="ascii",
    )

    # 4. Windows Client PowerShell & Batch installer
    ps1_client = dist_dir / "install-client-windows.ps1"
    shutil.copy2(scripts_dir / "install_client.ps1", ps1_client)
    bat_client = dist_dir / "install-client-windows.bat"
    bat_client.write_text(
        "@echo off\r\n"
        'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install-client-windows.ps1" %*\r\n',
        encoding="ascii",
    )

    # Build manifest
    artifacts = [
        {"filename": ctrl_pyz.name, "platform": "all", "type": "zipapp", "component": "controller"},
        {"filename": client_pyz.name, "platform": "all", "type": "zipapp", "component": "client"},
        {"filename": sh_ctrl.name, "platform": "linux", "type": "shell-installer", "component": "controller"},
        {"filename": sh_client.name, "platform": "linux", "type": "shell-installer", "component": "client"},
        {"filename": ps1_ctrl.name, "platform": "windows", "type": "powershell-installer", "component": "controller"},
        {"filename": bat_ctrl.name, "platform": "windows", "type": "batch-installer", "component": "controller"},
        {"filename": ps1_client.name, "platform": "windows", "type": "powershell-installer", "component": "client"},
        {"filename": bat_client.name, "platform": "windows", "type": "batch-installer", "component": "client"},
    ]

    manifest = {
        "project": "qkd-sdwan-poc",
        "version": "0.1.0",
        "artifacts": [],
    }

    for art in artifacts:
        file_path = dist_dir / art["filename"]
        manifest["artifacts"].append(
            {
                **art,
                "size_bytes": file_path.stat().st_size,
                "sha256": sha256_file(file_path),
            }
        )

    manifest_path = dist_dir / "MANIFEST.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"  [+] Wrote distribution manifest: {manifest_path.name}")
    print("[build_installers] Build complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
