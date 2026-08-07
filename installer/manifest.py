#!/usr/bin/env python3
"""Manifest verification and self-contained payload staging for HYU VPN.

This module is intentionally not a dry-run installer simulator.  It has two
jobs only: verify the immutable package manifest before any privileged step, and
stage the package's already-built Task8 runtime into a caller-owned staging
directory.  Production install mutation is owned by ``root-admin.sh``.
"""
from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import shutil
import stat
import sys
from pathlib import Path
from typing import Dict, Optional, Sequence


class ManifestError(RuntimeError):
    pass


MAX_MANIFEST_BYTES = 2 * 1024 * 1024


def _reject_duplicate_json_keys(pairs):
    seen = set()
    out = {}
    for key, value in pairs:
        if key in seen:
            raise ManifestError(f"duplicate JSON key: {key}")
        seen.add(key)
        out[key] = value
    return out


def _read_bounded_regular_json(path: Path) -> Dict[str, object]:
    if path.is_symlink():
        raise ManifestError("manifest symlink rejected")
    st = path.stat()
    if not stat.S_ISREG(st.st_mode):
        raise ManifestError("manifest must be a regular file")
    if st.st_size > MAX_MANIFEST_BYTES:
        raise ManifestError("manifest too large")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ManifestError("manifest open failed") from exc
    try:
        data = os.read(fd, MAX_MANIFEST_BYTES + 1)
    finally:
        os.close(fd)
    if len(data) > MAX_MANIFEST_BYTES:
        raise ManifestError("manifest too large")
    try:
        parsed = json.loads(data.decode("utf-8"), object_pairs_hook=_reject_duplicate_json_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, ManifestError) as exc:
        if isinstance(exc, ManifestError):
            raise
        raise ManifestError("manifest JSON invalid") from exc
    if not isinstance(parsed, dict):
        raise ManifestError("manifest schema mismatch")
    return parsed


@dataclasses.dataclass(frozen=True)
class DryRunEnvironment:
    root: Path
    payload: Path
    home: Path
    arch: str = "arm64"
    manifest: Optional[Path] = None
    user: str = "tester"
    group: str = "staff"


class CommandRecorder:
    """Small test helper that records fixed absolute commands."""

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, argv: Sequence[str]) -> None:
        if not argv or not str(argv[0]).startswith("/"):
            raise ValueError(f"command must use a fixed absolute tool path: {argv}")
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(list(map(str, argv))) + "\n")

    def commands(self) -> list[list[str]]:
        if not self.path.exists():
            return []
        return [json.loads(line) for line in self.path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _rel(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError as exc:
        raise ValueError(f"path escapes payload: {path}") from exc


def safe_join(base: Path, relative: str, require_safe_parents: bool = False) -> Path:
    base = base.resolve(strict=False)
    target = (base / relative).resolve(strict=False)
    try:
        target.relative_to(base)
    except ValueError as exc:
        raise ValueError(f"path escapes base: {relative}") from exc
    if require_safe_parents:
        current = base
        for part in Path(relative).parts[:-1] or Path(relative).parts:
            current = current / part
            probe = current if current.exists() else current.parent
            if probe.exists() and stat.S_IMODE(probe.stat().st_mode) & 0o022:
                raise PermissionError(f"user-writable parent rejected: {probe}")
    return target


class PayloadManifest:
    @staticmethod
    def build(payload: Path) -> Dict[str, object]:
        payload = payload.resolve(strict=False)
        files: Dict[str, Dict[str, object]] = {}
        for path in sorted(payload.rglob("*")):
            if path.is_symlink():
                raise ManifestError(f"symlink payload entry rejected: {path.relative_to(payload).as_posix()}")
            st = path.lstat()
            if path == payload / "manifest.json":
                if not stat.S_ISREG(st.st_mode):
                    raise ManifestError("manifest must be a regular file")
                continue
            if stat.S_ISDIR(st.st_mode):
                continue
            if not stat.S_ISREG(st.st_mode):
                raise ManifestError(f"special payload entry rejected: {path.relative_to(payload).as_posix()}")
            rel = _rel(payload, path)
            files[rel] = {"sha256": _sha256(path), "mode": f"{stat.S_IMODE(st.st_mode):04o}", "size": st.st_size}
        return {"schema": 1, "files": files}

    @staticmethod
    def write_for_tree(payload: Path, manifest: Path) -> Path:
        (payload / "installer").mkdir(exist_ok=True)
        placeholder = payload / "installer" / "manifest.py"
        if not placeholder.exists():
            placeholder.write_text("# packaged manifest placeholder for tests\n", encoding="utf-8")
        data = PayloadManifest.build(payload)
        manifest.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return manifest

    @staticmethod
    def verify(payload: Path, manifest: Path) -> Dict[str, object]:
        expected = _read_bounded_regular_json(manifest)
        if expected.get("schema") != 1 or not isinstance(expected.get("files"), dict):
            raise ManifestError("manifest schema mismatch")
        actual = PayloadManifest.build(payload)
        for rel, info in expected["files"].items():
            if sorted(info.keys()) != ["mode", "sha256", "size"]:
                raise ManifestError(f"manifest schema mismatch for {rel}")
            current = actual["files"].get(rel)
            if current is None:
                raise ManifestError(f"missing payload file: {rel}")
            if current["sha256"] != info["sha256"]:
                raise ManifestError(f"hash mismatch: {rel}")
            if current["mode"] != info["mode"]:
                raise ManifestError(f"mode mismatch: {rel}")
            if current["size"] != info["size"]:
                raise ManifestError(f"size mismatch: {rel}")
        extras = set(actual["files"]) - set(expected["files"])
        if extras:
            raise ManifestError(f"unmanifested payload file: {sorted(extras)[0]}")
        return expected


def _copy_file(src: Path, dst: Path, mode: int) -> None:
    if not src.exists() or src.is_symlink() or not src.is_file():
        raise FileNotFoundError(f"missing required packaged artifact: {src}")
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    dst.chmod(mode)


def _copy_tree(src: Path, dst: Path, file_mode: int = 0o644, executable_mode: int = 0o755) -> None:
    if not src.exists() or src.is_symlink() or not src.is_dir():
        raise FileNotFoundError(f"missing required packaged directory: {src}")
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst, symlinks=False)
    for item in dst.rglob("*"):
        if item.is_symlink():
            raise ManifestError(f"symlink staged entry rejected: {item}")
        if item.is_file():
            src_mode = stat.S_IMODE(item.stat().st_mode)
            item.chmod(executable_mode if (src_mode & 0o111) else file_mode)


def _write_stage_manifest(stage: Path) -> None:
    files: Dict[str, Dict[str, object]] = {}
    for path in sorted(stage.rglob("*")):
        if path.is_symlink():
            raise ManifestError(f"symlink staged entry rejected: {path}")
        st = path.lstat()
        if path == stage / "manifest.json":
            if not stat.S_ISREG(st.st_mode):
                raise ManifestError("manifest must be a regular file")
            continue
        if stat.S_ISDIR(st.st_mode):
            continue
        if not stat.S_ISREG(st.st_mode):
            raise ManifestError(f"special staged entry rejected: {path}")
        rel = path.relative_to(stage).as_posix()
        files[rel] = {"sha256": _sha256(path), "mode": f"{stat.S_IMODE(st.st_mode):04o}", "size": st.st_size}
    (stage / "manifest.json").write_text(json.dumps({"schema": 1, "files": files}, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _stage_into(payload: Path, manifest: Path, stage: Path) -> Path:
    PayloadManifest.verify(payload, manifest)
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir(parents=True, mode=0o700)

    (stage / "runtime/bin").mkdir(parents=True)
    (stage / "runtime/lib").mkdir(parents=True)
    (stage / "runtime/vpnc").mkdir(parents=True)
    (stage / "backend").mkdir(parents=True)
    (stage / "bin").mkdir(parents=True)
    (stage / "src").mkdir(parents=True)
    (stage / "config/launchd").mkdir(parents=True)

    required = {
        "runtime/openconnect/bin/openconnect": ("runtime/bin/openconnect", 0o755),
        "runtime/oathtool": ("runtime/bin/oathtool", 0o755),
        "runtime/gp-hip-report": ("runtime/gp-hip-report", 0o755),
        "runtime/vpnc/hyu-vpnc-wrapper": ("runtime/vpnc/hyu-vpnc-wrapper", 0o755),
        "runtime/vpnc/hyu-vpnc-wrapperd": ("runtime/vpnc/hyu-vpnc-wrapperd", 0o755),
        "runtime/vpnc/vpnc-script": ("runtime/vpnc/vpnc-script", 0o755),
        "com.hyu.vpn.helper": ("com.hyu.vpn.helper", 0o755),
        "hyu-vpn-control": ("backend/hyu-vpn-control", 0o755),
        "hyu-vpn-service": ("backend/hyu-vpn-service", 0o755),
        "hyu-vpn-connect": ("backend/hyu-vpn-connect", 0o755),
        "hyu-vpn-native-client": ("bin/hyu-vpn-native-client", 0o755),
        "launchd/com.hyu.vpn.service.plist.in": ("config/launchd/com.hyu.vpn.service.plist.in", 0o644),
    }
    for rel, (dst_rel, mode) in required.items():
        _copy_file(payload / rel, stage / dst_rel, mode)

    runtime_lib = payload / "runtime/openconnect/lib"
    if runtime_lib.exists():
        _copy_tree(runtime_lib, stage / "runtime/lib", file_mode=0o755, executable_mode=0o755)
    _copy_tree(payload / "src/hyu_vpn", stage / "src/hyu_vpn", file_mode=0o644, executable_mode=0o755)
    _copy_tree(payload / "HYU VPN.app", stage / "HYU VPN.app", file_mode=0o644, executable_mode=0o755)
    menu_exec = stage / "HYU VPN.app/Contents/MacOS/HYUVPNMenuApp"
    credential_reader = stage / "HYU VPN.app/Contents/MacOS/HYUVPNCredentialReader"
    if not menu_exec.exists():
        raise FileNotFoundError("missing app executable: HYUVPNMenuApp")
    if not credential_reader.exists():
        raise FileNotFoundError("missing app executable: HYUVPNCredentialReader")
    menu_exec.chmod(0o755)
    credential_reader.chmod(0o755)
    (stage / ".hyu-vpn-dry-run-root").write_text("hyu-vpn-installer-stage\n", encoding="utf-8")
    _write_stage_manifest(stage)
    return stage


def stage_user_payload(env: DryRunEnvironment, recorder: Optional[CommandRecorder] = None) -> Path:
    manifest = env.manifest or (env.payload / "manifest.json")
    if recorder:
        recorder.record(["/usr/bin/python3", "installer/manifest.py", "--verify-manifest", str(env.payload), str(manifest)])
    env.root.mkdir(parents=True, exist_ok=True)
    (env.root / ".hyu-vpn-dry-run-root").write_text("hyu-vpn-installer-test-root\n", encoding="utf-8")
    stage = env.root / "Users" / env.user / "Library/Application Support/HYU VPN/staged-payload"
    result = _stage_into(env.payload, manifest, stage)
    if recorder:
        recorder.record(["/usr/bin/sudo", "/bin/zsh", "installer/root-admin.sh", "--administrator-phase", "install"])
    return result


def _package_audit(payload: Path, manifest: Path) -> None:
    PayloadManifest.verify(payload, manifest)
    if not Path("/usr/bin/python3").is_file() or not os.access("/usr/bin/python3", os.X_OK):
        raise ManifestError("/usr/bin/python3 is required for this internal-lab package")


def _cli(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--payload", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--verify-manifest", action="store_true")
    parser.add_argument("--stage-user-payload", action="store_true")
    parser.add_argument("--stage-dir", type=Path)
    parser.add_argument("--package-audit", action="store_true")
    ns = parser.parse_args(argv)
    try:
        if ns.verify_manifest:
            PayloadManifest.verify(ns.payload, ns.manifest)
            return 0
        if ns.package_audit:
            _package_audit(ns.payload, ns.manifest)
            return 0
        if ns.stage_user_payload:
            if ns.stage_dir is None:
                print("--stage-dir is required", file=sys.stderr)
                return 2
            _stage_into(ns.payload, ns.manifest, ns.stage_dir)
            return 0
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1
    parser.error("choose --verify-manifest, --package-audit, or --stage-user-payload")
    return 2


if __name__ == "__main__":
    raise SystemExit(_cli(sys.argv[1:]))
