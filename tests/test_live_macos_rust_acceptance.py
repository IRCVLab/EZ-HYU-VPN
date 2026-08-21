from __future__ import annotations

import json
import os
import plistlib
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "live-macos-rust-acceptance.sh"
CHECKLIST = ROOT / "docs" / "release-checklist-macos-rust.md"
REPORT = ROOT / "task-9-report.md"

SERVICE_HASH = "a" * 64
HELPER_HASH = "b" * 64
MENU_HASH = "c" * 64
INSTALLER_HASH = "d" * 64
DMG_HASH = "e" * 64
USER_PRESENT = "I-am-present-for-live-macOS-Rust-acceptance"


def write_tool(root: Path, path: str, body: str) -> None:
    target = root / path.lstrip("/")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("#!/bin/bash\nset -euo pipefail\n" + body, encoding="utf-8")
    target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def sha(path: Path) -> str:
    return subprocess.check_output(["/usr/bin/shasum", "-a", "256", str(path)], text=True).split()[0]


class IpcServer:
    def __init__(self, path: Path, commands: list[str], statuses: list[dict[str, object]], protocol: str = "rust", *, helper_state: Path | None = None, same_generation: bool = False):
        self.path = path
        self.commands = commands
        self.statuses = statuses
        self.seen: list[dict[str, object]] = []
        self.stop = threading.Event()
        self.protocol = protocol
        self.helper_state = helper_state
        self.same_generation = same_generation
        self.generation = 0
        self.thread = threading.Thread(target=self._run, daemon=True)

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(str(self.path))
        os.chmod(self.path, 0o600)
        self.sock.listen(20)
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.stop.set()
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(0.1)
                client.connect(str(self.path))
        except OSError:
            pass
        self.thread.join(timeout=2)
        self.sock.close()
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass

    def _run(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                try:
                    header = conn.recv(4)
                    if len(header) != 4:
                        continue
                    size = struct.unpack(">I", header)[0]
                    payload = b""
                    while len(payload) < size:
                        chunk = conn.recv(size - len(payload))
                        if not chunk:
                            break
                        payload += chunk
                    req = json.loads(payload.decode())
                    self.seen.append(req)
                    command = req.get("command")
                    ok = command in {"status", "connect", "disconnect", "reconnect"}
                    if command == "status":
                        status = self.statuses[min(len([r for r in self.seen if r.get('command') == 'status']) - 1, len(self.statuses) - 1)]
                    else:
                        self.commands.append(str(command))
                        if self.helper_state is not None:
                            if command in {"connect", "reconnect"}:
                                if self.same_generation:
                                    state = {"schema_version": 1, "state": "running", "pid": 4242, "session_nonce": "ABCDEF12", "tunnel_interface": "utun9"}
                                else:
                                    self.generation += 1
                                    pid = 7000 + self.generation
                                    nonce = "ZYXW9876" if self.generation == 1 else "ZXCV9876"
                                    tunnel = "utun10" if self.generation == 1 else "utun11"
                                    state = {"schema_version": 1, "state": "running", "pid": pid, "session_nonce": nonce, "tunnel_interface": tunnel}
                                self.helper_state.write_text(json.dumps(state), encoding="utf-8")
                            if command == "disconnect":
                                self.helper_state.write_text(json.dumps({"schema_version": 1, "state": "stopped", "pid": None, "session_nonce": None, "tunnel_interface": None}), encoding="utf-8")
                        status = self.statuses[min(len(self.statuses) - 1, 0)]
                    resp = ({"schema_version": 1, "request_id": req.get("request_id"), "result": "status", "status": status} if self.protocol == "rust" and command == "status" else ({"schema_version": 1, "request_id": req.get("request_id"), "result": "ack"} if self.protocol == "rust" and ok else {"schema_version": 1, "request_id": req.get("request_id"), "ok": ok, "error_code": None if ok else "BAD_REQUEST", "status": status}))
                    raw = json.dumps(resp, separators=(",", ":")).encode()
                    conn.sendall(struct.pack(">I", len(raw)) + raw)
                except Exception:
                    continue


class Task9Fixture:
    def __init__(self, case: unittest.TestCase, *, helper_invalid: bool = False):
        self.case = case
        self.td = tempfile.TemporaryDirectory(dir="/private/tmp")
        self.root = Path(self.td.name)
        self.tools = self.root / "tools"
        self.audit = self.root / "audit.log"
        self.install_root = self.root / "installed"
        self.home = self.root / "home"
        self.home.mkdir()
        self.dmg = self.root / "EZ-HYU-VPN-arm64.dmg"
        self.dmg.write_bytes(b"fake task9 dmg")
        self.sha = self.root / "EZ-HYU-VPN-arm64.dmg.sha256"
        self.sha.write_text(f"{sha(self.dmg)}  EZ-HYU-VPN-arm64.dmg\n", encoding="utf-8")
        self.mount_payload = self.root / "mount-payload"
        self.mount_payload.mkdir()
        self.socket = self.root / "daemon.sock"
        self.helper_state = self.root / "helper-state.json"
        self.test_root = self.root / "dry-root"
        self.test_root.mkdir()
        (self.test_root / ".hyu-vpn-dry-run-root").write_text("", encoding="utf-8")
        self.evidence = self.root / "test-root-evidence.txt"
        self._write_payload()
        self.stage_manifest = self.test_root / "Users/tester/Library/Application Support/HYU VPN/staged-payload/manifest.json"
        self.stage_manifest.parent.mkdir(parents=True)
        shutil.copy2(self.mount_payload / "manifest.json", self.stage_manifest)
        self.helper_state.write_text(json.dumps({"schema_version": 1, "state": "running", "pid": 4242, "session_nonce": "ABCDEF12", "tunnel_interface": "utun9"}), encoding="utf-8")
        self._write_installed_payload()
        self._write_tools(helper_invalid=helper_invalid)
        cred_dir = self.home / "Library/Application Support/hyu-openconnect"
        cred_dir.mkdir(parents=True)
        (cred_dir / "credentials.key").write_bytes(b"key-material-metadata-only")
        (cred_dir / "credentials.enc").write_bytes(b"ciphertext-metadata-only")
        os.chmod(cred_dir / "credentials.key", 0o600)
        os.chmod(cred_dir / "credentials.enc", 0o600)
        self.env = os.environ.copy()
        self.env.update({
            "HOME": str(self.home),
            "PATH": f"{self.tools / 'bin'}:{os.environ.get('PATH', '')}",
            "HYU_LIVE_MACOS_RUST_TOOLS_ROOT": str(self.tools),
            "HYU_LIVE_MACOS_RUST_AUDIT": str(self.audit),
            "HYU_LIVE_MACOS_RUST_SOCKET": str(self.socket),
            "HYU_LIVE_MACOS_RUST_INSTALL_ROOT": str(self.install_root),
            "HYU_LIVE_MACOS_RUST_TEST_ROOT_EVIDENCE": str(self.evidence),
            "HYU_LIVE_MACOS_RUST_NONCE_DIR": str(self.root / "nonces"),
        })

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.td.cleanup()

    def run(self, *args: str, timeout: int = 20, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        merged = self.env.copy()
        if env:
            merged.update(env)
        return subprocess.run([str(SCRIPT), *args], cwd=ROOT, env=merged, capture_output=True, text=True, timeout=timeout, check=False)

    def audit_text(self) -> str:
        return self.audit.read_text(encoding="utf-8") if self.audit.exists() else ""

    def _write_payload(self) -> None:
        files = {
            "HYU VPN.app/Contents/MacOS/HYUVPNMenuApp": b"menu",
            "Install HYU VPN.app/Contents/MacOS/HYUVPNInstallerApp": b"installer",
            "hyu-vpn-macos-service": b"service",
            "com.hyu.vpn.helper": b"helper",
            "runtime/gp-hip-report": b"hip",
            "launchd/com.hyu.vpn.service.plist.in": plistlib.dumps({"Label": "com.hyu.vpn.service", "ProgramArguments": ["/Library/Application Support/HYU VPN/bin/hyu-vpn-macos-service"]}),
            "release-metadata.json": json.dumps({"schema": 1, "version": "0.2.3"}, separators=(",", ":")).encode(),
            "manifest.json": b"{}",
        }
        manifest: dict[str, dict[str, object]] = {}
        for rel, data in files.items():
            path = self.mount_payload / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            os.chmod(path, 0o755 if "MacOS" in rel or rel in {"hyu-vpn-macos-service", "com.hyu.vpn.helper", "runtime/gp-hip-report"} else 0o644)
        for rel in list(files):
            path = self.mount_payload / rel
            if rel == "manifest.json":
                continue
            manifest[rel] = {"sha256": sha(path), "size": path.stat().st_size, "mode": f"{path.stat().st_mode & 0o777:04o}"}
        (self.mount_payload / "manifest.json").write_text(json.dumps({"schema": 1, "files": manifest}, separators=(",", ":")), encoding="utf-8")


    def _write_installed_payload(self) -> None:
        mappings = {
            "hyu-vpn-macos-service": "/Library/Application Support/HYU VPN/bin/hyu-vpn-macos-service",
            "com.hyu.vpn.helper": "/Library/PrivilegedHelperTools/com.hyu.vpn.helper",
            "HYU VPN.app/Contents/MacOS/HYUVPNMenuApp": "/Applications/HYU VPN.app/Contents/MacOS/HYUVPNMenuApp",
        }
        for src_rel, dst_abs in mappings.items():
            src = self.mount_payload / src_rel
            dst = self.install_root / dst_abs.lstrip("/")
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            os.chmod(dst, 0o755)
        plist = self.home / "Library/LaunchAgents/com.hyu.vpn.service.plist"
        plist.parent.mkdir(parents=True, exist_ok=True)
        plist.write_bytes(plistlib.dumps({"Label": "com.hyu.vpn.service", "ProgramArguments": ["/Library/Application Support/HYU VPN/bin/hyu-vpn-macos-service"]}))
        os.chmod(plist, 0o644)

    def _write_tools(self, *, helper_invalid: bool) -> None:
        bin_dir = self.tools / "bin"
        bin_dir.mkdir(parents=True)
        for name in ("hdiutil", "codesign", "lipo", "file"):
            wrapper = bin_dir / name
            wrapper.write_text(f"#!/bin/bash\nexec '{self.tools}/{name}' \"$@\"\n", encoding="utf-8")
            wrapper.chmod(0o755)
        write_tool(self.tools, "/hdiutil", f"""
printf 'hdiutil %s\\n' "$*" >> '{self.audit}'
case "${{1:-}}" in
  verify) exit 0 ;;
  attach)
    mountpoint=""
    while [[ $# -gt 0 ]]; do
      if [[ "$1" == "-mountpoint" ]]; then mountpoint="$2"; shift 2; else shift; fi
    done
    [[ -n "$mountpoint" ]]
    cp -R '{self.mount_payload}/.' "$mountpoint/"
    exit 0 ;;
  detach) rm -rf "${{2:-}}"/*; exit 0 ;;
esac
exit 64
""")
        write_tool(self.tools, "/codesign", f"printf 'codesign %s\\n' \"$*\" >> '{self.audit}'\n")
        write_tool(self.tools, "/lipo", "printf 'arm64\n'\n")
        write_tool(self.tools, "/file", "printf 'Mach-O 64-bit executable arm64\n'\n")
        write_tool(self.tools, "/usr/bin/open", f"""
printf 'open %s\n' "$*" >> '{self.audit}'
if [[ "$*" == *'Install HYU VPN.app'* ]]; then
  /bin/mkdir -p '{self.install_root}/Library/Application Support/HYU VPN/bin' '{self.install_root}/Library/PrivilegedHelperTools' '{self.install_root}/Applications/HYU VPN.app/Contents/MacOS' '{self.home}/Library/LaunchAgents'
  /bin/cp '{self.mount_payload}/hyu-vpn-macos-service' '{self.install_root}/Library/Application Support/HYU VPN/bin/hyu-vpn-macos-service'
  /bin/cp '{self.mount_payload}/com.hyu.vpn.helper' '{self.install_root}/Library/PrivilegedHelperTools/com.hyu.vpn.helper'
  /bin/cp '{self.mount_payload}/HYU VPN.app/Contents/MacOS/HYUVPNMenuApp' '{self.install_root}/Applications/HYU VPN.app/Contents/MacOS/HYUVPNMenuApp'
  /bin/chmod 755 '{self.install_root}/Library/Application Support/HYU VPN/bin/hyu-vpn-macos-service' '{self.install_root}/Library/PrivilegedHelperTools/com.hyu.vpn.helper' '{self.install_root}/Applications/HYU VPN.app/Contents/MacOS/HYUVPNMenuApp'
  /bin/cp '{self.mount_payload}/launchd/com.hyu.vpn.service.plist.in' '{self.home}/Library/LaunchAgents/com.hyu.vpn.service.plist'
  /bin/chmod 644 '{self.home}/Library/LaunchAgents/com.hyu.vpn.service.plist'
fi
""")
        write_tool(self.tools, "/sbin/route", f"""
printf 'route %s\n' "$*" >> '{self.audit}'
printf '   route to: default\ndestination: default\n    gateway: 192.0.2.3\n  interface: en0\n      flags: <UP,GATEWAY,DONE,STATIC,WASCLONED>\n'
""")
        write_tool(self.tools, "/usr/sbin/scutil", "printf 'DNS configuration\nresolver #1\n  nameserver[0] : 9.9.9.9\n'\n")
        write_tool(self.tools, "/usr/bin/curl", f"""
state='{self.root}/wifi-state'
mode=$(cat "$state" 2>/dev/null || printf on)
if [[ "$mode" == off ]]; then exit 28; fi
url="${{@: -1}}"; case "$url" in *google*) printf '204';; *github*) printf '200';; *) printf '200';; esac
""")
        write_tool(self.tools, "/usr/bin/dig", "printf '140.82.112.4\n'\n")
        write_tool(self.tools, "/usr/bin/shasum", "exec /usr/bin/shasum \"$@\"\n")
        write_tool(self.tools, "/usr/bin/stat", "exec /usr/bin/stat \"$@\"\n")
        write_tool(self.tools, "/usr/bin/id", "printf '501\n'\n")
        write_tool(self.tools, "/usr/bin/pgrep", "case \"$*\" in *hyu-vpn-macos-service*) printf '111\n';; *HYUVPNMenuApp*) printf '222\n';; *) exit 1;; esac\n")
        write_tool(self.tools, "/bin/ps", """
if [[ "$*" == *'-axo command'* ]]; then printf '/usr/libexec/other\n'; exit 0; fi
if [[ "$*" == *'-p 4242'* ]]; then printf '  PID COMM STARTED\n 4242 openconnect 00:00:01\n'; exit 0; fi
if [[ "$*" == *'-p 7001'* ]]; then printf '  PID COMM STARTED\n 7001 openconnect 00:00:02\n'; exit 0; fi
if [[ "$*" == *'-p 7002'* ]]; then printf '  PID COMM STARTED\n 7002 openconnect 00:00:03\n'; exit 0; fi
printf '  PID COMM STARTED\n 777 openconnect 00:00:02\n'
""")
        write_tool(self.tools, "/bin/launchctl", f"printf 'launchctl %s\\n' \"$*\" >> '{self.audit}'\n")
        if helper_invalid:
            helper_status_body = "printf 'not-json\\nextra\\n'"
        else:
            helper_status_body = f"cat '{self.helper_state}'"
        write_tool(self.tools, "/usr/bin/sudo", f"""
printf 'sudo %s\n' "$*" >> '{self.audit}'
if [[ "$*" == *'com.hyu.vpn.helper status'* ]]; then {helper_status_body}; printf '\n'; exit 0; fi
if [[ "$*" == *'com.hyu.vpn.helper stop'* ]]; then printf '{{"schema_version":1,"state":"stopped","pid":null,"session_nonce":null,"tunnel_interface":null}}' > '{self.helper_state}'; printf '{{"schema_version":1,"state":"stopped","pid":null,"session_nonce":null,"tunnel_interface":null}}\n'; exit 0; fi
if [[ "$*" == *'root-admin.sh'* ]]; then
  [[ "$*" == *'--payload '* && "$*" == *'--manifest '* ]] || exit 66
  if [[ "$*" == *'--administrator-phase uninstall'* ]]; then
    [[ "$*" == *'hyu-install-mutation-'* ]] || exit 67
    /bin/rm -rf '{self.install_root}/Library/Application Support/HYU VPN' '{self.install_root}/Library/PrivilegedHelperTools/com.hyu.vpn.helper' '{self.install_root}/Applications/HYU VPN.app'
    /bin/rm -f '{self.home}/Library/LaunchAgents/com.hyu.vpn.service.plist'
  fi
  if [[ "$*" == *'--dry-run-root'* ]]; then
    [[ "$*" == *'{self.test_root}'* && "${{HYU_VPN_FAIL_AFTER:-}}" == health ]] || exit 68
    exit 42
  fi
  exit 0
fi
exit 0
""")
        write_tool(self.tools, "/usr/sbin/networksetup", f"""
printf 'networksetup %s\n' "$*" >> '{self.audit}'
if [[ "${{1:-}}" == "-listallhardwareports" ]]; then printf 'Hardware Port: Wi-Fi\nDevice: en0\nEthernet Address: aa:bb:cc:dd:ee:ff\n'; exit 0; fi
if [[ "${{1:-}}" == "-setairportpower" && "${{3:-}}" == off ]]; then printf off > '{self.root}/wifi-state'; exit 0; fi
if [[ "${{1:-}}" == "-setairportpower" && "${{3:-}}" == on ]]; then printf on > '{self.root}/wifi-state'; printf '{{"schema_version":1,"state":"running","pid":9001,"session_nonce":"WIFI1234","tunnel_interface":"utun12"}}' > '{self.helper_state}'; exit 0; fi
exit 0
""")
        write_tool(self.tools, "/usr/bin/python3", f"""
if [[ "$*" == *'installer/manifest.py'* && "$*" == *'--stage-user-payload'* ]]; then
  stage=""
  while [[ $# -gt 0 ]]; do
    if [[ "$1" == "--stage-dir" ]]; then stage="$2"; shift 2; else shift; fi
  done
  [[ -n "$stage" ]]
  /bin/mkdir -p "$stage/bin"
  printf service > "$stage/bin/hyu-vpn-macos-service"
  printf '{{"schema":1,"files":{{"bin/hyu-vpn-macos-service":{{"sha256":"00","size":7,"mode":"0755"}}}}}}' > "$stage/manifest.json"
  exit 0
fi
if [[ "$*" == *'RootAdminShellHarnessTests'* ]]; then printf 'Ran 1 test in 0.1s\nOK\n'; exit 0; fi
exec /usr/bin/python3 "$@"
""")
        write_tool(self.tools, "/bin/zsh", f"""
printf 'zsh %s\n' "$*" >> '{self.audit}'
if [[ "$*" == *'root-admin.sh'* ]]; then
  [[ "$*" == *'--dry-run-root {self.test_root}'* ]] || exit 68
  [[ "$*" == *'--stage-manifest-sha256 '* && "$*" == *'--package-manifest-sha256 '* ]] || exit 70
  [[ "${{HYU_VPN_FAIL_AFTER:-}}" == health ]] || exit 71
  /bin/mkdir -p '{self.test_root}/private/var/db/hyu-vpn'
  printf 'install-pending\nrollback-complete\n' > '{self.test_root}/private/var/db/hyu-vpn/install-transaction.log'
  printf complete > '{self.test_root}/private/var/db/hyu-vpn/transaction-state'
  printf 'injected failure after health\n' >&2
  exit 42
fi
exec /bin/zsh "$@"
""")

def evidence_json(f: Task9Fixture) -> str:
    return json.dumps({
        "schema_version": 1,
        "test_root": str(f.test_root.resolve()),
        "dmg_sha256": sha(f.dmg),
        "manifest_sha256": sha(f.mount_payload / "manifest.json"),
        "stage_sha256": sha(f.stage_manifest),
        "injection": "health",
        "timestamp_epoch": int(time.time()),
        "command_contract": "root-admin-dry-run-health",
        "result": "rollback-proved",
    })


class LiveMacOSRustAcceptanceTests(unittest.TestCase):
    def test_preflight_captures_actual_baseline_helper_and_hyu_openconnect_credential_metadata(self):
        with Task9Fixture(self) as f:
            result = f.run("--mode", "preflight")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("mode=preflight", result.stdout)
        self.assertIn("baseline.default_route.identity=", result.stdout)
        self.assertIn("baseline.dns.sha256=", result.stdout)
        self.assertIn("internet.google=ok", result.stdout)
        self.assertIn("baseline.helper.state=running", result.stdout)
        self.assertIn("baseline.helper.pid=4242", result.stdout)
        self.assertIn("baseline.helper.nonce.sha256=", result.stdout)
        self.assertIn("credential_metadata.path=Library/Application Support/hyu-openconnect/credentials.key", result.stdout)
        self.assertIn("credential_metadata.path=Library/Application Support/hyu-openconnect/credentials.enc", result.stdout)
        self.assertNotRegex(result.stdout + result.stderr, r"(?i)(password|totp|cookie|ABCDEF12|key-material|ciphertext)")

    def test_preflight_accepts_exact_legacy_stopped_helper_status(self):
        with Task9Fixture(self) as f:
            write_tool(f.tools, "/usr/bin/sudo", """
if [[ "$*" == *'com.hyu.vpn.helper status'* ]]; then
  printf '{"schema_version":1,"state":"stopped"}\n'
  exit 0
fi
exit 0
""")
            result = f.run("--mode", "preflight")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("baseline.helper.state=stopped", result.stdout)

    def test_preflight_rejects_invalid_multiline_helper_status(self):
        with Task9Fixture(self, helper_invalid=True) as f:
            result = f.run("--mode", "preflight")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("helper status invalid", result.stderr)

    def test_test_root_executes_targeted_unittest_and_writes_evidence_not_contract_only(self):
        with Task9Fixture(self) as f:
            result = f.run("--mode", "test-root", "--dmg", str(f.dmg), "--test-root", str(f.test_root), "--rollback-injection", "health", "--evidence-out", str(f.evidence))
            audit = f.audit_text()
            evidence = f.evidence.read_text(encoding="utf-8") if f.evidence.exists() else ""
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("test_root.rollback=proved", result.stdout)
            self.assertNotIn("contract-only", result.stdout)
            self.assertIn("zsh ", audit)
            self.assertNotIn("sudo -n", audit)
            self.assertIn("rollback-proved", evidence)

    def test_live_requires_dmg_acceptance_rerun_test_root_evidence_and_audits_exact_state_machine(self):
        with Task9Fixture(self) as f:
            nonce = f"hyu-live-macos-rust-{int(time.time())}"
            f.evidence.write_text(evidence_json(f), encoding="utf-8"); os.chmod(f.evidence, 0o600)
            commands: list[str] = []
            statuses = [
                {"schema_version": 1, "state": "disabled", "automatic_reconnect_enabled": True, "connected_at": None, "session_expires_at": None, "last_successful_hip_at": None, "tunnel_interface": None, "next_retry_at": None, "error_code": None, "last_transition_at": "2026-08-12T00:00:00Z", "backend_build_version": "0.2.3"},
                {"schema_version": 1, "state": "connected", "automatic_reconnect_enabled": True, "connected_at": "2026-08-12T00:00:01Z", "session_expires_at": None, "last_successful_hip_at": "2026-08-12T00:00:01Z", "tunnel_interface": "utun9", "next_retry_at": None, "error_code": None, "last_transition_at": "2026-08-12T00:00:01Z", "backend_build_version": "0.2.3"},
                {"schema_version": 1, "state": "disabled", "automatic_reconnect_enabled": True, "connected_at": None, "session_expires_at": None, "last_successful_hip_at": None, "tunnel_interface": None, "next_retry_at": None, "error_code": None, "last_transition_at": "2026-08-12T00:00:02Z", "backend_build_version": "0.2.3"},
            ]
            with IpcServer(f.socket, commands, [statuses[1], statuses[1], statuses[1], statuses[1], statuses[2], statuses[1]], helper_state=f.helper_state) as server:
                result = f.run(
                    "--mode", "live",
                    "--dmg", str(f.dmg),
                    "--test-root", str(f.test_root),
                    "--nonce", nonce,
                    "--user-present", USER_PRESENT,
                    env={"HYU_LIVE_MACOS_RUST_NONCE": nonce},
                    timeout=30,
                )
                audit = f.audit_text()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("dmg_acceptance=rerun-pass", result.stdout)
        self.assertIn("phase=install_identity result=verified", result.stdout)
        self.assertIn("phase=owned_openconnect_stop_reconnect result=verified", result.stdout)
        self.assertIn("phase=rust_service_restart_reconciliation result=verified", result.stdout)
        self.assertIn("phase=disconnect_route_dns_restore result=verified", result.stdout)
        self.assertIn("phase=uninstall_residue_checks result=not-exercised", result.stdout)
        self.assertIn("task9_completion=partial-uninstall-not-exercised", result.stdout)
        self.assertIn("hdiutil verify", audit)
        self.assertIn("hdiutil attach -readonly -nobrowse", audit)
        self.assertIn("open -W", audit)
        self.assertIn("sudo -n /Library/PrivilegedHelperTools/com.hyu.vpn.helper status", audit)
        self.assertIn("sudo -n /Library/PrivilegedHelperTools/com.hyu.vpn.helper stop", audit)
        self.assertIn("launchctl kickstart -k gui/501/com.hyu.vpn.service", audit)
        self.assertNotIn("PASS forged", result.stdout + result.stderr)
        self.assertIn("connect", commands)
        self.assertIn("disconnect", commands)
        self.assertTrue(any(req.get("schema_version") == 1 and set(req) == {"schema_version", "request_id", "command"} for req in server.seen))

    def test_live_rejects_missing_test_root_evidence_and_placeholder_not_provided_claims(self):
        with Task9Fixture(self) as f:
            nonce = f"hyu-live-macos-rust-{int(time.time())}"
            result = f.run("--mode", "live", "--dmg", str(f.dmg), "--test-root", str(f.test_root), "--nonce", nonce, "--user-present", USER_PRESENT, env={"HYU_LIVE_MACOS_RUST_NONCE": nonce})
        self.assertEqual(result.returncode, 2)
        self.assertIn("test-root evidence required", result.stderr)
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn("contract-only", text)
        self.assertNotIn("dmg_acceptance=not-provided", text)
        self.assertNotIn("available-helper-repair-only", text)

    def test_live_exercise_uninstall_reinstall_gate_invokes_uninstall_and_reinstall(self):
        with Task9Fixture(self) as f:
            nonce = f"hyu-live-macos-rust-{int(time.time())}"
            f.evidence.write_text(evidence_json(f), encoding="utf-8"); os.chmod(f.evidence, 0o600)
            commands: list[str] = []
            connected = {"schema_version": 1, "state": "connected", "automatic_reconnect_enabled": True, "connected_at": "2026-08-12T00:00:01Z", "session_expires_at": None, "last_successful_hip_at": "2026-08-12T00:00:01Z", "tunnel_interface": "utun9", "next_retry_at": None, "error_code": None, "last_transition_at": "2026-08-12T00:00:01Z", "backend_build_version": "0.2.3"}
            disabled = dict(connected, state="disabled", connected_at=None, last_successful_hip_at=None, tunnel_interface=None)
            with IpcServer(f.socket, commands, [connected, connected, connected, connected, disabled, connected, connected], helper_state=f.helper_state):
                result = f.run("--mode", "live", "--dmg", str(f.dmg), "--test-root", str(f.test_root), "--nonce", nonce, "--user-present", USER_PRESENT, "--exercise-uninstall-reinstall", env={"HYU_LIVE_MACOS_RUST_NONCE": nonce}, timeout=30)
                audit = f.audit_text()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("phase=uninstall_residue_checks result=verified-reinstalled", result.stdout)
        self.assertIn("task9_completion=full-scripted-except-physical-wifi", result.stdout)
        self.assertRegex(audit, r"sudo .*root-admin\.sh.*--administrator-phase uninstall")
        self.assertGreaterEqual(audit.count("open -W"), 2)

    def test_physical_wifi_gate_is_final_flagged_and_uses_exact_restore_trap_commands(self):
        with Task9Fixture(self) as f:
            nonce = f"hyu-live-macos-rust-{int(time.time())}"
            f.evidence.write_text(evidence_json(f), encoding="utf-8"); os.chmod(f.evidence, 0o600)
            status = {"schema_version": 1, "state": "connected", "automatic_reconnect_enabled": True, "connected_at": "2026-08-12T00:00:01Z", "session_expires_at": None, "last_successful_hip_at": "2026-08-12T00:00:01Z", "tunnel_interface": "utun9", "next_retry_at": None, "error_code": None, "last_transition_at": "2026-08-12T00:00:01Z", "backend_build_version": "0.2.3"}
            disabled = dict(status, state="disabled", connected_at=None, last_successful_hip_at=None, tunnel_interface=None)
            with IpcServer(f.socket, [], [status, status, status, status, status, dict(status, state="connecting", tunnel_interface="utun9", last_transition_at="2026-08-12T00:00:02Z"), dict(status, last_transition_at="2026-08-12T00:00:03Z"), disabled], helper_state=f.helper_state):
                result = f.run("--mode", "live", "--dmg", str(f.dmg), "--test-root", str(f.test_root), "--nonce", nonce, "--user-present", USER_PRESENT, "--physical-wifi-gate", env={"HYU_LIVE_MACOS_RUST_NONCE": nonce}, timeout=30)
                audit = f.audit_text()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertLess(result.stdout.index("phase=rust_service_restart_reconciliation"), result.stdout.index("phase=physical_wifi_gate"))
        self.assertLess(result.stdout.index("phase=physical_wifi_gate"), result.stdout.index("phase=disconnect_route_dns_restore"))
        self.assertIn("phase=physical_wifi_gate result=verified", result.stdout)
        self.assertIn("networksetup -listallhardwareports", audit)
        self.assertIn("networksetup -setairportpower en0 off", audit)
        self.assertIn("networksetup -setairportpower en0 on", audit)


    def _run_live_with_statuses(self, f: Task9Fixture, statuses: list[dict[str, object]], *, same_generation: bool = False, flags: tuple[str, ...] = ()):
        nonce = f"hyu-live-macos-rust-{int(time.time())}"
        f.evidence.write_text(evidence_json(f), encoding="utf-8"); os.chmod(f.evidence, 0o600)
        commands: list[str] = []
        with IpcServer(f.socket, commands, statuses, helper_state=f.helper_state, same_generation=same_generation):
            return f.run("--mode", "live", "--dmg", str(f.dmg), "--test-root", str(f.test_root), "--nonce", nonce, "--user-present", USER_PRESENT, *flags, env={"HYU_LIVE_MACOS_RUST_NONCE": nonce}, timeout=45)

    def test_round3_a_rejects_wrong_installed_service_hash(self):
        with Task9Fixture(self) as f:
            write_tool(f.tools, "/usr/bin/open", f"""
printf 'open %s\n' "$*" >> '{f.audit}'
/bin/mkdir -p '{f.install_root}/Library/Application Support/HYU VPN/bin' '{f.install_root}/Library/PrivilegedHelperTools' '{f.install_root}/Applications/HYU VPN.app/Contents/MacOS' '{f.home}/Library/LaunchAgents'
printf tampered > '{f.install_root}/Library/Application Support/HYU VPN/bin/hyu-vpn-macos-service'
/bin/cp '{f.mount_payload}/com.hyu.vpn.helper' '{f.install_root}/Library/PrivilegedHelperTools/com.hyu.vpn.helper'
/bin/cp '{f.mount_payload}/HYU VPN.app/Contents/MacOS/HYUVPNMenuApp' '{f.install_root}/Applications/HYU VPN.app/Contents/MacOS/HYUVPNMenuApp'
/bin/chmod 755 '{f.install_root}/Library/Application Support/HYU VPN/bin/hyu-vpn-macos-service' '{f.install_root}/Library/PrivilegedHelperTools/com.hyu.vpn.helper' '{f.install_root}/Applications/HYU VPN.app/Contents/MacOS/HYUVPNMenuApp'
/bin/cp '{f.mount_payload}/launchd/com.hyu.vpn.service.plist.in' '{f.home}/Library/LaunchAgents/com.hyu.vpn.service.plist'
""")
            st = {"schema_version": 1, "state": "connected", "automatic_reconnect_enabled": True, "connected_at": "2026-08-12T00:00:01Z", "session_expires_at": None, "last_successful_hip_at": "2026-08-12T00:00:01Z", "tunnel_interface": "utun9", "next_retry_at": None, "error_code": None, "last_transition_at": "2026-08-12T00:00:01Z", "backend_build_version": "0.2.3"}
            result = self._run_live_with_statuses(f, [st, st, st, st, dict(st, state="disabled", connected_at=None, last_successful_hip_at=None, tunnel_interface=None)])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("installed service hash mismatch", result.stderr)

    def test_round3_b_rejects_legacy_python_residue_categories(self):
        with Task9Fixture(self) as f:
            residue = f.install_root / "Library/Application Support/HYU VPN/src/hyu_vpn"
            residue.mkdir(parents=True)
            st = {"schema_version": 1, "state": "connected", "automatic_reconnect_enabled": True, "connected_at": "2026-08-12T00:00:01Z", "session_expires_at": None, "last_successful_hip_at": "2026-08-12T00:00:01Z", "tunnel_interface": "utun9", "next_retry_at": None, "error_code": None, "last_transition_at": "2026-08-12T00:00:01Z", "backend_build_version": "0.2.3"}
            result = self._run_live_with_statuses(f, [st, st, st, st, dict(st, state="disabled", connected_at=None, last_successful_hip_at=None, tunnel_interface=None)])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("python/legacy residue categories=legacy:1", result.stderr)
        self.assertNotIn("src/hyu_vpn", result.stderr)

    def test_round3_c_rejects_owned_reconnect_same_pid_nonce(self):
        with Task9Fixture(self) as f:
            st = {"schema_version": 1, "state": "connected", "automatic_reconnect_enabled": True, "connected_at": "2026-08-12T00:00:01Z", "session_expires_at": None, "last_successful_hip_at": "2026-08-12T00:00:01Z", "tunnel_interface": "utun9", "next_retry_at": None, "error_code": None, "last_transition_at": "2026-08-12T00:00:01Z", "backend_build_version": "0.2.3"}
            result = self._run_live_with_statuses(f, [st, st, st, st, dict(st, state="disabled", connected_at=None, last_successful_hip_at=None, tunnel_interface=None)], same_generation=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("owned reconnect reused generation", result.stderr)

    def test_round3_d_rejects_service_restart_changed_helper_generation(self):
        with Task9Fixture(self) as f:
            write_tool(f.tools, "/bin/launchctl", f"printf 'launchctl %s\\n' \"$*\" >> '{f.audit}'\nprintf '{{\"schema_version\":1,\"state\":\"running\",\"pid\":9002,\"session_nonce\":\"RSTRT999\",\"tunnel_interface\":\"utun13\"}}' > '{f.helper_state}'\n")
            st = {"schema_version": 1, "state": "connected", "automatic_reconnect_enabled": True, "connected_at": "2026-08-12T00:00:01Z", "session_expires_at": None, "last_successful_hip_at": "2026-08-12T00:00:01Z", "tunnel_interface": "utun9", "next_retry_at": None, "error_code": None, "last_transition_at": "2026-08-12T00:00:01Z", "backend_build_version": "0.2.3"}
            result = self._run_live_with_statuses(f, [st, st, st, st, dict(st, state="disabled", connected_at=None, last_successful_hip_at=None, tunnel_interface=None)])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("service restart changed helper generation", result.stderr)

    def test_round3_e_test_root_invokes_exact_root_admin_dry_root_contract(self):
        with Task9Fixture(self) as f:
            result = f.run("--mode", "test-root", "--dmg", str(f.dmg), "--test-root", str(f.test_root), "--evidence-out", str(f.evidence))
            audit = f.audit_text()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("HYU_VPN_FAIL_AFTER", (ROOT / "scripts/live-macos-rust-acceptance.sh").read_text())
        self.assertIn(f"--dry-run-root {f.test_root}", audit)
        self.assertIn("--administrator-phase install", audit)
        self.assertIn(f"--tools-root {f.test_root}/Users/.task9-tools", audit)
        self.assertNotIn("sudo -n", audit)

    def test_round3_g_rejects_wifi_gate_when_internet_never_drops(self):
        with Task9Fixture(self) as f:
            write_tool(f.tools, "/usr/sbin/networksetup", f"printf 'networksetup %s\\n' \"$*\" >> '{f.audit}'\nif [[ \"${{1:-}}\" == \"-listallhardwareports\" ]]; then printf 'Hardware Port: Wi-Fi\\nDevice: en0\\n'; fi\nexit 0\n")
            st = {"schema_version": 1, "state": "connected", "automatic_reconnect_enabled": True, "connected_at": "2026-08-12T00:00:01Z", "session_expires_at": None, "last_successful_hip_at": "2026-08-12T00:00:01Z", "tunnel_interface": "utun9", "next_retry_at": None, "error_code": None, "last_transition_at": "2026-08-12T00:00:01Z", "backend_build_version": "0.2.3"}
            nonce = f"hyu-live-macos-rust-{int(time.time())}"
            f.evidence.write_text(evidence_json(f), encoding="utf-8"); os.chmod(f.evidence, 0o600)
            with IpcServer(f.socket, [], [st, st, st, st, st, st], helper_state=f.helper_state):
                result = f.run("--mode", "live", "--dmg", str(f.dmg), "--test-root", str(f.test_root), "--nonce", nonce, "--user-present", USER_PRESENT, "--physical-wifi-gate", env={"HYU_LIVE_MACOS_RUST_NONCE": nonce}, timeout=75)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("wifi internet did not drop", result.stderr)


    def test_round4_test_root_rejects_auth_failure_without_evidence(self):
        with Task9Fixture(self) as f:
            write_tool(f.tools, "/bin/zsh", f"printf 'zsh %s\\n' \"$*\" >> '{f.audit}'\nprintf 'sudo: a password is required\\n' >&2\nexit 1\n")
            result = f.run("--mode", "test-root", "--dmg", str(f.dmg), "--test-root", str(f.test_root), "--evidence-out", str(f.evidence))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("root-admin dry-run used live authentication", result.stderr)
        self.assertFalse(f.evidence.exists())

    def test_round4_live_rejects_stage_manifest_digest_tamper(self):
        with Task9Fixture(self) as f:
            f.evidence.write_text(evidence_json(f), encoding="utf-8")
            os.chmod(f.evidence, 0o600)
            f.stage_manifest.write_text("tampered-stage-manifest", encoding="utf-8")
            nonce = f"hyu-live-macos-rust-{int(time.time())}"
            result = f.run("--mode", "live", "--dmg", str(f.dmg), "--test-root", str(f.test_root), "--nonce", nonce, "--user-present", USER_PRESENT, env={"HYU_LIVE_MACOS_RUST_NONCE": nonce})
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("phase=install_identity", result.stdout)

    def test_round4_wifi_gate_rejects_automatic_reconnect_disabled(self):
        with Task9Fixture(self) as f:
            st = {"schema_version": 1, "state": "connected", "automatic_reconnect_enabled": False, "connected_at": "2026-08-12T00:00:01Z", "session_expires_at": None, "last_successful_hip_at": "2026-08-12T00:00:01Z", "tunnel_interface": "utun9", "next_retry_at": None, "error_code": None, "last_transition_at": "2026-08-12T00:00:01Z", "backend_build_version": "0.2.3"}
            result = self._run_live_with_statuses(f, [dict(st, automatic_reconnect_enabled=True), dict(st, automatic_reconnect_enabled=True), dict(st, automatic_reconnect_enabled=True), dict(st, automatic_reconnect_enabled=True), st], flags=("--physical-wifi-gate",))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("automatic reconnect disabled before wifi gate", result.stderr)

    def test_round4_bounded_gui_installer_timeout_fails(self):
        with Task9Fixture(self) as f:
            write_tool(f.tools, "/usr/bin/open", f"printf 'open %s\\n' \"$*\" >> '{f.audit}'\nsleep 5\n")
            st = {"schema_version": 1, "state": "connected", "automatic_reconnect_enabled": True, "connected_at": "2026-08-12T00:00:01Z", "session_expires_at": None, "last_successful_hip_at": "2026-08-12T00:00:01Z", "tunnel_interface": "utun9", "next_retry_at": None, "error_code": None, "last_transition_at": "2026-08-12T00:00:01Z", "backend_build_version": "0.2.3"}
            nonce = f"hyu-live-macos-rust-{int(time.time())}"
            f.evidence.write_text(evidence_json(f), encoding="utf-8"); os.chmod(f.evidence, 0o600)
            with IpcServer(f.socket, [], [st], helper_state=f.helper_state):
                result = f.run("--mode", "live", "--dmg", str(f.dmg), "--test-root", str(f.test_root), "--nonce", nonce, "--user-present", USER_PRESENT, env={"HYU_LIVE_MACOS_RUST_NONCE": nonce, "HYU_LIVE_MACOS_RUST_INSTALLER_TIMEOUT_SECONDS": "1"}, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("installer app timed out", result.stderr)

    def test_docs_and_report_are_updated_with_non_forgeable_boundaries(self):
        checklist = CHECKLIST.read_text(encoding="utf-8")
        report = REPORT.read_text(encoding="utf-8")
        for text in (checklist, report):
            self.assertIn("reruns scripts/macos-dmg-acceptance.sh", text)
            self.assertIn("test-root evidence", text)
            self.assertIn("--exercise-uninstall-reinstall", text)
            self.assertIn("Unix-socket framed IPC", text)
            self.assertIn("physical Wi-Fi gate last", text)
            self.assertNotIn("contract-only", text)

    def test_fix2_static_contracts_socket_protocol_cleanup_and_no_load_bearing_true(self):
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('SOCKET_PATH="${HYU_LIVE_MACOS_RUST_SOCKET:-$HOME/Library/Application Support/hyu-openconnect/daemon.sock}"', text)
        self.assertIn('"result":"ack"', text)
        self.assertIn('"result":"status"', text)
        self.assertNotIn('"ok"', text)
        self.assertNotIn('"error_code"', text)
        self.assertNotIn('validate_backend_status "$st" connected || true', text)
        self.assertNotIn('validate_backend_status "$st" disabled || true', text)
        self.assertNotIn('rm -rf "$MOUNT_PARENT" || true', text)
        self.assertIn('cleanup_detach', text)
        self.assertIn('validate_nonce_dir', text)
        self.assertIn('hyu-install-mutation-', text)
        self.assertIn('wait_until_unhealthy', text)
        self.assertIn('wait_wifi_connected_transition', text)
        self.assertIn('EXPECTED_BACKEND_VERSION', text)
        self.assertIn('release-metadata.json', text)
        self.assertNotIn('d["backend_build_version"]=="0.2.3"', text)

    def test_fix2_ipc_uses_exact_rust_protocol_ack_and_status_variants(self):
        with Task9Fixture(self) as f:
            f.evidence.write_text(json.dumps({
                "schema_version": 1,
                "test_root": str(f.test_root.resolve()),
                "dmg_sha256": sha(f.dmg),
                "manifest_sha256": sha(f.mount_payload / "manifest.json"),
                "stage_sha256": sha(f.stage_manifest),
                "injection": "health",
                "timestamp_epoch": int(time.time()),
                "command_contract": "root-admin-dry-run-health",
                "result": "rollback-proved",
            }), encoding="utf-8")
            os.chmod(f.evidence, 0o600)
            nonce = f"hyu-live-macos-rust-{int(time.time())}"
            commands: list[str] = []
            connected_status = {"schema_version": 1, "state": "connected", "automatic_reconnect_enabled": True, "connected_at": "2026-08-12T00:00:01Z", "session_expires_at": None, "last_successful_hip_at": "2026-08-12T00:00:01Z", "tunnel_interface": "utun9", "next_retry_at": None, "error_code": None, "last_transition_at": "2026-08-12T00:00:01Z", "backend_build_version": "0.2.3"}
            disabled_status = dict(connected_status, state="disabled", connected_at=None, last_successful_hip_at=None, tunnel_interface=None)
            with IpcServer(f.socket, commands, [connected_status, connected_status, connected_status, connected_status, disabled_status], protocol="rust", helper_state=f.helper_state) as server:
                result = f.run("--mode", "live", "--dmg", str(f.dmg), "--test-root", str(f.test_root), "--nonce", nonce, "--user-present", USER_PRESENT, env={"HYU_LIVE_MACOS_RUST_NONCE": nonce}, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(all(set(req) == {"schema_version", "request_id", "command"} for req in server.seen))
        self.assertIn("phase=real_connection_helper_owned_utun result=verified", result.stdout)

    def test_fix2_test_root_evidence_is_json_bound_to_dmg_manifest_and_mode_0600(self):
        with Task9Fixture(self) as f:
            result = f.run("--mode", "test-root", "--dmg", str(f.dmg), "--test-root", str(f.test_root), "--rollback-injection", "health", "--evidence-out", str(f.evidence))
            self.assertEqual(result.returncode, 0, result.stderr)
            evidence = json.loads(f.evidence.read_text(encoding="utf-8"))
            self.assertEqual(f.evidence.stat().st_mode & 0o777, 0o600)
            self.assertEqual(evidence["schema_version"], 1)
            self.assertEqual(evidence["test_root"], str(f.test_root.resolve()))
            self.assertEqual(evidence["dmg_sha256"], sha(f.dmg))
            self.assertEqual(evidence["manifest_sha256"], sha(f.mount_payload / "manifest.json"))
            self.assertEqual(evidence["injection"], "health")
            self.assertEqual(evidence["command_contract"], "root-admin-dry-run-health")
            self.assertEqual(evidence["result"], "rollback-proved")
            self.assertNotIn("task9-test-root-ok", f.evidence.read_text(encoding="utf-8"))

    def test_fix2_temp_cleanup_success_leaves_no_live_mount_temp_dirs(self):
        before = {p.resolve(strict=False) for p in Path("/private/tmp").glob("hyu-live-macos-rust.*")}
        with Task9Fixture(self) as f:
            result = f.run("--mode", "preflight", "--dmg", str(f.dmg))
            self.assertEqual(result.returncode, 0, result.stderr)
        after = {p.resolve(strict=False) for p in Path("/private/tmp").glob("hyu-live-macos-rust.*")}
        self.assertEqual(after - before, set())


if __name__ == "__main__":
    unittest.main()
