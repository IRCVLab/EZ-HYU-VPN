import json
import os
import plistlib
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import hashlib
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
from installer.manifest import CommandRecorder, DryRunEnvironment, ManifestError, PayloadManifest, safe_join, stage_user_payload, _write_stage_manifest


class InstallerTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.payload = self.root / "Payload With Spaces"
        self.payload.mkdir()
        self._write_payload()
        self.manifest_path = PayloadManifest.write_for_tree(self.payload, self.payload / "manifest.json")

    def tearDown(self):
        self.tmp.cleanup()

    def _script(self, rel: str, text: str = '#!/bin/sh\nif [ "${1:-}" = root-util ] && [ "${2:-}" = fsync ]; then exit 0; fi\nif [ "${1:-}" = root-util ] && [ "${2:-}" = helper-state ]; then\n  raw=$(cat)\n  case "$raw" in\n    *\'"schema_version":1\'*\'"state":"stopped"\'*\'"pid":null\'*\'"session_nonce":null\'*\'"tunnel_interface":null\'*) printf \'%s\\n\' stopped; exit 0 ;;\n    *\'"schema_version":1\'*\'"state":"running"\'*\'"pid":\'*\'"session_nonce":"\'*\'"tunnel_interface":"utun\'*) printf \'%s\\n\' running; exit 0 ;;\n    *\'"schema_version":1\'*\'"state":"repair-required"\'*\'"pid":null\'*\'"session_nonce":"\'*\'"tunnel_interface":null\'*) printf \'%s\\n\' repair-required; exit 0 ;;\n  esac\n  exit 70\nfi\nif [ "${1:-}" = root-util ] && [ "${2:-}" = helper-repair-nonce ]; then sed -n \'s/.*"session_nonce":"\\([A-Za-z0-9_-][A-Za-z0-9_-]*\\)".*/\\1/p\' | head -n 1; exit 0; fi\nif [ "${1:-}" = status ]; then printf \'%s\\n\' \'{"schema_version":1,"state":"stopped","pid":null,"session_nonce":null,"tunnel_interface":null}\'; else printf ok; fi\n') -> Path:
        p = self.payload / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        p.chmod(0o755)
        return p

    def _write_payload(self):
        for rel in [
            "runtime/openconnect/bin/openconnect",
            "runtime/oathtool",
            "runtime/gp-hip-report",
            "runtime/vpnc/hyu-vpnc-wrapper",
            "runtime/vpnc/hyu-vpnc-wrapperd",
            "runtime/vpnc/vpnc-script",
            "hyu-vpn-macos-service",
        ]:
            self._script(rel)
        (self.payload / "runtime/openconnect/lib").mkdir(parents=True)
        self._script("runtime/openconnect/lib/libvpn.dylib", "lib")
        self._script(
            "com.hyu.vpn.helper",
            """#!/bin/sh
root=${0%%/Library/PrivilegedHelperTools/com.hyu.vpn.helper}
state="$root/private/var/db/hyu-vpn/fake-helper-state"
mkdir -p "$(dirname "$state")"
current=$(cat "$state" 2>/dev/null || printf stopped)
case "${1:-}" in
  status)
    case "$current" in
      stopped) printf '%s\\n' '{"schema_version":1,"state":"stopped","pid":null,"session_nonce":null,"tunnel_interface":null}' ;;
      running) printf '%s\\n' '{"schema_version":1,"state":"running","pid":123,"session_nonce":"fake12345","tunnel_interface":"utun7"}' ;;
      repair-required) printf '%s\\n' '{"schema_version":1,"state":"repair-required","pid":null,"session_nonce":"fake12345","tunnel_interface":null}' ;;
      *) exit 65 ;;
    esac
    ;;
  stop)
    printf stopped > "$state"
    ;;
  repair)
    [ "${HYU_FAKE_NEW_HELPER_REPAIR_FAIL:-0}" = 1 ] && exit 42
    printf stopped > "$state"
    ;;
  *) exit 64 ;;
esac
""",
        )
        (self.payload / "config").mkdir()
        (self.payload / "config/final-runtime-manifest.json").write_text('{"schema":1,"release_gate":"non_release_task8_placeholder"}\n', encoding="utf-8")
        (self.payload / "installer").mkdir()
        shutil.copy2(REPO / "installer" / "manifest.py", self.payload / "installer" / "manifest.py")
        (self.payload / "installer" / "manifest.py").chmod(0o755)
        (self.payload / "launchd").mkdir()
        for template in ["com.hyu.vpn.service.plist.in"]:
            shutil.copy2(REPO / "launchd" / template, self.payload / "launchd" / template)
        app_exec = self.payload / "HYU VPN.app/Contents/MacOS/HYUVPNMenuApp"
        app_exec.parent.mkdir(parents=True)
        app_exec.write_text("app", encoding="utf-8")
        app_exec.chmod(0o755)
        credential_reader = self.payload / "HYU VPN.app/Contents/MacOS/HYUVPNCredentialReader"
        credential_reader.write_text("reader", encoding="utf-8")
        credential_reader.chmod(0o755)

    def env(self):
        return DryRunEnvironment(root=self.root / "dry root", payload=self.payload, home=self.root / "home dir", manifest=self.manifest_path)


class PayloadManifestTests(InstallerTestCase):
    def test_manifest_verify_rejects_hash_mode_extra_and_symlink(self):
        (self.payload / "hyu-vpn-macos-service").write_text("tampered", encoding="utf-8")
        with self.assertRaisesRegex(ManifestError, "hash mismatch"):
            PayloadManifest.verify(self.payload, self.manifest_path)
        self._script("hyu-vpn-macos-service")
        data = json.loads(self.manifest_path.read_text())
        data["files"]["hyu-vpn-macos-service"]["mode"] = "0600"
        bad = self.payload / "bad-mode.json"
        bad.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaisesRegex(ManifestError, "mode mismatch"):
            PayloadManifest.verify(self.payload, bad)
        bad.unlink()
        (self.payload / "extra").write_text("x", encoding="utf-8")
        with self.assertRaisesRegex(ManifestError, "unmanifested"):
            PayloadManifest.verify(self.payload, self.manifest_path)
        (self.payload / "extra").unlink()
        (self.payload / "evil-link").symlink_to(self.root / "outside")
        with self.assertRaisesRegex(ManifestError, "symlink"):
            PayloadManifest.build(self.payload)


    def test_manifest_rejects_duplicate_keys_root_manifest_symlink_and_special_entries(self):
        duplicate = self.payload / "duplicate.json"
        duplicate.write_text('{"schema":1,"schema":1,"files":{}}', encoding="utf-8")
        with self.assertRaisesRegex(ManifestError, "duplicate JSON key"):
            PayloadManifest.verify(self.payload, duplicate)
        manifest = self.payload / "manifest.json"
        manifest.unlink()
        manifest.symlink_to(self.payload / "duplicate.json")
        with self.assertRaisesRegex(ManifestError, "manifest symlink"):
            PayloadManifest.verify(self.payload, manifest)
        manifest.unlink()
        self.manifest_path = PayloadManifest.write_for_tree(self.payload, self.payload / "manifest.json")
        fifo = self.payload / "fifo-entry"
        try:
            os.mkfifo(fifo)
        except (AttributeError, PermissionError):
            self.skipTest("mkfifo unavailable")
        with self.assertRaisesRegex(ManifestError, "special payload entry"):
            PayloadManifest.build(self.payload)

    def test_safe_join_rejects_escape_and_world_writable_parent(self):
        with self.assertRaisesRegex(ValueError, "escapes"):
            safe_join(self.payload, "../outside")
        unsafe = self.root / "unsafe"
        unsafe.mkdir(mode=0o777)
        unsafe.chmod(0o777)
        with self.assertRaisesRegex(PermissionError, "user-writable parent"):
            safe_join(unsafe, "Library/PrivilegedHelperTools/com.hyu.vpn.helper", require_safe_parents=True)


class StageAndCliTests(InstallerTestCase):
    def test_stage_contains_only_packaged_task8_runtime_no_homebrew_discovery(self):
        env = self.env()
        recorder = CommandRecorder(self.root / "commands.jsonl")
        stage = stage_user_payload(env, recorder=recorder)
        self.assertFalse((stage / "config/launchd/com.hyu.vpn.menubar.plist.in").exists())
        self.assertTrue((env.root / ".hyu-vpn-dry-run-root").exists())
        for rel in [
            "runtime/bin/openconnect",
            "runtime/bin/oathtool",
            "runtime/gp-hip-report",
            "runtime/vpnc/hyu-vpnc-wrapper",
            "bin/hyu-vpn-macos-service",
            "HYU VPN.app/Contents/MacOS/HYUVPNMenuApp",
            "HYU VPN.app/Contents/MacOS/HYUVPNCredentialReader",
            "manifest.json",
        ]:
            self.assertTrue((stage / rel).exists(), rel)
        text = (REPO / "installer/manifest.py").read_text(encoding="utf-8")
        for forbidden in ["/opt/homebrew", "/usr/local", "resolve_homebrew", "InstallerTransaction", "RootAdminTransaction", "--dry-run-root", "install_name_tool", "codesign"]:
            self.assertNotIn(forbidden, text)
        recorded = recorder.commands()
        self.assertEqual(recorded[0][:3], ["/usr/bin/python3", "installer/manifest.py", "--verify-manifest"])
        self.assertFalse(any("/usr/bin/sudo" in cell for row in recorded[:-1] for cell in row))

    def test_cli_stage_is_exact_unique_stage_dir_and_package_audit_checks_runtime_artifacts(self):
        base = self.root / "cli"
        stage1 = base / "stage-one"
        stage2 = base / "stage-two"
        for stage in [stage1, stage2]:
            proc = subprocess.run([sys.executable, str(REPO / "installer/manifest.py"), "--payload", str(self.payload), "--manifest", str(self.manifest_path), "--stage-user-payload", "--stage-dir", str(stage)], text=True, capture_output=True)
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            self.assertTrue((stage / "manifest.json").exists())
        self.assertEqual(sorted(p.name for p in base.iterdir()), ["stage-one", "stage-two"])
        self.assertFalse((base / ".hyu-vpn-dry-run-root").exists())
        audit = subprocess.run([sys.executable, str(REPO / "installer/manifest.py"), "--payload", str(self.payload), "--manifest", str(self.manifest_path), "--package-audit"], text=True, capture_output=True)
        self.assertEqual(audit.returncode, 0, audit.stderr)

    def test_cli_requires_external_stage_dir_and_has_no_final_runtime_manifest_dependency(self):
        proc = subprocess.run([sys.executable, str(REPO / "installer/manifest.py"), "--payload", str(self.payload), "--manifest", str(self.manifest_path), "--stage-user-payload"], text=True, capture_output=True)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("--stage-dir is required", proc.stderr)
        (self.payload / "config/final-runtime-manifest.json").unlink()
        self.manifest_path = PayloadManifest.write_for_tree(self.payload, self.payload / "manifest.json")
        stage = self.root / "no-final-stage"
        staged = subprocess.run([sys.executable, str(REPO / "installer/manifest.py"), "--payload", str(self.payload), "--manifest", str(self.manifest_path), "--stage-user-payload", "--stage-dir", str(stage)], text=True, capture_output=True)
        self.assertEqual(staged.returncode, 0, staged.stderr + staged.stdout)
        audit = subprocess.run([sys.executable, str(REPO / "installer/manifest.py"), "--payload", str(self.payload), "--manifest", str(self.manifest_path), "--package-audit"], text=True, capture_output=True)
        self.assertEqual(audit.returncode, 0, audit.stderr)


class RootAdminShellHarnessTests(InstallerTestCase):
    def run_root_admin(self, env, stage, action="install", extra_env=None, recover=False, tools_root=None):
        args = [
            "/bin/zsh", str(REPO / "installer/root-admin.sh"),
            "--dry-run-root", str(env.root),
            "--stage", str(stage),
            "--stage-manifest-sha256", hashlib.sha256((stage / "manifest.json").read_bytes()).hexdigest(),
            "--package-manifest-sha256", hashlib.sha256((env.payload / "manifest.json").read_bytes()).hexdigest(),
            "--payload", str(env.payload),
            "--manifest", str(env.manifest),
            "--admin-user", env.user,
            "--admin-uid", "501",
            "--administrator-phase", action,
        ]
        if tools_root is not None:
            args.extend(["--tools-root", str(tools_root)])
        if recover:
            args.append("--recover")
        proc_env = os.environ.copy()
        proc_env.update(extra_env or {})
        return subprocess.run(args, cwd=str(REPO), env=proc_env, text=True, capture_output=True)

    def run_root_admin_raw(self, args, env=None):
        proc_env = os.environ.copy()
        if env is not None:
            proc_env.update(env)
        return subprocess.run(["/bin/zsh", str(REPO / "installer/root-admin.sh"), *args], cwd=str(REPO), env=proc_env, text=True, capture_output=True)

    def make_fake_tools_for(self, env, failing_tool=None, route_output="", dns_output=""):
        tools = env.root / "Users" / ".fake-tools"
        for tool in ["/usr/sbin/visudo", "/usr/sbin/chown", "/usr/bin/pgrep", "/usr/sbin/netstat", "/usr/sbin/scutil", "/usr/bin/env", "/usr/bin/sudo", "/bin/launchctl", "/bin/mv"]:
            path = tools / tool.lstrip("/")
            path.parent.mkdir(parents=True, exist_ok=True)
            name = path.name
            if failing_tool == name:
                body = f"#!/bin/sh\necho {name} failed >&2\nexit 42\n"
            elif name == "mv":
                body = "#!/bin/sh\n/bin/mv \"$@\"\n"
            elif name == "netstat" and route_output:
                body = f"#!/bin/sh\nprintf '%s\\n' {route_output!r}\n"
            elif name == "scutil" and dns_output:
                body = f"#!/bin/sh\nprintf '%s\\n' {dns_output!r}\n"
            elif name == "env":
                body = '#!/bin/sh\nexit 99\n'
            elif name == "sudo":
                body = '#!/bin/sh\nwhile [ "$#" -gt 0 ] && [ "$1" != "--" ]; do shift; done\n[ "$1" = "--" ] && shift\nexec "$@"\n'
            else:
                body = "#!/bin/sh\nexit 0\n"
            path.write_text(body, encoding="utf-8")
            path.chmod(0o755)
        return tools

    def make_fake_tools(self, failing_tool=None, route_output="", dns_output=""):
        return self.make_fake_tools_for(self.env(), failing_tool=failing_tool, route_output=route_output, dns_output=dns_output)

    def test_macos_manifest_rejects_legacy_backend_entries(self):
        self.maxDiff = None
        env = self.env()
        stage = stage_user_payload(env)
        proc = self.run_root_admin(env, stage)
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)

        stage_manifest = json.loads((stage / "manifest.json").read_text(encoding="utf-8"))
        stage_files = set(stage_manifest["files"])
        app_support = env.root / "Library/Application Support/HYU VPN"
        installed_legacy = [
            rel
            for rel in [
                "bin/hyu-vpn-service",
                "bin/hyu-vpn-control",
                "bin/hyu-vpn-connect",
                "src/hyu_vpn",
            ]
            if (app_support / rel).exists()
        ]
        rendered_service = plistlib.loads((env.root / "Users/tester/Library/LaunchAgents/com.hyu.vpn.service.plist").read_bytes())
        violations = {}
        stage_legacy = sorted(
            rel
            for rel in stage_files
            if rel in {"backend/hyu-vpn-service", "backend/hyu-vpn-control", "backend/hyu-vpn-connect"}
            or rel == "src/hyu_vpn"
            or rel.startswith("src/hyu_vpn/")
        )
        if stage_legacy:
            violations["stage_manifest_legacy_backend_entries"] = stage_legacy
        if installed_legacy:
            violations["installed_legacy_backend_entries"] = sorted(installed_legacy)
        if rendered_service["ProgramArguments"] != ["/Library/Application Support/HYU VPN/bin/hyu-vpn-macos-service"]:
            violations["rendered_service_program_arguments"] = rendered_service["ProgramArguments"]

        rust_service_stage_entries = [rel for rel in stage_files if Path(rel).name == "hyu-vpn-macos-service"]

        self.assertEqual(violations, {})
        self.assertTrue(rust_service_stage_entries)
        self.assertTrue((app_support / "bin/hyu-vpn-macos-service").exists())

    def test_root_admin_bootstraps_with_exact_admin_health_cli_then_commits_before_menu_boundary(self):
        env = self.env()
        stage = stage_user_payload(env)
        proc = self.run_root_admin(env, stage)
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        root = env.root
        app_support = root / "Library/Application Support/HYU VPN"
        self.assertTrue((app_support / "bin/hyu-vpn-macos-service").exists())
        commands = (root / "private/var/db/hyu-vpn/command-log.jsonl").read_text()
        journal = (root / "private/var/db/hyu-vpn/install-transaction.log").read_text()
        expected_health = (
            "/usr/bin/sudo -H -u tester -- "
            f"{app_support}/bin/hyu-vpn-macos-service health --uid 501 --home /Users/tester --timeout-ms 2500"
        )
        self.assertIn("launchctl bootstrap gui/501", commands)
        self.assertIn("launchctl kickstart -k gui/501/com.hyu.vpn.service", commands)
        self.assertIn(expected_health, commands)
        self.assertNotIn("hyu-vpn-macos-service status", commands)
        self.assertLess(commands.index("launchctl bootstrap"), commands.index(expected_health))
        self.assertLess(commands.index(expected_health), journal.index("install-commit"))
        self.assertEqual((root / "private/var/db/hyu-vpn/transaction-state").read_text().strip(), "complete")
        self.assertNotIn("hyu-vpn-native-client", commands)
        self.assertNotIn("install_name_tool", commands)
        self.assertNotIn("codesign", commands)

    def test_root_admin_real_health_cli_failure_rolls_back_and_recover_is_idempotent(self):
        env = DryRunEnvironment(root=self.root / "dry real health rollback", payload=self.payload, home=self.root / "home real health rollback", manifest=self.manifest_path)
        old_service = env.root / "Library/Application Support/HYU VPN/bin/hyu-vpn-macos-service"
        old_service.parent.mkdir(parents=True, exist_ok=True)
        old_service.write_text("old-service", encoding="utf-8")
        old_service.chmod(0o755)
        stage = stage_user_payload(env)
        tools = self.make_fake_tools_for(env)
        sudo = tools / "usr/bin/sudo"
        sudo.parent.mkdir(parents=True, exist_ok=True)
        sudo.write_text("#!/bin/sh\necho health failed >&2\nexit 70\n", encoding="utf-8")
        sudo.chmod(0o755)
        proc = self.run_root_admin(env, stage, tools_root=tools)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("health failed", proc.stderr)
        self.assertEqual(old_service.read_text(encoding="utf-8"), "old-service")
        journal = (env.root / "private/var/db/hyu-vpn/install-transaction.log").read_text(encoding="utf-8")
        self.assertIn("rollback-complete", journal)
        recover = self.run_root_admin(env, stage, recover=True, tools_root=tools)
        self.assertEqual(recover.returncode, 0, recover.stderr + recover.stdout)

    def test_root_admin_health_failure_boots_out_new_service_before_rollback_completes(self):
        env = DryRunEnvironment(root=self.root / "dry health bootout rollback", payload=self.payload, home=self.root / "home health bootout rollback", manifest=self.manifest_path)
        stage = stage_user_payload(env)
        tools = self.make_fake_tools_for(env)
        sudo = tools / "usr/bin/sudo"
        sudo.write_text("#!/bin/sh\necho health failed >&2\nexit 70\n", encoding="utf-8")
        sudo.chmod(0o755)
        proc = self.run_root_admin(env, stage, tools_root=tools)
        self.assertNotEqual(proc.returncode, 0)
        commands = (env.root / "private/var/db/hyu-vpn/command-log.jsonl").read_text(encoding="utf-8")
        journal = (env.root / "private/var/db/hyu-vpn/install-transaction.log").read_text(encoding="utf-8")
        service_bootout = "launchctl bootout gui/501/com.hyu.vpn.service"
        self.assertGreaterEqual(commands.count(service_bootout), 2, commands)
        self.assertLess(commands.index("launchctl kickstart -k gui/501/com.hyu.vpn.service"), commands.rindex(service_bootout))
        self.assertLess(journal.index("rollback-start"), journal.index("rollback-complete"))
        self.assertEqual((env.root / "private/var/db/hyu-vpn/transaction-state").read_text().strip(), "complete")

    def test_root_admin_bootout_failure_during_rollback_surfaces_incomplete_repair(self):
        env = DryRunEnvironment(root=self.root / "dry health bootout rollback failure", payload=self.payload, home=self.root / "home health bootout rollback failure", manifest=self.manifest_path)
        stage = stage_user_payload(env)
        tools = self.make_fake_tools_for(env)
        sudo = tools / "usr/bin/sudo"
        sudo.write_text("#!/bin/sh\necho health failed >&2\nexit 70\n", encoding="utf-8")
        sudo.chmod(0o755)
        launchctl = tools / "bin/launchctl"
        launchctl.write_text(
            '#!/bin/sh\n'
            'state="$0.bootstrapped"\n'
            'if [ "$1" = kickstart ]; then : > "$state"; exit 0; fi\n'
            'if [ "$1" = bootout ] && [ -f "$state" ] && [ "$2" = gui/501/com.hyu.vpn.service ]; then echo bootout failed >&2; exit 55; fi\n'
            'exit 0\n',
            encoding="utf-8",
        )
        launchctl.chmod(0o755)
        proc = self.run_root_admin(env, stage, tools_root=tools)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("bootout failed", proc.stderr)
        state = env.root / "private/var/db/hyu-vpn"
        self.assertNotIn("rollback-complete", (state / "install-transaction.log").read_text(encoding="utf-8"))
        self.assertNotEqual((state / "transaction-state").read_text().strip(), "complete")

    def test_root_admin_health_failure_rolls_back_previous_binary_plist_helper_sudoers_app_state(self):
        env = DryRunEnvironment(root=self.root / "dry health rollback", payload=self.payload, home=self.root / "home health rollback", manifest=self.manifest_path)
        old_paths = {
            "service": env.root / "Library/Application Support/HYU VPN/bin/hyu-vpn-macos-service",
            "plist": env.root / "Users/tester/Library/LaunchAgents/com.hyu.vpn.service.plist",
            "helper": env.root / "Library/PrivilegedHelperTools/com.hyu.vpn.helper",
            "sudoers": env.root / "etc/sudoers.d/hyu-vpn",
            "app": env.root / "Applications/HYU VPN.app/Contents/MacOS/HYUVPNMenuApp",
            "state": env.root / "private/var/db/hyu-vpn/installed-paths.tsv",
        }
        for name, path in old_paths.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"old-{name}", encoding="utf-8")
            if name in {"service", "helper", "app"}:
                path.chmod(0o755)
        stage = stage_user_payload(env)
        proc = self.run_root_admin(env, stage, extra_env={"HYU_VPN_FAIL_AFTER": "health"})
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("injected failure after health", proc.stderr)
        for name, path in old_paths.items():
            self.assertTrue(path.exists(), name)
            self.assertEqual(path.read_text(encoding="utf-8"), f"old-{name}")
        state = env.root / "private/var/db/hyu-vpn"
        self.assertEqual((state / "transaction-state").read_text().strip(), "complete")
        self.assertIn("rollback-complete", (state / "install-transaction.log").read_text(encoding="utf-8"))
        self.assertFalse((state / "backups.tsv").exists())

    def test_root_admin_rejects_user_stage_tamper_and_rolls_back_exact_paths(self):
        env = self.env()
        stage = stage_user_payload(env)
        (stage / "runtime/bin/openconnect").write_text("tampered", encoding="utf-8")
        proc = self.run_root_admin(env, stage)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("hash mismatch: runtime/bin/openconnect", proc.stderr)
        self.assertFalse((env.root / "Library/Application Support/HYU VPN/runtime/current/bin/openconnect").exists())
        env2 = DryRunEnvironment(root=self.root / "dry rollback", payload=self.payload, home=self.root / "home rollback", manifest=self.manifest_path)
        stage2 = stage_user_payload(env2)
        proc = self.run_root_admin(env2, stage2, extra_env={"HYU_VPN_FAIL_AFTER": "sudoers"})
        self.assertNotEqual(proc.returncode, 0)
        self.assertFalse((env2.root / "etc/sudoers.d/hyu-vpn").exists())
        self.assertIn("rollback-complete", (env2.root / "private/var/db/hyu-vpn/install-transaction.log").read_text())

    def test_root_admin_accepts_valid_stage_manifest_with_swift_json_spacing(self):
        env = self.env()
        stage = stage_user_payload(env)
        manifest = json.loads((stage / "manifest.json").read_text(encoding="utf-8"))
        swift_json = (json.dumps(manifest, indent=2, separators=(",", " : ")) + "\n").replace("/", r"\/")
        (stage / "manifest.json").write_text(swift_json, encoding="utf-8")

        proc = self.run_root_admin(env, stage)

        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        self.assertEqual((env.root / "private/var/db/hyu-vpn/transaction-state").read_text().strip(), "complete")

    def test_successful_upgrade_rollback_is_idempotent_under_explicit_recovery(self):
        env = DryRunEnvironment(root=self.root / "dry idempotent rollback", payload=self.payload, home=self.root / "home idempotent rollback", manifest=self.manifest_path)
        old_app = env.root / "Applications/HYU VPN.app/Contents/MacOS/HYUVPNMenuApp"
        old_helper = env.root / "Library/PrivilegedHelperTools/com.hyu.vpn.helper"
        old_service = env.root / "Library/Application Support/HYU VPN/bin/hyu-vpn-macos-service"
        old_state = env.root / "private/var/db/hyu-vpn/installed-paths.tsv"
        old_app.parent.mkdir(parents=True, exist_ok=True)
        old_helper.parent.mkdir(parents=True, exist_ok=True)
        old_service.parent.mkdir(parents=True, exist_ok=True)
        old_state.parent.mkdir(parents=True, exist_ok=True)
        old_app.write_text("old app", encoding="utf-8")
        old_helper.write_text("old helper", encoding="utf-8")
        old_service.write_text("old service", encoding="utf-8")
        old_state.write_text("old installed metadata", encoding="utf-8")

        stage = stage_user_payload(env)
        proc = self.run_root_admin(env, stage, extra_env={"HYU_VPN_FAIL_AFTER": "app"})
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(old_app.read_text(encoding="utf-8"), "old app")
        self.assertEqual(old_helper.read_text(encoding="utf-8"), "old helper")
        self.assertEqual(old_service.read_text(encoding="utf-8"), "old service")

        recovered = self.run_root_admin(env, stage, recover=True)

        self.assertEqual(recovered.returncode, 0, recovered.stderr + recovered.stdout)
        self.assertEqual(old_app.read_text(encoding="utf-8"), "old app")
        self.assertEqual(old_helper.read_text(encoding="utf-8"), "old helper")
        self.assertEqual(old_service.read_text(encoding="utf-8"), "old service")
        state = env.root / "private/var/db/hyu-vpn"
        self.assertTrue((state / "transaction-state").exists())
        self.assertEqual((state / "transaction-state").read_text(encoding="utf-8").strip(), "complete")
        self.assertFalse((state / "backups.tsv").exists())
        self.assertFalse((state / "backups").exists())

    def test_root_admin_migrates_legacy_dotted_sudoers_fragment(self):
        env = DryRunEnvironment(root=self.root / "dry sudoers migration", payload=self.payload, home=self.root / "home sudoers migration", manifest=self.manifest_path)
        stage = stage_user_payload(env)
        tools = self.make_fake_tools_for(env)
        launchctl = tools / "bin/launchctl"
        legacy = env.root / "etc/sudoers.d/com.hyu.vpn"
        launchctl.write_text(
            "#!/bin/sh\n"
            'case " $* " in *" local.hyu-openconnect "*) ;; *) exit 0 ;; esac\n'
            f"mkdir -p {str(legacy.parent)!r}\n"
            f"printf '%s\\n' legacy-rule > {str(legacy)!r}\n"
            "exit 0\n",
            encoding="utf-8",
        )
        launchctl.chmod(0o755)

        proc = self.run_root_admin(env, stage, tools_root=tools)

        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        self.assertTrue((env.root / "etc/sudoers.d/hyu-vpn").exists())
        self.assertFalse(legacy.exists())
        installed_paths = (env.root / "private/var/db/hyu-vpn/installed-paths.tsv").read_text(encoding="utf-8")
        self.assertIn("etc/sudoers.d/hyu-vpn", installed_paths)
        self.assertNotIn("etc/sudoers.d/com.hyu.vpn", installed_paths)


    def test_root_admin_stops_current_service_before_legacy_quarantine_and_keeps_service_owner(self):
        env = DryRunEnvironment(root=self.root / "dry menu migration", payload=self.payload, home=self.root / "home menu migration", manifest=self.manifest_path)
        stage = stage_user_payload(env)
        legacy = env.root / "Users/tester/Library/LaunchAgents/com.hyu.vpn.menubar.plist"
        service = env.root / "Users/tester/Library/LaunchAgents/com.hyu.vpn.service.plist"
        legacy.parent.mkdir(parents=True, exist_ok=True)
        legacy.write_text("legacy-menu", encoding="utf-8")
        service.write_text("keep-service", encoding="utf-8")

        proc = self.run_root_admin(env, stage)

        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        self.assertFalse(legacy.exists())
        self.assertTrue(service.exists())
        service_plist = plistlib.loads(service.read_bytes())
        self.assertEqual(service_plist["Label"], "com.hyu.vpn.service")
        self.assertEqual(service_plist["ProgramArguments"], ["/Library/Application Support/HYU VPN/bin/hyu-vpn-macos-service"])
        commands = (env.root / "private/var/db/hyu-vpn/command-log.jsonl").read_text(encoding="utf-8")
        service_bootout = "launchctl bootout gui/501/com.hyu.vpn.service"
        legacy_probe = "launchctl print gui/501/local.hyu-openconnect"
        self.assertIn(service_bootout, commands)
        self.assertLess(commands.index(service_bootout), commands.index(legacy_probe))
        self.assertIn("launchctl bootout gui/501/com.hyu.vpn.menubar", commands)
        self.assertNotIn("gui/501/com.hyu.vpn.service.plist", commands)
        installed_paths = (env.root / "private/var/db/hyu-vpn/installed-paths.tsv").read_text(encoding="utf-8")
        self.assertNotIn("com.hyu.vpn.menubar.plist", installed_paths)
        self.assertIn("Users/tester/Library/LaunchAgents/com.hyu.vpn.service.plist", installed_paths)

    def _inject_stale_old_helper_during_quarantine(self, env, tools):
        helper = env.root / "Library/PrivilegedHelperTools/com.hyu.vpn.helper"
        state_dir = env.root / "private/var/db/hyu-vpn"
        state = state_dir / "fake-helper-state"
        session = state_dir / "session.json"
        ledger = state_dir / "ledger/oldsession1.ledger"
        launchctl = tools / "bin/launchctl"
        launchctl.write_text(
            "#!/bin/sh\n"
            f"mkdir -p {str(helper.parent)!r} {str(state.parent)!r} {str(ledger.parent)!r}\n"
            f"if [ ! -e {str(helper)!r} ]; then\n"
            f"  cat > {str(helper)!r} <<'OLD_HELPER'\n"
            "#!/bin/sh\n"
            f"state={str(state)!r}\n"
            "case \"${1:-}\" in\n"
            '  status) printf \'%s\\n\' \'{"schema_version":1,"state":"repair-required","pid":null,"session_nonce":"oldsession1","tunnel_interface":null}\' ;;\n'
            "  repair) exit 42 ;;\n"
            "  stop) exit 42 ;;\n"
            "  *) exit 64 ;;\n"
            "esac\n"
            "OLD_HELPER\n"
            f"  chmod 755 {str(helper)!r}\n"
            f"  printf repair-required > {str(state)!r}\n"
            f"  printf stale-session > {str(session)!r}\n"
            f"  printf stale-ledger > {str(ledger)!r}\n"
            f"  chmod 600 {str(session)!r} {str(ledger)!r}\n"
            "fi\n"
            "exit 0\n",
            encoding="utf-8",
        )
        launchctl.chmod(0o755)
        return helper, state

    def test_upgrade_defers_old_repair_bug_then_new_helper_repairs_and_verifies_stopped(self):
        env = DryRunEnvironment(root=self.root / "dry helper repair upgrade", payload=self.payload, home=self.root / "home helper repair upgrade", manifest=self.manifest_path)
        stage = stage_user_payload(env)
        tools = self.make_fake_tools_for(env)
        _, state = self._inject_stale_old_helper_during_quarantine(env, tools)

        proc = self.run_root_admin(env, stage, tools_root=tools)

        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        self.assertEqual(state.read_text(encoding="utf-8"), "stopped")
        self.assertFalse((env.root / "private/var/db/hyu-vpn/session.json").exists())
        self.assertFalse((env.root / "private/var/db/hyu-vpn/ledger/oldsession1.ledger").exists())
        journal = (env.root / "private/var/db/hyu-vpn/install-transaction.log").read_text(encoding="utf-8")
        self.assertLess(journal.index("old-helper-repair-deferred"), journal.index("before-mutate Library/PrivilegedHelperTools/com.hyu.vpn.helper"))
        self.assertLess(journal.index("legacy-quarantined-never-restore"), journal.index("inactive-repair-state-cleared"))
        self.assertLess(journal.index("inactive-repair-state-cleared"), journal.index("before-mutate Library/PrivilegedHelperTools/com.hyu.vpn.helper"))
        self.assertLess(journal.index("before-mutate Library/PrivilegedHelperTools/com.hyu.vpn.helper"), journal.index("installed-helper-stopped"))

    def test_upgrade_rolls_back_if_new_helper_cannot_clear_deferred_repair(self):
        env = DryRunEnvironment(root=self.root / "dry helper repair rollback", payload=self.payload, home=self.root / "home helper repair rollback", manifest=self.manifest_path)
        stage = stage_user_payload(env)
        tools = self.make_fake_tools_for(env)
        old_helper, _ = self._inject_stale_old_helper_during_quarantine(env, tools)

        proc = self.run_root_admin(env, stage, tools_root=tools, extra_env={"HYU_FAKE_NEW_HELPER_REPAIR_FAIL": "1"})

        self.assertNotEqual(proc.returncode, 0)
        self.assertTrue(old_helper.exists())
        self.assertIn("repair) exit 42", old_helper.read_text(encoding="utf-8"))
        journal = (env.root / "private/var/db/hyu-vpn/install-transaction.log").read_text(encoding="utf-8")
        self.assertIn("rollback-complete", journal)

    def test_upgrade_accepts_nonzero_stop_that_transitions_to_repair_required(self):
        env = DryRunEnvironment(root=self.root / "dry stop repair upgrade", payload=self.payload, home=self.root / "home stop repair upgrade", manifest=self.manifest_path)
        stage = stage_user_payload(env)
        tools = self.make_fake_tools_for(env)
        helper = env.root / "Library/PrivilegedHelperTools/com.hyu.vpn.helper"
        state = env.root / "private/var/db/hyu-vpn/fake-helper-state"
        ledger = env.root / "private/var/db/hyu-vpn/ledger"
        helper.parent.mkdir(parents=True, exist_ok=True)
        state.parent.mkdir(parents=True, exist_ok=True)
        ledger.mkdir(parents=True, exist_ok=True)
        ledger.chmod(0o700)
        state.write_text("running", encoding="utf-8")
        helper.write_text(
            "#!/bin/sh\n"
            f"state={str(state)!r}\n"
            "case \"${1:-}\" in\n"
            "  status)\n"
            "    current=$(cat \"$state\")\n"
            "    if [ \"$current\" = running ]; then printf '%s\\n' '{\"schema_version\":1,\"state\":\"running\",\"pid\":123,\"session_nonce\":\"stopfail1\",\"tunnel_interface\":\"utun7\"}'; else printf '%s\\n' '{\"schema_version\":1,\"state\":\"repair-required\",\"pid\":null,\"session_nonce\":\"stopfail1\",\"tunnel_interface\":null}'; fi ;;\n"
            "  stop) printf repair-required > \"$state\"; exit 42 ;;\n"
            "  repair) exit 42 ;;\n"
            "  *) exit 64 ;;\n"
            "esac\n",
            encoding="utf-8",
        )
        helper.chmod(0o755)

        proc = self.run_root_admin(env, stage, tools_root=tools)

        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        journal = (env.root / "private/var/db/hyu-vpn/install-transaction.log").read_text(encoding="utf-8")
        self.assertIn("old-helper-stop-repair-deferred", journal)
        self.assertIn("inactive-repair-state-cleared", journal)

    def test_failed_upgrade_restarts_service_after_rollback(self):
        env = DryRunEnvironment(root=self.root / "dry rollback restart", payload=self.payload, home=self.root / "home rollback restart", manifest=self.manifest_path)
        stage = stage_user_payload(env)
        service = env.root / "Users/tester/Library/LaunchAgents/com.hyu.vpn.service.plist"
        service.parent.mkdir(parents=True, exist_ok=True)
        service.write_text("old-service-plist", encoding="utf-8")

        proc = self.run_root_admin(env, stage, extra_env={"HYU_VPN_FAIL_AFTER": "helper"})

        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(service.read_text(encoding="utf-8"), "old-service-plist")
        commands = (env.root / "private/var/db/hyu-vpn/command-log.jsonl").read_text(encoding="utf-8")
        self.assertIn("launchctl bootstrap gui/501", commands)
        self.assertIn("launchctl kickstart -k gui/501/com.hyu.vpn.service", commands)
        journal = (env.root / "private/var/db/hyu-vpn/install-transaction.log").read_text(encoding="utf-8")
        self.assertIn("rollback-existing-service-restarted", journal)

    def test_tampered_stage_service_cannot_execute_root_util_before_rejection(self):
        env = self.env()
        stage = stage_user_payload(env)
        marker = self.root / "stage-root-util-executed"
        (stage / "bin/hyu-vpn-macos-service").write_text(
            f"#!/bin/sh\nif [ \"${{1:-}}\" = root-util ] && [ \"${{2:-}}\" = fsync ]; then printf owned > {str(marker)!r}; exit 0; fi\nexit 70\n",
            encoding="utf-8",
        )
        (stage / "bin/hyu-vpn-macos-service").chmod(0o755)

        proc = self.run_root_admin(env, stage)

        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("hash mismatch", proc.stderr + proc.stdout)
        self.assertFalse(marker.exists(), "root executed mutable user-stage service before trust verification")

    def test_regenerated_stage_manifest_is_rejected_by_locked_package_payload(self):
        env = self.env()
        stage = stage_user_payload(env)
        (stage / "bin/hyu-vpn-macos-service").write_text("#!/bin/sh\nif [ \"${1:-}\" = root-util ] && [ \"${2:-}\" = fsync ]; then exit 0; fi\nprintf preverified-replacement-service\n", encoding="utf-8")
        _write_stage_manifest(stage)
        args = [
            "--dry-run-root", str(env.root),
            "--stage", str(stage),
            "--stage-manifest-sha256", hashlib.sha256((stage / "manifest.json").read_bytes()).hexdigest(),
            "--package-manifest-sha256", hashlib.sha256((env.payload / "manifest.json").read_bytes()).hexdigest(),
            "--payload", str(env.payload),
            "--manifest", str(env.manifest),
            "--admin-user", env.user,
            "--admin-uid", "501",
            "--administrator-phase", "install",
        ]
        proc = self.run_root_admin_raw(args)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("hash mismatch", proc.stderr + proc.stdout)
        installed = env.root / "Library/Application Support/HYU VPN/bin/hyu-vpn-macos-service"
        self.assertFalse(installed.exists())

    def test_payload_concurrent_change_after_user_stage_is_rejected_by_package_manifest(self):
        env = self.env()
        stage = stage_user_payload(env)
        (env.payload / "hyu-vpn-macos-service").write_text("#!/bin/sh\nif [ \"${1:-}\" = root-util ] && [ \"${2:-}\" = fsync ]; then exit 0; fi\nprintf changed-after-stage\n", encoding="utf-8")
        proc = self.run_root_admin(env, stage)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("hash mismatch", proc.stderr + proc.stdout)



    def test_root_package_manifest_arg_must_be_exact_top_manifest(self):
        env = self.env()
        stage = stage_user_payload(env)
        copied_manifest = env.payload / "copied-manifest.json"
        copied_manifest.write_bytes((env.payload / "manifest.json").read_bytes())
        args = [
            "--dry-run-root", str(env.root),
            "--stage", str(stage),
            "--stage-manifest-sha256", hashlib.sha256((stage / "manifest.json").read_bytes()).hexdigest(),
            "--package-manifest-sha256", hashlib.sha256((env.payload / "manifest.json").read_bytes()).hexdigest(),
            "--payload", str(env.payload),
            "--manifest", str(copied_manifest),
            "--admin-user", env.user,
            "--admin-uid", "501",
            "--administrator-phase", "install",
        ]
        proc = self.run_root_admin_raw(args)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("manifest must be package top manifest", proc.stderr)

    def test_root_rejects_symlinked_preverified_stage_before_mutation(self):
        env = self.env()
        stage = stage_user_payload(env)
        target = stage / "bin/hyu-vpn-macos-service"
        target.unlink()
        target.symlink_to("/tmp/evil-service")
        proc = self.run_root_admin(env, stage)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("symlink in staged payload", proc.stderr)



    def test_stage_manifest_digest_binds_pre_sudo_stage_against_tamper_and_regenerate(self):
        env = self.env()
        stage = stage_user_payload(env)
        expected = hashlib.sha256((stage / "manifest.json").read_bytes()).hexdigest()
        (stage / "bin/hyu-vpn-macos-service").write_text("evil", encoding="utf-8")
        _write_stage_manifest(stage)
        args = [
            "--dry-run-root", str(env.root),
            "--stage", str(stage),
            "--stage-manifest-sha256", expected,
            "--package-manifest-sha256", hashlib.sha256((env.payload / "manifest.json").read_bytes()).hexdigest(),
            "--payload", str(env.payload),
            "--manifest", str(env.manifest),
            "--admin-user", env.user,
            "--admin-uid", "501",
            "--administrator-phase", "install",
        ]
        proc = self.run_root_admin_raw(args)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("staged manifest digest mismatch", proc.stderr)
        self.assertFalse((env.root / "Library/Application Support/HYU VPN/bin/hyu-vpn-macos-service").exists())

    def test_dry_root_must_be_fresh_marked_temp_and_tools_root_confined(self):
        args = ["--dry-run-root", "/", "--stage", str(self.payload), "--package-manifest-sha256", hashlib.sha256((self.payload / "manifest.json").read_bytes()).hexdigest(), "--payload", str(self.payload), "--manifest", str(self.manifest_path), "--admin-user", "tester", "--admin-uid", "501", "--administrator-phase", "install"]
        proc = self.run_root_admin_raw(args)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("fresh temporary dry-run root", proc.stderr)
        unmarked = self.root / "unmarked-dry-root"
        unmarked.mkdir()
        args[1] = str(unmarked)
        proc = self.run_root_admin_raw(args)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("dry-run marker", proc.stderr)
        env = self.env()
        stage = stage_user_payload(env)
        (env.root / "preexisting").mkdir()
        proc = self.run_root_admin(env, stage)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("fresh empty dry-run root", proc.stderr)
        shutil.rmtree(env.root / "preexisting")
        escaped = self.root / "escaped-tools"
        escaped.mkdir()
        clean_env = self.env()
        proc = self.run_root_admin(clean_env, stage_user_payload(clean_env), tools_root=escaped)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("tools root must be inside dry-run root", proc.stderr)

    def test_live_mode_fails_closed_on_duplicate_options_nonce_and_test_switches(self):
        base = ["--payload", str(self.payload), "--manifest", str(self.manifest_path), "--administrator-phase", "install", "--live-install", f"hyu-install-mutation-{int(time.time())}"]
        dup = self.run_root_admin_raw(base + ["--payload", str(self.payload)], env={})
        self.assertNotEqual(dup.returncode, 0)
        self.assertIn("duplicate option", dup.stderr)
        live_test = self.run_root_admin_raw(base + ["--dry-run-root", str(self.root / "dry")], env={})
        self.assertNotEqual(live_test.returncode, 0)
        self.assertIn("live root phase rejects test-only option", live_test.stderr)
        stripped = self.run_root_admin_raw(base, env={})
        self.assertNotEqual(stripped.returncode, 0)
        self.assertIn("invalid sudo identity", stripped.stderr)
        stale = self.run_root_admin_raw(["--payload", str(self.payload), "--manifest", str(self.manifest_path), "--administrator-phase", "install", "--live-install", "hyu-install-mutation-1"], env={})
        self.assertNotEqual(stale.returncode, 0)
        self.assertIn("fresh live mutation nonce", stale.stderr)
        root_admin = (REPO / "installer/root-admin.sh").read_text(encoding="utf-8")
        self.assertNotIn("HYU_VPN_INSTALL_NONCE", root_admin)
        self.assertNotIn("install-nonce", root_admin)

    def test_fake_tool_failures_and_legacy_residue_block_install_but_plain_utun_does_not(self):
        env = DryRunEnvironment(root=self.root / "dry chown", payload=self.payload, home=self.root / "home chown", manifest=self.manifest_path)
        stage = stage_user_payload(env)
        proc = self.run_root_admin(env, stage, tools_root=self.make_fake_tools_for(env, "chown"))
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("chown failed", proc.stderr)
        env2 = DryRunEnvironment(root=self.root / "dry utun", payload=self.payload, home=self.root / "home utun", manifest=self.manifest_path)
        stage2 = stage_user_payload(env2)
        proc = self.run_root_admin(env2, stage2, tools_root=self.make_fake_tools_for(env2, route_output="default 1.2.3.4 UGSc utun7"))
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        env3 = DryRunEnvironment(root=self.root / "dry legacy", payload=self.payload, home=self.root / "home legacy", manifest=self.manifest_path)
        stage3 = stage_user_payload(env3)
        proc = self.run_root_admin(env3, stage3, tools_root=self.make_fake_tools_for(env3, route_output="166.104.0.0/16 link#42 UCS utun7"))
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("legacy tunnel route remains", proc.stderr)

    def test_root_admin_allows_hyu_gateway_host_route_on_physical_interface(self):
        env = DryRunEnvironment(root=self.root / "dry physical hanyang route", payload=self.payload, home=self.root / "home physical hanyang route", manifest=self.manifest_path)
        stage = stage_user_payload(env)
        route_output = """Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            172.16.65.254      UGScg                 en0
166.104.0.17       172.16.65.254      UGHS                  en0
"""
        proc = self.run_root_admin(env, stage, tools_root=self.make_fake_tools_for(env, route_output=route_output))
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)

    def test_root_admin_allows_hanyang_resolver_bound_to_physical_interface(self):
        env = DryRunEnvironment(root=self.root / "dry physical hanyang dns", payload=self.payload, home=self.root / "home physical hanyang dns", manifest=self.manifest_path)
        stage = stage_user_payload(env)
        dns_output = """DNS configuration

resolver #1
  search domain[0] : hanyang.ac.kr
  nameserver[0] : 166.104.1.1
  if_index : 12 (en0)
"""
        proc = self.run_root_admin(env, stage, tools_root=self.make_fake_tools_for(env, dns_output=dns_output))
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)

    def test_root_admin_blocks_hanyang_resolver_bound_to_tunnel_interface(self):
        env = DryRunEnvironment(root=self.root / "dry tunnel dns", payload=self.payload, home=self.root / "home tunnel dns", manifest=self.manifest_path)
        stage = stage_user_payload(env)
        dns_output = """DNS configuration

resolver #1
  search domain[0] : hanyang.ac.kr
  nameserver[0] : 166.104.1.1
  if_index : 23 (utun7)
"""
        proc = self.run_root_admin(env, stage, tools_root=self.make_fake_tools_for(env, dns_output=dns_output))
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("legacy VPN resolver remains", proc.stderr)

    def test_sudoers_candidate_is_outside_includedir_and_removed_when_validation_fails(self):
        env = DryRunEnvironment(root=self.root / "dry visudo failure", payload=self.payload, home=self.root / "home visudo failure", manifest=self.manifest_path)
        stage = stage_user_payload(env)

        proc = self.run_root_admin(env, stage, tools_root=self.make_fake_tools_for(env, "visudo"))

        self.assertNotEqual(proc.returncode, 0)
        sudoers_dir = env.root / "etc/sudoers.d"
        self.assertEqual(list(sudoers_dir.iterdir()) if sudoers_dir.exists() else [], [])
        state = env.root / "private/var/db/hyu-vpn"
        self.assertEqual(list(state.glob("sudoers-candidate.*")), [])

    def test_sudoers_activation_is_recorded_before_move_that_applies_then_fails(self):
        env = DryRunEnvironment(root=self.root / "dry sudoers move failure", payload=self.payload, home=self.root / "home sudoers move failure", manifest=self.manifest_path)
        stage = stage_user_payload(env)
        tools = self.make_fake_tools_for(env)
        mv = tools / "bin/mv"
        mv.write_text('#!/bin/sh\n/bin/mv "$@"\nexit 42\n', encoding="utf-8")
        mv.chmod(0o755)

        proc = self.run_root_admin(env, stage, tools_root=tools)

        self.assertNotEqual(proc.returncode, 0)
        self.assertFalse((env.root / "etc/sudoers.d/hyu-vpn").exists())
        self.assertEqual(list((env.root / "private/var/db/hyu-vpn").glob("sudoers-candidate.*")), [])

    def test_root_uninstall_is_idempotent_and_allowlisted(self):
        env = self.env()
        stage = stage_user_payload(env)
        self.assertEqual(self.run_root_admin(env, stage).returncode, 0)
        unrelated = env.root / "etc/sudoers.d/other"
        unrelated.write_text("keep", encoding="utf-8")
        proc = self.run_root_admin(env, stage, action="uninstall")
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        proc2 = self.run_root_admin(env, stage, action="uninstall")
        self.assertEqual(proc2.returncode, 0, proc2.stderr + proc2.stdout)
        self.assertTrue(unrelated.exists())
        self.assertFalse((env.root / "Library/PrivilegedHelperTools/com.hyu.vpn.helper").exists())
        self.assertFalse((env.root / "Library/PrivilegedHelperTools/com.hyu.vpn.vpnc-wrapper").exists())


    def test_root_admin_rejects_privileged_destination_symlink_ancestors(self):
        targets = [
            ("Library/Application Support", "privileged destination contains symlink"),
            ("Library/PrivilegedHelperTools", "privileged destination contains symlink"),
            ("Applications", "privileged destination contains symlink"),
            ("Users/tester/Library/LaunchAgents", "privileged destination contains symlink"),
            ("etc/sudoers.d", "privileged destination contains symlink"),
            ("private/var/db/hyu-vpn", "privileged destination contains symlink"),
        ]
        for rel, message in targets:
            env = DryRunEnvironment(root=self.root / f"dry symlink {rel.replace('/', '_')}", payload=self.payload, home=self.root / f"home symlink {rel.replace('/', '_')}", manifest=self.manifest_path)
            stage = stage_user_payload(env)
            target = env.root / rel
            if target.exists() and target.is_dir():
                shutil.rmtree(target)
            elif target.exists():
                target.unlink()
            target.parent.mkdir(parents=True, exist_ok=True)
            target.symlink_to(self.root)
            proc = self.run_root_admin(env, stage)
            self.assertNotEqual(proc.returncode, 0, rel)
            self.assertIn(message, proc.stderr)

    def test_root_admin_rejects_group_or_world_writable_privileged_ancestors(self):
        for rel in ["Library/Application Support", "Library/PrivilegedHelperTools", "Applications", "Users/tester/Library/LaunchAgents", "etc/sudoers.d", "private/var/db/hyu-vpn"]:
            env = DryRunEnvironment(root=self.root / f"dry writable {rel.replace('/', '_')}", payload=self.payload, home=self.root / f"home writable {rel.replace('/', '_')}", manifest=self.manifest_path)
            stage = stage_user_payload(env)
            target = env.root / rel
            target.mkdir(parents=True, exist_ok=True)
            target.chmod(0o777)
            proc = self.run_root_admin(env, stage)
            self.assertNotEqual(proc.returncode, 0, rel)
            self.assertIn("privileged destination ancestor is writable", proc.stderr)

    def test_static_forbids_production_native_client_payload_and_python_install_hooks(self):
        production_files = [
            "installer/root-admin.sh",
            "packaging/README-lab.md",
            "launchd/com.hyu.vpn.service.plist.in",
        ]
        combined = "\n".join((REPO / rel).read_text(encoding="utf-8") for rel in production_files)
        for forbidden in ["hyu-vpn-native-client", "src/hyu_vpn", "suppress-auto-launch", "verify-suppressed", "restore-auto-launch", "native-suppression", "com.paloaltonetworks.gp", "/usr/bin/python3", "PYTHON3_PATH", "python3", "thon3", 'manifest.py" --payload', "manifest.py' --payload"]:
            self.assertNotIn(forbidden, combined)

    def test_live_style_privileged_chain_guard_checks_absolute_ancestors_from_root(self):
        sandbox = self.root / "live-style"
        safe = sandbox / "Library/Application Support/HYU VPN/bin/hyu-vpn-macos-service"
        safe.parent.mkdir(parents=True, exist_ok=True)
        safe.parent.chmod(0o755)
        env = {"HYU_VPN_CHAIN_GUARD_SELFTEST_PATH": str(safe)}
        ok = self.run_root_admin_raw(["--payload", str(self.payload), "--manifest", str(self.manifest_path), "--administrator-phase", "install", "--live-install", f"hyu-install-mutation-{int(time.time())}"], env=env)
        self.assertEqual(ok.returncode, 0, ok.stderr + ok.stdout)

        writable = sandbox / "Applications/HYU VPN.app"
        writable.parent.mkdir(parents=True, exist_ok=True)
        writable.parent.chmod(0o777)
        bad = self.run_root_admin_raw(["--payload", str(self.payload), "--manifest", str(self.manifest_path), "--administrator-phase", "install", "--live-install", f"hyu-install-mutation-{int(time.time())}"], env={"HYU_VPN_CHAIN_GUARD_SELFTEST_PATH": str(writable)})
        self.assertNotEqual(bad.returncode, 0)
        self.assertIn("privileged destination ancestor is writable", bad.stderr)

        writable.write_text("existing", encoding="utf-8")
        writable.chmod(0o755)
        existing_bad = self.run_root_admin_raw(["--payload", str(self.payload), "--manifest", str(self.manifest_path), "--administrator-phase", "install", "--live-install", f"hyu-install-mutation-{int(time.time())}"], env={"HYU_VPN_CHAIN_GUARD_SELFTEST_PATH": str(writable)})
        self.assertNotEqual(existing_bad.returncode, 0)
        self.assertIn("privileged destination ancestor is writable", existing_bad.stderr)

        link_parent = sandbox / "etc"
        if link_parent.exists() or link_parent.is_symlink():
            if link_parent.is_dir() and not link_parent.is_symlink():
                shutil.rmtree(link_parent)
            else:
                link_parent.unlink()
        link_parent.symlink_to(sandbox / "Library")
        symlinked = self.run_root_admin_raw(["--payload", str(self.payload), "--manifest", str(self.manifest_path), "--administrator-phase", "install", "--live-install", f"hyu-install-mutation-{int(time.time())}"], env={"HYU_VPN_CHAIN_GUARD_SELFTEST_PATH": str(link_parent / "sudoers.d/hyu-vpn")})
        self.assertNotEqual(symlinked.returncode, 0)
        self.assertIn("privileged destination contains symlink", symlinked.stderr)

    def test_live_chain_guard_allows_standard_macos_etc_alias(self):
        proc = self.run_root_admin_raw(
            [
                "--payload", str(self.payload),
                "--manifest", str(self.manifest_path),
                "--administrator-phase", "install",
                "--live-install", f"hyu-install-mutation-{int(time.time())}",
            ],
            env={"HYU_VPN_CHAIN_GUARD_SELFTEST_PATH": "/etc"},
        )
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)

    def test_live_chain_guard_allows_standard_macos_applications_anchor(self):
        proc = self.run_root_admin_raw(
            [
                "--payload", str(self.payload),
                "--manifest", str(self.manifest_path),
                "--administrator-phase", "install",
                "--live-install", f"hyu-install-mutation-{int(time.time())}",
            ],
            env={"HYU_VPN_CHAIN_GUARD_SELFTEST_PATH": "/Applications"},
        )
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)

    def test_root_admin_static_security_contracts(self):
        text = (REPO / "installer/root-admin.sh").read_text(encoding="utf-8")
        self.assertIn('SUDOERS_DST="$(map_path /etc/sudoers.d/hyu-vpn)"', text)
        self.assertIn('LEGACY_SUDOERS_DST="$(map_path /etc/sudoers.d/com.hyu.vpn)"', text)
        self.assertIn('SUDOERS_TMP="$STATE_DIR/sudoers-candidate.$$"', text)
        self.assertIn('/bin/rm -f "$SUDOERS_TMP"', text)
        self.assertIn('backup_target "$LEGACY_SUDOERS_DST"', text)
        self.assertIn("etc/sudoers.d/hyu-vpn|etc/sudoers.d/com.hyu.vpn", text)
        self.assertIn('capture_cmd(){', text)
        capture_line = next(line for line in text.splitlines() if line.startswith("capture_cmd(){"))
        self.assertIn('[[ -n "$DRY_RUN_ROOT" && -z "$TOOLS_ROOT" ]] && return 0', capture_line)
        self.assertNotIn("hyu-vpn-native-client", text)
        self.assertNotIn("suppress-auto-launch", text)
        self.assertIn("print-disabled", text)
        self.assertIn("openconnect.*secure", text)
        self.assertIn("run_optional_cmd", text)
        self.assertIn('uninstall_phase(){\n  if [[ -x "$HELPER_DST" ]]', text)
        self.assertIn("verify_installed_helper_stopped", text)
        self.assertIn("--stage-manifest-sha256", text)
        self.assertIn("--package-manifest-sha256", text)
        self.assertIn("verify_package_manifest_digest", text)
        self.assertIn("copy_package_snapshot", text)
        self.assertIn("verify_stage_digest", text)
        self.assertIn("root-util fsync", text)
        self.assertIn("root-util helper-state", text)
        self.assertNotIn('"$STAGE/bin/hyu-vpn-macos-service"', text)
        self.assertNotIn('"$PAYLOAD/hyu-vpn-macos-service"', text)
        self.assertIn('ROOT_NATIVE_TOOL="$ROOT_NATIVE_TOOL_DIR/hyu-vpn-macos-service"', text)
        self.assertNotIn("durable_flush(){ :; }", text)
        self.assertNotIn("sed -n 's/.*\"state\"", text)
        self.assertIn("validate_privileged_destination_chain", text)
        self.assertIn("root-service-health-ok", text)
        self.assertIn('/bin/chmod 700 "$dst"', text)
        self.assertIn('/usr/sbin/chown -R root:wheel "$dst"', text)
        self.assertIn('durable_flush', text)
        self.assertNotIn('/bin/sync', text)
        self.assertIn('unsafe installed path', text)
        self.assertIn('Library/Preferences/SystemConfiguration', text)


class LauncherAndTemplateTests(InstallerTestCase):
    def test_legacy_terminal_installers_are_removed(self):
        for rel in [
            "installer/install.sh",
            "installer/uninstall.sh",
            "installer/Install HYU VPN.command",
            "installer/Uninstall HYU VPN.command",
        ]:
            self.assertFalse((REPO / rel).exists(), rel)

    def test_runtime_sources_do_not_invoke_generic_keychain_cli(self):
        for rel in [
            "src/hyu_vpn/otp.py",
            "installer/manifest.py",
            "scripts/preflight.sh",
            "macos/Sources/HYUVPNMenuApp/SystemAdapters.swift",
        ]:
            self.assertNotIn("/usr/bin/security", (REPO / rel).read_text(encoding="utf-8"), rel)
        adapter = (REPO / "macos/Sources/HYUVPNMenuApp/SystemAdapters.swift").read_text(encoding="utf-8")
        self.assertNotIn("import Security", adapter)
        self.assertNotIn("SecItem", adapter)
        self.assertIn("AES.GCM", adapter)

    def test_launchd_templates_are_valid_safe_defaults(self):
        for rel in ["launchd/com.hyu.vpn.service.plist.in"]:
            text = (REPO / rel).read_text(encoding="utf-8")
            rendered = text.replace("@USER_HOME@", "/Users/tester").replace("@APP_PATH@", "/Applications/HYU VPN.app").replace("@SERVICE_PATH@", "/Library/Application Support/HYU VPN/bin/hyu-vpn-macos-service")
            plist = plistlib.loads(rendered.encode("utf-8"))
            self.assertTrue(plist["Label"].startswith("com.hyu.vpn."))
            self.assertTrue(plist["RunAtLoad"])
            self.assertFalse(plist["KeepAlive"])
        service = plistlib.loads((REPO / "launchd/com.hyu.vpn.service.plist.in").read_text().replace("@USER_HOME@", "/Users/tester").replace("@SERVICE_PATH@", "/Library/Application Support/HYU VPN/bin/hyu-vpn-macos-service").encode())
        self.assertEqual(service["ProgramArguments"], ["/Library/Application Support/HYU VPN/bin/hyu-vpn-macos-service"])

    def test_production_menu_bundle_uses_canonical_single_instance_identity(self):
        plist = plistlib.loads((REPO / "macos/Resources/HYUVPNMenuApp/Info.plist").read_bytes())
        self.assertEqual(plist["CFBundleIdentifier"], "com.hyu.vpn.menubar")
        self.assertIs(plist["LSMultipleInstancesProhibited"], True)
        self.assertEqual(plist["CFBundleIconFile"], "AppIcon")

        installer_plist = plistlib.loads((REPO / "macos/Resources/HYUVPNInstallerApp/Info.plist").read_bytes())
        self.assertEqual(installer_plist["CFBundleIconFile"], "AppIcon")
        self.assertTrue((REPO / "macos/Resources/AppIcon.icns").is_file())


if __name__ == "__main__":
    unittest.main()
