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
from hyu_vpn.native_client import AutoLaunchMechanism, NativeAutoLaunchManager

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

    def _script(self, rel: str, text: str = "#!/usr/bin/env python3\nprint('ok')\n") -> Path:
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
            "hyu-vpn-control",
            "hyu-vpn-service",
            "hyu-vpn-connect",
            "hyu-vpn-native-client",
        ]:
            self._script(rel)
        (self.payload / "runtime/openconnect/lib").mkdir(parents=True)
        self._script("runtime/openconnect/lib/libvpn.dylib", "lib")
        self._script("com.hyu.vpn.helper", "helper")
        (self.payload / "config").mkdir()
        (self.payload / "config/final-runtime-manifest.json").write_text('{"schema":1,"release_gate":"non_release_task8_placeholder"}\n', encoding="utf-8")
        (self.payload / "installer").mkdir()
        shutil.copy2(REPO / "installer" / "manifest.py", self.payload / "installer" / "manifest.py")
        (self.payload / "installer" / "manifest.py").chmod(0o755)
        shutil.copytree(REPO / "src" / "hyu_vpn", self.payload / "src" / "hyu_vpn", dirs_exist_ok=True)
        (self.payload / "launchd").mkdir()
        for template in ["com.hyu.vpn.service.plist.in", "com.hyu.vpn.menubar.plist.in"]:
            shutil.copy2(REPO / "launchd" / template, self.payload / "launchd" / template)
        app_exec = self.payload / "HYU VPN.app/Contents/MacOS/HYUVPNMenuApp"
        app_exec.parent.mkdir(parents=True)
        app_exec.write_text("app", encoding="utf-8")
        app_exec.chmod(0o755)

    def env(self):
        return DryRunEnvironment(root=self.root / "dry root", payload=self.payload, home=self.root / "home dir", manifest=self.manifest_path)


class PayloadManifestTests(InstallerTestCase):
    def test_manifest_verify_rejects_hash_mode_extra_and_symlink(self):
        (self.payload / "hyu-vpn-control").write_text("tampered", encoding="utf-8")
        with self.assertRaisesRegex(ManifestError, "hash mismatch"):
            PayloadManifest.verify(self.payload, self.manifest_path)
        self._script("hyu-vpn-control")
        data = json.loads(self.manifest_path.read_text())
        data["files"]["hyu-vpn-control"]["mode"] = "0600"
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
        self.assertTrue((env.root / ".hyu-vpn-dry-run-root").exists())
        for rel in [
            "runtime/bin/openconnect",
            "runtime/bin/oathtool",
            "runtime/gp-hip-report",
            "runtime/vpnc/hyu-vpnc-wrapper",
            "bin/hyu-vpn-native-client",
            "src/hyu_vpn/__init__.py",
            "HYU VPN.app/Contents/MacOS/HYUVPNMenuApp",
            "manifest.json",
        ]:
            self.assertTrue((stage / rel).exists(), rel)
        text = (REPO / "installer/manifest.py").read_text(encoding="utf-8")
        for forbidden in ["/opt/homebrew", "/usr/local", "resolve_homebrew", "InstallerTransaction", "RootAdminTransaction", "--dry-run-root", "install_name_tool", "codesign"]:
            self.assertNotIn(forbidden, text)
        recorded = recorder.commands()
        self.assertEqual(recorded[0][:3], ["/usr/bin/python3", "installer/manifest.py", "--verify-manifest"])
        self.assertFalse(any("/usr/bin/sudo" in cell for row in recorded[:-1] for cell in row))

    def test_cli_stage_is_exact_unique_stage_dir_and_package_audit_checks_python_runtime(self):
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

    def make_fake_tools_for(self, env, failing_tool=None, route_output=""):
        tools = env.root / "Users" / ".fake-tools"
        for tool in ["/usr/sbin/visudo", "/usr/sbin/chown", "/usr/bin/pgrep", "/usr/sbin/netstat", "/usr/sbin/scutil", "/usr/bin/env", "/bin/launchctl", "/bin/mv"]:
            path = tools / tool.lstrip("/")
            path.parent.mkdir(parents=True, exist_ok=True)
            name = path.name
            if failing_tool == name:
                body = f"#!/bin/sh\necho {name} failed >&2\nexit 42\n"
            elif name == "mv":
                body = "#!/bin/sh\n/bin/mv \"$@\"\n"
            elif name == "netstat" and route_output:
                body = f"#!/bin/sh\nprintf '%s\\n' {route_output!r}\n"
            elif name == "env":
                body = '#!/bin/sh\nroot=""\nfor arg in "$@"; do\n  case "$arg" in */Library/Application\\ Support/HYU\\ VPN/*) root=${arg%%/Library/Application\\ Support/HYU\\ VPN/*};; esac\ndone\nstate="$root/private/var/db/hyu-vpn"\nmkdir -p "$state"\ncase " $* " in\n  *" verify-suppressed "*) exit 0 ;;\n  *" suppress-auto-launch "*) printf \'%s\n\' \'{"schema_version":1,"console_uid":501,"mechanisms":[{"identifier":"com.paloaltonetworks.gp.pangps","kind":"launchd-gui","enabled":true,"exact_target":"/Library/LaunchAgents/com.paloaltonetworks.gp.pangps.plist","running":false}]}\' > "$state/native-suppression.json"; chmod 600 "$state/native-suppression.json"; exit 0 ;;\n  *" restore-auto-launch "*) rm -f "$state/native-suppression.json"; exit 0 ;;\nesac\nexit 99\n'
            else:
                body = "#!/bin/sh\nexit 0\n"
            path.write_text(body, encoding="utf-8")
            path.chmod(0o755)
        return tools

    def make_fake_tools(self, failing_tool=None, route_output=""):
        return self.make_fake_tools_for(self.env(), failing_tool=failing_tool, route_output=route_output)

    def test_root_admin_installs_complete_payload_without_bootstrap_or_autostart(self):
        env = self.env()
        stage = stage_user_payload(env)
        proc = self.run_root_admin(env, stage)
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        root = env.root
        self.assertTrue((root / "Library/PrivilegedHelperTools/com.hyu.vpn.helper").exists())
        app_support = root / "Library/Application Support/HYU VPN"
        self.assertTrue((app_support / "helper-config.json").exists())
        self.assertTrue((app_support / "runtime/current/bin/openconnect").exists())
        self.assertTrue((app_support / "runtime/vpnc/hyu-vpnc-wrapperd.sha256").exists())
        self.assertTrue((app_support / "bin/hyu-vpn-service").exists())
        self.assertTrue((root / "etc/sudoers.d/hyu-vpn").exists())
        self.assertFalse((root / "etc/sudoers.d/com.hyu.vpn").exists())
        service = plistlib.loads((root / "Users/tester/Library/LaunchAgents/com.hyu.vpn.service.plist").read_bytes())
        menubar = plistlib.loads((root / "Users/tester/Library/LaunchAgents/com.hyu.vpn.menubar.plist").read_bytes())
        self.assertEqual(service["ProgramArguments"], ["/usr/bin/python3", "/Library/Application Support/HYU VPN/bin/hyu-vpn-service"])
        self.assertTrue(service["RunAtLoad"])
        self.assertFalse(service["KeepAlive"])
        self.assertTrue(menubar["RunAtLoad"])
        commands = (root / "private/var/db/hyu-vpn/command-log.jsonl").read_text()
        self.assertIn("launchctl disable gui/501/local.hyu-openconnect", commands)
        self.assertNotIn("launchctl bootstrap", commands)
        self.assertNotIn("install_name_tool", commands)
        self.assertNotIn("codesign", commands)

    def test_root_admin_ignores_user_stage_contents_and_rolls_back_exact_paths(self):
        env = self.env()
        stage = stage_user_payload(env)
        (stage / "runtime/bin/openconnect").write_text("tampered", encoding="utf-8")
        proc = self.run_root_admin(env, stage)
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        installed = env.root / "Library/Application Support/HYU VPN/runtime/current/bin/openconnect"
        self.assertEqual(installed.read_text(encoding="utf-8"), (env.payload / "runtime/openconnect/bin/openconnect").read_text(encoding="utf-8"))
        env2 = DryRunEnvironment(root=self.root / "dry rollback", payload=self.payload, home=self.root / "home rollback", manifest=self.manifest_path)
        stage2 = stage_user_payload(env2)
        proc = self.run_root_admin(env2, stage2, extra_env={"HYU_VPN_FAIL_AFTER": "sudoers"})
        self.assertNotEqual(proc.returncode, 0)
        self.assertFalse((env2.root / "etc/sudoers.d/hyu-vpn").exists())
        self.assertIn("rollback-complete", (env2.root / "private/var/db/hyu-vpn/install-transaction.log").read_text())

    def test_root_admin_migrates_legacy_dotted_sudoers_fragment(self):
        env = DryRunEnvironment(root=self.root / "dry sudoers migration", payload=self.payload, home=self.root / "home sudoers migration", manifest=self.manifest_path)
        stage = stage_user_payload(env)
        tools = self.make_fake_tools_for(env)
        launchctl = tools / "bin/launchctl"
        legacy = env.root / "etc/sudoers.d/com.hyu.vpn"
        launchctl.write_text(
            "#!/bin/sh\n"
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

    def test_upgrade_preserves_existing_native_suppression_snapshot(self):
        env = DryRunEnvironment(root=self.root / "dry native upgrade", payload=self.payload, home=self.root / "home native upgrade", manifest=self.manifest_path)
        stage = stage_user_payload(env)
        state = env.root / "private/var/db/hyu-vpn"
        state.mkdir(parents=True, exist_ok=True)
        record = state / "native-suppression.json"
        original = (
            '{"schema_version":1,"console_uid":501,"mechanisms":['
            '{"identifier":"com.paloaltonetworks.gp.pangps","kind":"launchd-gui",'
            '"enabled":true,"exact_target":"/Library/LaunchAgents/com.paloaltonetworks.gp.pangps.plist","running":false}'
            ']}\n'
        )
        record.write_text(original, encoding="utf-8")
        record.chmod(0o600)

        proc = self.run_root_admin(env, stage, tools_root=self.make_fake_tools_for(env))

        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        self.assertEqual(record.read_text(encoding="utf-8"), original)
        commands = (state / "command-log.jsonl").read_text(encoding="utf-8")
        self.assertNotIn("suppress-auto-launch", commands)
        self.assertIn("verify-suppressed", commands)
        self.assertIn("native-suppression-preserved", (state / "install-transaction.log").read_text(encoding="utf-8"))

    def test_malicious_stage_with_regenerated_digest_cannot_override_verified_package(self):
        env = self.env()
        stage = stage_user_payload(env)
        (stage / "backend/hyu-vpn-service").write_text("evil", encoding="utf-8")
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
        self.assertIn("staged manifest digest mismatch", proc.stderr)
        self.assertFalse((env.root / "Library/Application Support/HYU VPN/bin/hyu-vpn-service").exists())

    def test_payload_concurrent_change_after_user_stage_fails_root_package_verification(self):
        env = self.env()
        stage = stage_user_payload(env)
        package_digest = hashlib.sha256((env.payload / "manifest.json").read_bytes()).hexdigest()
        (env.payload / "hyu-vpn-control").write_text("changed-after-stage", encoding="utf-8")
        args = [
            "--dry-run-root", str(env.root),
            "--stage", str(stage),
            "--stage-manifest-sha256", hashlib.sha256((stage / "manifest.json").read_bytes()).hexdigest(),
            "--package-manifest-sha256", package_digest,
            "--payload", str(env.payload),
            "--manifest", str(env.manifest),
            "--admin-user", env.user,
            "--admin-uid", "501",
            "--administrator-phase", "install",
        ]
        proc = self.run_root_admin_raw(args)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("package snapshot manifest verification failed", proc.stderr)
        self.assertFalse((env.root / "Library/Application Support/HYU VPN/bin/hyu-vpn-control").exists())



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

    def test_root_package_snapshot_rejects_symlinked_verifier_before_execution(self):
        env = self.env()
        stage = stage_user_payload(env)
        package_digest = hashlib.sha256((env.payload / "manifest.json").read_bytes()).hexdigest()
        verifier = env.payload / "installer/manifest.py"
        verifier.unlink()
        verifier.symlink_to("/tmp/evil-manifest.py")
        args = [
            "--dry-run-root", str(env.root),
            "--stage", str(stage),
            "--stage-manifest-sha256", hashlib.sha256((stage / "manifest.json").read_bytes()).hexdigest(),
            "--package-manifest-sha256", package_digest,
            "--payload", str(env.payload),
            "--manifest", str(env.manifest),
            "--admin-user", env.user,
            "--admin-uid", "501",
            "--administrator-phase", "install",
        ]
        proc = self.run_root_admin_raw(args)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("package snapshot manifest verification failed", proc.stderr)
        self.assertIn("symlink in package snapshot", proc.stderr)



    def test_stale_native_suppression_marker_is_cleared_before_pre_suppression_failure(self):
        env = DryRunEnvironment(root=self.root / "dry stale", payload=self.payload, home=self.root / "home stale", manifest=self.manifest_path)
        stage = stage_user_payload(env)
        state = env.root / "private/var/db/hyu-vpn"
        state.mkdir(parents=True, exist_ok=True)
        (state / "native-suppression-transaction").write_text("stale", encoding="utf-8")
        proc = self.run_root_admin(env, stage, extra_env={"HYU_VPN_FAIL_AFTER": "app"})
        self.assertNotEqual(proc.returncode, 0)
        commands_path = state / "command-log.jsonl"
        commands = commands_path.read_text() if commands_path.exists() else ""
        self.assertNotIn("restore-auto-launch", commands)
        self.assertFalse((state / "native-suppression-transaction").exists())

    def test_stage_manifest_digest_binds_pre_sudo_stage_against_tamper_and_regenerate(self):
        env = self.env()
        stage = stage_user_payload(env)
        expected = hashlib.sha256((stage / "manifest.json").read_bytes()).hexdigest()
        (stage / "backend/hyu-vpn-service").write_text("evil", encoding="utf-8")
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
        self.assertFalse((env.root / "Library/Application Support/HYU VPN/bin/hyu-vpn-service").exists())

    def test_post_native_failure_restores_native_before_rollback_removes_cli(self):
        env = DryRunEnvironment(root=self.root / "dry native", payload=self.payload, home=self.root / "home native", manifest=self.manifest_path)
        stage = stage_user_payload(env)
        proc = self.run_root_admin(env, stage, extra_env={"HYU_VPN_FAIL_AFTER": "native-suppression"}, tools_root=self.make_fake_tools_for(env))
        self.assertNotEqual(proc.returncode, 0)
        journal = (env.root / "private/var/db/hyu-vpn/install-transaction.log").read_text()
        commands = (env.root / "private/var/db/hyu-vpn/command-log.jsonl").read_text()
        self.assertIn("rollback-native-restored", journal)
        self.assertLess(commands.index("suppress-auto-launch"), commands.index("restore-auto-launch"))

    def test_native_suppress_command_failure_is_marked_for_root_rollback_before_cli_runs(self):
        env = DryRunEnvironment(root=self.root / "dry native command failure", payload=self.payload, home=self.root / "home native command failure", manifest=self.manifest_path)
        stage = stage_user_payload(env)
        tools = self.make_fake_tools_for(env)
        env_tool = tools / "usr/bin/env"
        env_tool.write_text(
            '#!/bin/sh\n'
            'root=""\n'
            'for arg in "$@"; do case "$arg" in */Library/Application\\ Support/HYU\\ VPN/*) root=${arg%%/Library/Application\\ Support/HYU\\ VPN/*};; esac; done\n'
            'state="$root/private/var/db/hyu-vpn"\n'
            'mkdir -p "$state"\n'
            'case " $* " in\n'
            '  *" suppress-auto-launch "*) printf \'%s\\n\' \'{"schema_version":1,"console_uid":501,"phase":"rollback-required","pending_identifier":null,"applied_identifiers":["com.paloaltonetworks.gp.pangps"],"stopped_identifiers":[],"mechanisms":[{"identifier":"com.paloaltonetworks.gp.pangps","kind":"launchd-gui","enabled":true,"exact_target":"/Library/LaunchAgents/com.paloaltonetworks.gp.pangps.plist","running":false}]}\' > "$state/native-suppression.json"; chmod 600 "$state/native-suppression.json"; exit 42 ;;\n'
            '  *" restore-auto-launch "*) rm -f "$state/native-suppression.json"; exit 0 ;;\n'
            'esac\n'
            'exit 99\n',
            encoding="utf-8",
        )
        env_tool.chmod(0o755)

        proc = self.run_root_admin(env, stage, tools_root=tools)

        self.assertNotEqual(proc.returncode, 0)
        commands = (env.root / "private/var/db/hyu-vpn/command-log.jsonl").read_text(encoding="utf-8")
        journal = (env.root / "private/var/db/hyu-vpn/install-transaction.log").read_text(encoding="utf-8")
        self.assertIn("suppress-auto-launch", commands)
        self.assertIn("restore-auto-launch", commands)
        self.assertLess(commands.index("suppress-auto-launch"), commands.index("restore-auto-launch"))
        self.assertIn("rollback-native-restored", journal)

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
        proc = self.run_root_admin(env3, stage3, tools_root=self.make_fake_tools_for(env3, route_output="166.104.0.0/16 link#1"))
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("legacy tunnel route remains", proc.stderr)

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

    def test_uninstall_is_idempotent_allowlisted_and_uses_singleton_keychain_account(self):
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
        uninstall = (REPO / "installer/uninstall.sh").read_text(encoding="utf-8")
        for item in ["gp-vpn-username", "gp-vpn-password", "gp-vpn-totp"]:
            self.assertIn(f"delete-generic-password -s {item} -a hyu-vpn", uninstall)


    def test_native_snapshot_validator_accepts_actual_manager_record_schema(self):
        class Store:
            def __init__(self):
                self.mechanisms = {
                    "com.paloaltonetworks.gp.pangps": AutoLaunchMechanism(
                        "com.paloaltonetworks.gp.pangps",
                        "launchd-gui",
                        True,
                        "/Library/LaunchAgents/com.paloaltonetworks.gp.pangps.plist",
                    )
                }
            def list_mechanisms(self):
                return list(self.mechanisms.values())
            def set_enabled(self, identifier, enabled):
                current = self.mechanisms[identifier]
                self.mechanisms[identifier] = AutoLaunchMechanism(current.identifier, current.kind, enabled, current.exact_target)
        with tempfile.TemporaryDirectory() as td:
            record = Path(td) / "native-suppression.json"
            NativeAutoLaunchManager(store=Store(), console_uid=501).suppress_auto_launch(record)
            data = json.loads(record.read_text(encoding="utf-8"))
        self.assertEqual(set(data), {"schema_version", "console_uid", "mechanisms"})
        self.assertEqual(set(data["mechanisms"][0]), {"identifier", "kind", "enabled", "exact_target", "running"})
        root_admin = (REPO / "installer/root-admin.sh").read_text(encoding="utf-8")
        for token in ["mechanisms", "exact_target", "com.paloaltonetworks.gp.pangps", "com.paloaltonetworks.gp.pangpa", "com.paloaltonetworks.gp.pangpsd"]:
            self.assertIn(token, root_admin)

    def test_root_admin_static_security_contracts(self):
        text = (REPO / "installer/root-admin.sh").read_text(encoding="utf-8")
        self.assertIn('SUDOERS_DST="$(map_path /etc/sudoers.d/hyu-vpn)"', text)
        self.assertIn('LEGACY_SUDOERS_DST="$(map_path /etc/sudoers.d/com.hyu.vpn)"', text)
        self.assertIn('SUDOERS_TMP="$STATE_DIR/sudoers-candidate.$$"', text)
        self.assertIn('/bin/rm -f "$SUDOERS_TMP"', text)
        self.assertIn('backup_target "$LEGACY_SUDOERS_DST"', text)
        self.assertIn("etc/sudoers.d/hyu-vpn|etc/sudoers.d/com.hyu.vpn", text)
        self.assertIn('capture_cmd(){', text)
        self.assertIn('else "$exe" "$@"', text)
        self.assertIn("validate_native_snapshot", text)
        self.assertIn('SUDO_UID="$ADMIN_UID"', text)
        self.assertIn("print-disabled", text)
        self.assertIn("openconnect.*secure", text)
        self.assertIn("run_optional_cmd", text)
        self.assertIn("--stage-manifest-sha256", text)
        self.assertIn("--package-manifest-sha256", text)
        self.assertIn("verify_package_manifest_digest", text)
        self.assertIn("copy_package_snapshot", text)
        self.assertIn('--stage-user-payload --stage-dir "$TXN_SNAPSHOT"', text)
        self.assertIn("verify_stage_digest", text)
        self.assertIn("rollback-native-restored", text)
        self.assertIn("native-suppression-transaction", text)
        self.assertIn("/bin/rm -f \"$STATE_DIR/native-suppression-transaction\"", text)
        self.assertIn('/bin/chmod 700 "$dst"', text)
        self.assertIn('/usr/sbin/chown -R root:wheel "$dst"', text)
        self.assertIn('durable_flush', text)
        self.assertNotIn('/bin/sync', text)
        self.assertIn('unsafe installed path', text)
        self.assertIn('Library/Preferences/SystemConfiguration', text)


class LauncherAndTemplateTests(InstallerTestCase):

    def _write_fake_install_tools(self, root: Path):
        tools = root / "fake-install-tools"
        tools.mkdir(parents=True)
        security = tools / "security"
        security.write_text('#!/bin/sh\nlog="$FAKE_INSTALL_LOG"\nprintf \'security\' >> "$log"\nfor arg in "$@"; do printf \' [%s]\' "$arg" >> "$log"; done\nprintf \'\n\' >> "$log"\nif [ "$1" = "find-generic-password" ]; then\n  want_password=0\n  while [ $# -gt 0 ]; do [ "$1" = "-w" ] && want_password=1; shift; done\n  [ "$want_password" = 1 ] && { printf \'secret-from-temp\n\'; exit 0; }\n  exit 1\nfi\nif [ "$1" = "add-generic-password" ]; then\n  service=""\n  while [ $# -gt 0 ]; do [ "$1" = "-s" ] && { shift; service="$1"; }; shift; done\n  [ "$service" = "gp-vpn-totp" ] && exit 44\n  exit 0\nfi\nif [ "$1" = "delete-generic-password" ]; then exit 0; fi\nexit 0\n', encoding="utf-8")
        security.chmod(0o755)
        sudo = tools / "sudo"
        sudo.write_text('#!/bin/sh\nlog="$FAKE_INSTALL_LOG"\nprintf \'sudo\' >> "$log"\nfor arg in "$@"; do printf \' [%s]\' "$arg" >> "$log"; done\nprintf \'\n\' >> "$log"\n[ "$1" = "-v" ] && exit 0\ncase " $* " in\n  *" --administrator-phase install "*) exit 0 ;;\n  *" --administrator-phase uninstall "*) exit "${FAKE_UNINSTALL_STATUS:-0}" ;;\nesac\nexit 99\n', encoding="utf-8")
        sudo.chmod(0o755)
        date = tools / "date"
        date.write_text('#!/bin/sh\nlog="$FAKE_INSTALL_LOG"\nprintf \'date\' >> "$log"\nfor arg in "$@"; do printf \' [%s]\' "$arg" >> "$log"; done\nprintf \'\n\' >> "$log"\nprintf \'%s\\n\' "${FAKE_DATE_EPOCH:-1785881401}"\n', encoding="utf-8")
        date.chmod(0o755)
        return tools

    def _patched_install_script_for_fake_tools(self, tools: Path) -> Path:
        script = self.payload / "installer/install.fake-tools.sh"
        text = (REPO / "installer/install.sh").read_text(encoding="utf-8")
        text = text.replace("/usr/bin/security", str(tools / "security"))
        text = text.replace("/usr/bin/sudo", str(tools / "sudo"))
        text = text.replace("/bin/date", str(tools / "date"))
        script.write_text(text, encoding="utf-8")
        script.chmod(0o755)
        self.manifest_path = PayloadManifest.write_for_tree(self.payload, self.payload / "manifest.json")
        return script

    def _patched_uninstall_script_for_fake_tools(self, tools: Path) -> Path:
        script = self.payload / "installer/uninstall.fake-tools.sh"
        text = (REPO / "installer/uninstall.sh").read_text(encoding="utf-8")
        text = text.replace("/usr/bin/security", str(tools / "security"))
        text = text.replace("/usr/bin/sudo", str(tools / "sudo"))
        text = text.replace("/bin/date", str(tools / "date"))
        script.write_text(text, encoding="utf-8")
        script.chmod(0o755)
        self.manifest_path = PayloadManifest.write_for_tree(self.payload, self.payload / "manifest.json")
        return script

    def test_install_promotion_failure_executes_root_cleanup_and_reports_successful_cleanup(self):
        tools = self._write_fake_install_tools(self.root)
        script = self._patched_install_script_for_fake_tools(tools)
        log = self.root / "fake-install.log"
        proc = subprocess.run(["/bin/zsh", str(script), "--live-install"], input="tester\n", text=True, capture_output=True, env={**os.environ, "FAKE_INSTALL_LOG": str(log), "FAKE_UNINSTALL_STATUS": "0", "HOME": str(self.root / "home")})
        self.assertEqual(proc.returncode, 1, proc.stderr + proc.stdout)
        logged = log.read_text(encoding="utf-8")
        self.assertIn("sudo [-n] [/bin/zsh]", logged)
        self.assertIn("--administrator-phase] [install]", logged)
        self.assertIn("--administrator-phase] [uninstall]", logged)
        self.assertNotIn("rollback incomplete", proc.stderr.lower())

    def test_install_promotion_failure_reports_rollback_incomplete_when_root_cleanup_fails(self):
        tools = self._write_fake_install_tools(self.root)
        script = self._patched_install_script_for_fake_tools(tools)
        log = self.root / "fake-install-fail.log"
        proc = subprocess.run(["/bin/zsh", str(script), "--live-install"], input="tester\n", text=True, capture_output=True, env={**os.environ, "FAKE_INSTALL_LOG": str(log), "FAKE_UNINSTALL_STATUS": "42", "HOME": str(self.root / "home")})
        self.assertEqual(proc.returncode, 70, proc.stderr + proc.stdout)
        self.assertIn("HYU VPN root rollback incomplete", proc.stderr)
        logged = log.read_text(encoding="utf-8")
        self.assertIn("--administrator-phase] [uninstall]", logged)

    def test_live_nonce_is_generated_after_admin_auth_and_used_noninteractively(self):
        tools = self._write_fake_install_tools(self.root)
        script = self._patched_install_script_for_fake_tools(tools)
        log = self.root / "fake-install-nonce.log"
        proc = subprocess.run(["/bin/zsh", str(script), "--live-install"], input="tester\n", text=True, capture_output=True, env={**os.environ, "FAKE_INSTALL_LOG": str(log), "HOME": str(self.root / "home")})
        self.assertEqual(proc.returncode, 1, proc.stderr + proc.stdout)
        logged = log.read_text(encoding="utf-8")
        auth = logged.index("sudo [-v]")
        nonce = logged.index("date [+%s]", auth)
        root_admin = logged.index("sudo [-n] [/bin/zsh]", nonce)
        self.assertLess(auth, nonce)
        self.assertLess(nonce, root_admin)
        self.assertIn("[--live-install] [hyu-install-mutation-1785881401]", logged[root_admin:])

    def test_uninstall_live_nonce_is_generated_after_admin_auth_and_used_noninteractively(self):
        tools = self._write_fake_install_tools(self.root)
        script = self._patched_uninstall_script_for_fake_tools(tools)
        log = self.root / "fake-uninstall-nonce.log"
        proc = subprocess.run(["/bin/zsh", str(script), "--live-install"], input="KEEP\n", text=True, capture_output=True, env={**os.environ, "FAKE_INSTALL_LOG": str(log), "HOME": str(self.root / "home")})
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        logged = log.read_text(encoding="utf-8")
        auth = logged.index("sudo [-v]")
        nonce = logged.index("date [+%s]", auth)
        root_admin = logged.index("sudo [-n] [/bin/zsh]", nonce)
        self.assertLess(auth, nonce)
        self.assertLess(nonce, root_admin)
        self.assertIn("[--live-install] [hyu-install-mutation-1785881401]", logged[root_admin:])

    def test_install_uninstall_default_to_audit_and_single_sudo_after_credentials(self):
        install = (REPO / "installer/install.sh").read_text(encoding="utf-8")
        uninstall = (REPO / "installer/uninstall.sh").read_text(encoding="utf-8")
        self.assertIn("--package-audit", install)
        self.assertIn("--live-install", install)
        self.assertIn("hyu-install-mutation-$(/bin/date +%s)", install)
        self.assertNotIn("HYU_VPN_INSTALL_NONCE", install)
        nonce_assignment = 'LIVE_NONCE="hyu-install-mutation-$(/bin/date +%s)"'
        self.assertEqual(install.count(nonce_assignment), 1)
        self.assertIn("/usr/bin/sudo -v", install)
        self.assertIn("/usr/bin/sudo -n /bin/zsh", install)
        self.assertGreater(install.index(nonce_assignment), install.index("/usr/bin/sudo -v"))
        self.assertLess(install.index(nonce_assignment), install.index('/usr/bin/sudo -n /bin/zsh'))
        self.assertIn("-w \"$HYU_VPN_USERNAME\"", install)
        self.assertIn("hyu-vpn-install-password-", install)
        self.assertIn("HYU VPN password (not the Mac administrator password)", install)
        self.assertIn("TOTP secret seed (not the current 6-digit OTP code)", install)
        self.assertIn("find-generic-password -w -s \"$TMP_PASS_SERVICE\"", install)
        self.assertIn("AutoReconnectPreference", install)
        self.assertIn("launchctl bootstrap", install)
        self.assertIn("launchctl kickstart", install)
        self.assertIn('launchctl kickstart -k "gui/$USER_UID/com.hyu.vpn.service"', install)
        self.assertIn('launchctl kickstart -k "gui/$USER_UID/com.hyu.vpn.menubar"', install)
        self.assertIn("launchctl print", install)
        self.assertIn("missing installed service LaunchAgent", install)
        self.assertIn("/usr/bin/open -a", install)
        self.assertLess(install.index("AutoReconnectPreference"), install.index("launchctl bootstrap"))
        activation = install[install.index("AutoReconnectPreference"):]
        self.assertNotIn("/opt/homebrew/bin/openconnect", activation)
        self.assertNotIn("com.hyu.vpn.helper start", activation)
        self.assertLess(install.index("TMP_PASS_SERVICE"), install.index("/usr/bin/sudo"))
        self.assertLess(install.index("/usr/bin/sudo"), install.index("record_keychain_created gp-vpn-password"))
        self.assertGreaterEqual(install.count("/usr/bin/sudo"), 1)
        self.assertIn("--administrator-phase uninstall", install)
        self.assertIn("HYU VPN root rollback incomplete", install)
        root_cleanup = install[install.index("--administrator-phase uninstall")-120:install.index("HYU VPN root rollback incomplete")]
        self.assertNotIn(">/dev/null 2>&1", root_cleanup)
        self.assertNotIn("|| true", root_cleanup)
        self.assertLess(install.index("--verify-manifest"), install.index("/usr/bin/sudo"))
        self.assertGreater(install.index("record_keychain_created gp-vpn-username"), install.index("--administrator-phase install"))
        self.assertIn("--package-audit", uninstall)
        self.assertEqual(uninstall.count("/usr/bin/sudo -v"), 1)
        self.assertEqual(uninstall.count("/usr/bin/sudo -n /bin/zsh"), 1)

    def test_launchd_templates_are_valid_safe_defaults(self):
        for rel in ["launchd/com.hyu.vpn.service.plist.in", "launchd/com.hyu.vpn.menubar.plist.in"]:
            text = (REPO / rel).read_text(encoding="utf-8")
            rendered = text.replace("@USER_HOME@", "/Users/tester").replace("@APP_PATH@", "/Applications/HYU VPN.app").replace("@SERVICE_PATH@", "/Library/Application Support/HYU VPN/bin/hyu-vpn-service").replace("@CONTROL_PATH@", "/Library/Application Support/HYU VPN/bin/hyu-vpn-control")
            plist = plistlib.loads(rendered.encode("utf-8"))
            self.assertTrue(plist["Label"].startswith("com.hyu.vpn."))
            self.assertTrue(plist["RunAtLoad"])
            self.assertFalse(plist["KeepAlive"])
        service = plistlib.loads((REPO / "launchd/com.hyu.vpn.service.plist.in").read_text().replace("@USER_HOME@", "/Users/tester").replace("@SERVICE_PATH@", "/Library/Application Support/HYU VPN/bin/hyu-vpn-service").encode())
        self.assertEqual(service["ProgramArguments"], ["/usr/bin/python3", "/Library/Application Support/HYU VPN/bin/hyu-vpn-service"])


if __name__ == "__main__":
    unittest.main()
