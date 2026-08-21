from __future__ import annotations

import json
import os
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

import release_packaging as packaging_module

from release_packaging import (
    PackagingError,
    ReleaseBuilder,
    ReleaseToolchain,
    INSTALLER_APP_REL,
    INSTALLER_EXEC_REL,
    guard_destination,
    guard_root,
    loader_replacement_for,
    RuntimeClosurePlanner,
    assemble_payload_from_repo,
    copied_runtime_rel,
    copy_runtime_closure,
    validate_third_party_notices,
    verify_rewrite_target_exists,
)

ASSEMBLE_MENU_APP = REPO / "macos" / "Scripts" / "assemble-menu-app.sh"
ASSEMBLE_INSTALLER_APP = REPO / "macos" / "Scripts" / "assemble-installer-app.sh"
PACKAGE_RELEASE = REPO / "scripts" / "package-release.py"
INSTALLER_MANIFEST = REPO / "installer" / "manifest.py"


class PackagingTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve(strict=True)
        self.source = self.root / "source"
        self.source.mkdir()
        self.build_root = self.root / "build"
        self.output_root = self.root / "out"
        self.build_root.mkdir()
        self.output_root.mkdir()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def make_source_bundle(self, name: str = "SOURCE-COMPLIANCE-BUNDLE.tar.gz", *, malicious: str | None = None, runtime_files: dict[str, Path] | None = None) -> Path:
        bundle = self.root / name
        files = {
            "source/openconnect.tar.gz": b"openconnect source archive\n",
            "source/oath-toolkit.tar.gz": b"oath source archive\n",
            "formula/openconnect.rb": b"class Openconnect < Formula\nend\n",
            "formula/oath-toolkit.rb": b"class OathToolkit < Formula\nend\n",
            "receipts/openconnect.json": b"{\"name\":\"openconnect\"}\n",
            "receipts/oath-toolkit.json": b"{\"name\":\"oath-toolkit\"}\n",
            "patches/openconnect.patch": b"diff --git a/a b/a\n",
            "resources/vpnc-script": b"#!/bin/sh\n",
            "build-info.txt": b"HYU VPN internal source compliance bundle\n",
            "homebrew-formula-info.json": json.dumps({
                "formulae": [
                    {"name": "openconnect", "versions": {"stable": "9.21"}, "revision": 0},
                    {"name": "oath-toolkit", "versions": {"stable": "2.6.14"}, "revision": 3},
                ],
                "casks": [],
            }, sort_keys=True).encode() + b"\n",
        }
        if runtime_files is None:
            runtime_entries = [
                {"path": "runtime/openconnect/bin/openconnect", "sha256": "0" * 64, "size": 0, "package": "openconnect", "source": "source/openconnect.tar.gz"},
                {"path": "runtime/oathtool", "sha256": "1" * 64, "size": 0, "package": "oath-toolkit", "source": "source/oath-toolkit.tar.gz"},
                {"path": "runtime/vpnc/vpnc-script", "sha256": "2" * 64, "size": 0, "package": "vpnc-script", "source": "resources/vpnc-script"},
            ]
        else:
            runtime_entries = []
            for rel, file_path in sorted(runtime_files.items()):
                data = file_path.read_bytes()
                package = "oath-toolkit" if rel == "runtime/oathtool" else "vpnc-script" if rel.endswith("vpnc-script") else "openconnect"
                source = "source/oath-toolkit.tar.gz" if package == "oath-toolkit" else "resources/vpnc-script" if package == "vpnc-script" else "source/openconnect.tar.gz"
                runtime_entries.append({"path": rel, "sha256": __import__("hashlib").sha256(data).hexdigest(), "size": len(data), "package": package, "source": source})
        runtime_closure = {"schema": 1, "files": runtime_entries}
        files["runtime-closure.json"] = json.dumps(runtime_closure, sort_keys=True).encode() + b"\n"
        digests = {rel: __import__("hashlib").sha256(data).hexdigest() for rel, data in files.items()}
        inventory = {
            "schema": 1,
            "runtime": [{"package": "hyu-runtime", "runtime_closure": "runtime-closure.json", "sha256": digests["runtime-closure.json"]}],
            "sources": [
                {"package": "openconnect", "file": "source/openconnect.tar.gz", "sha256": digests["source/openconnect.tar.gz"]},
                {"package": "oath-toolkit", "file": "source/oath-toolkit.tar.gz", "sha256": digests["source/oath-toolkit.tar.gz"]},
                {"package": "openconnect", "file": "formula/openconnect.rb", "sha256": digests["formula/openconnect.rb"]},
                {"package": "oath-toolkit", "file": "formula/oath-toolkit.rb", "sha256": digests["formula/oath-toolkit.rb"]},
                {"package": "homebrew:formula-metadata", "file": "homebrew-formula-info.json", "sha256": digests["homebrew-formula-info.json"]},
            ],
            "resource_sources": [{"name": "vpnc-script", "file": "resources/vpnc-script", "sha256": digests["resources/vpnc-script"]}],
            "receipts": [
                {"package": "openconnect", "file": "receipts/openconnect.json", "sha256": digests["receipts/openconnect.json"]},
                {"package": "oath-toolkit", "file": "receipts/oath-toolkit.json", "sha256": digests["receipts/oath-toolkit.json"]},
            ],
            "patches": [{"package": "openconnect", "file": "patches/openconnect.patch", "sha256": digests["patches/openconnect.patch"]}],
        }
        files["inventory.json"] = json.dumps(inventory, sort_keys=True).encode() + b"\n"
        checksum_lines = [f"{__import__('hashlib').sha256(data).hexdigest()}  {rel}\n" for rel, data in sorted(files.items()) if rel != "checksums.txt"]
        files["checksums.txt"] = "".join(checksum_lines).encode()
        with tarfile.open(bundle, "w:gz") as tf:
            for rel, data in files.items():
                path = self.root / f"bundle-{rel.replace('/', '-')}"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
                tf.add(path, arcname=rel)
            if malicious == "absolute":
                path = self.root / "evil"; path.write_text("evil", encoding="utf-8"); tf.add(path, arcname="/tmp/evil")
            elif malicious == "traversal":
                path = self.root / "evil"; path.write_text("evil", encoding="utf-8"); tf.add(path, arcname="../evil")
            elif malicious == "symlink":
                info = tarfile.TarInfo("bad-link"); info.type = tarfile.SYMTYPE; info.linkname = "/etc/passwd"; tf.addfile(info)
            elif malicious == "unchecked_extra":
                path = self.root / "extra"; path.write_text("extra", encoding="utf-8"); tf.add(path, arcname="extra.txt")
            elif malicious == "bad_checksum_format":
                path = self.root / "bad-checksums"; path.write_text("not-a-sha source/openconnect.tar.gz\n", encoding="utf-8"); tf.add(path, arcname="checksums.txt")
            elif malicious == "missing_inventory_reference":
                path = self.root / "bad-inventory"; path.write_text(json.dumps({"schema": 1, "runtime": [{"package": "openconnect", "runtime_closure": "missing.json", "sha256": "0"*64}], "sources": [], "resource_sources": []}), encoding="utf-8"); tf.add(path, arcname="inventory.json")
            elif malicious == "duplicate_key_inventory":
                path = self.root / "dup-inventory"; path.write_text('{"schema":1,"schema":1,"runtime":[],"sources":[],"resource_sources":[]}', encoding="utf-8"); tf.add(path, arcname="inventory.json")
        return bundle

    def make_payload_source(self) -> Path:
        src = self.source
        (src / "HYU VPN.app" / "Contents" / "MacOS").mkdir(parents=True)
        (src / "HYU VPN.app" / "Contents" / "MacOS" / "HYUVPNMenuApp").write_text("menu", encoding="utf-8")
        (src / "HYU VPN.app" / "Contents" / "MacOS" / "HYUVPNCredentialReader").write_text("reader", encoding="utf-8")
        (src / "HYU VPN.app" / "Contents" / "Info.plist").write_text("plist", encoding="utf-8")
        (src / "HYU VPN.app" / "Contents" / "Resources").mkdir()
        (src / "HYU VPN.app" / "Contents" / "Resources" / "AppIcon.icns").write_bytes(b"menu icon")
        (src / "Install HYU VPN.app" / "Contents" / "MacOS").mkdir(parents=True)
        (src / "Install HYU VPN.app" / "Contents" / "MacOS" / "HYUVPNInstallerApp").write_text("installer", encoding="utf-8")
        (src / "Install HYU VPN.app" / "Contents" / "Info.plist").write_text("installer plist", encoding="utf-8")
        (src / "Install HYU VPN.app" / "Contents" / "Resources").mkdir()
        (src / "Install HYU VPN.app" / "Contents" / "Resources" / "AppIcon.icns").write_bytes(b"installer icon")
        (src / "installer").mkdir()
        (src / "README-lab.md").write_text("HYU VPN lab package uses native GUI authorization before root commit.\n", encoding="utf-8")
        (src / "installer" / "root-admin.sh").write_text("root-admin.sh", encoding="utf-8")
        runtime = src / "runtime"
        for rel in [
            "openconnect/bin/openconnect",
            "oathtool",
            "openconnect/lib/libopenconnect.5.dylib",
            "gp-hip-report",
            "vpnc/vpnc-script",
            "vpnc/hyu-vpnc-wrapper",
            "vpnc/hyu-vpnc-wrapperd",
        ]:
            path = runtime / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(rel, encoding="utf-8")
            path.chmod(0o755)
        for rel in [
            "hyu-vpn-macos-service",
            "com.hyu.vpn.helper",
        ]:
            path = src / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(rel, encoding="utf-8")
            path.chmod(0o755)
        for rel in ["launchd/com.hyu.vpn.service.plist.in"]:
            path = src / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(rel, encoding="utf-8")
        (src / "config").mkdir(exist_ok=True)
        (src / "THIRD_PARTY_NOTICES.txt").write_text(
            "OpenConnect\nLicense: LGPL-2.1-only\nSource: https://www.openconnect-vpn.net/\n\n"
            "oath-toolkit\nLicense: GPL-3.0-or-later\nSource: https://www.nongnu.org/oath-toolkit/\n\n"
            "vpnc-script\nLicense: GPL-2.0-or-later\nSource: https://gitlab.com/openconnect/vpnc-scripts\n\n"
            "LGPL source offer: source is available from the URLs above.\n"
            "GPL source offer: source is available from the URLs above.\n",
            encoding="utf-8",
        )
        (src / "SOURCE-OFFER.txt").write_text("Corresponding source available at listed upstream URLs.\n", encoding="utf-8")
        return src


class NativeAppAssemblyTests(PackagingTestCase):
    def test_native_app_assemblers_inject_strict_release_version_and_update_policy(self):
        inputs = self.root / "native-inputs"
        inputs.mkdir()
        menu_executable = inputs / "HYUVPNMenuApp"
        credential_reader = inputs / "hyu-vpn-credential-reader"
        installer_executable = inputs / "HYUVPNInstallerApp"
        for executable in (menu_executable, credential_reader, installer_executable):
            executable.write_bytes(Path("/usr/bin/true").read_bytes())
            executable.chmod(0o755)

        menu_output = self.root / "menu-output"
        installer_output = self.root / "installer-output"
        for script, executable, output in (
            (ASSEMBLE_MENU_APP, menu_executable, menu_output),
            (ASSEMBLE_INSTALLER_APP, installer_executable, installer_output),
        ):
            output.mkdir()
            completed = subprocess.run([str(script), str(executable), str(output), "0.1.1"], text=True, capture_output=True)
            self.assertEqual(completed.returncode, 0, completed.stderr)

        with (menu_output / "HYU VPN.app/Contents/Info.plist").open("rb") as stream:
            menu_info = __import__("plistlib").load(stream)
        with (installer_output / "Install HYU VPN.app/Contents/Info.plist").open("rb") as stream:
            installer_info = __import__("plistlib").load(stream)
        for info in (menu_info, installer_info):
            self.assertEqual(info["CFBundleShortVersionString"], "0.1.1")
            self.assertEqual(info["CFBundleVersion"], "0.1.1")
        self.assertEqual(menu_info["HYUUpdateFeedURL"], "https://raw.githubusercontent.com/IRCVLab/EZ-HYU-VPN/main/update.json")
        self.assertEqual(menu_info["HYUUpdateAllowedReleaseHost"], "github.com")
        self.assertEqual(menu_info["HYUUpdateAllowedReleasePathPrefix"], "/IRCVLab/EZ-HYU-VPN/releases/")

    def test_native_app_assemblers_reject_non_semantic_versions(self):
        executable = self.root / "HYUVPNInstallerApp"
        executable.write_bytes(Path("/usr/bin/true").read_bytes())
        executable.chmod(0o755)
        for version in ("v0.1.1", "01.1.1", "1.2", "1.2.3-beta", "1.2.3.4"):
            output = self.root / ("invalid-" + version.replace("/", "_"))
            output.mkdir()
            completed = subprocess.run([str(ASSEMBLE_INSTALLER_APP), str(executable), str(output), version], text=True, capture_output=True)
            self.assertEqual(completed.returncode, 64)
            self.assertIn("invalid semantic version", completed.stderr)

    def test_public_update_feed_points_to_current_release(self):
        feed = json.loads((REPO / "update.json").read_text(encoding="utf-8"))
        self.assertEqual(set(feed), {"schema_version", "version", "release_url"})
        self.assertEqual(feed["schema_version"], 1)
        self.assertEqual(feed["version"], "0.2.10")
        self.assertEqual(feed["release_url"], "https://github.com/IRCVLab/EZ-HYU-VPN/releases/tag/macos-v0.2.10-internal")


class FakeOtoolRunner:
    def __init__(self, outputs):
        self.outputs = outputs
        self.argv = []

    def run(self, argv):
        self.argv.append(list(argv))
        raw = str(Path(argv[-1]))
        if raw in self.outputs:
            return self.outputs[raw]
        return self.outputs[str(Path(argv[-1]).resolve())]


class RuntimeClosureTests(PackagingTestCase):
    def test_discovers_openconnect_and_oathtool_non_system_closure_with_absolute_otool(self):
        oc = self.root / "Cellar/openconnect/9.21/bin/openconnect"
        oc_dep = self.root / "Cellar/openconnect/9.21/lib/libopenconnect.5.dylib"
        oath = self.root / "Cellar/oath-toolkit/2.6.14_3/bin/oathtool"
        oath_dep = self.root / "Cellar/oath-toolkit/2.6.14_3/lib/liboath.0.dylib"
        for path in [oc, oc_dep, oath, oath_dep]:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(path.name, encoding="utf-8")
        outputs = {
            str(oc.resolve()): f"{oc}:\n\t{oc_dep} (compatibility version 1.0.0, current version 1.0.0)\n\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1.0.0)\n",
            str(oc_dep.resolve()): f"{oc_dep}:\n\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1.0.0)\n",
            str(oath.resolve()): f"{oath}:\n\t{oath_dep} (compatibility version 1.0.0, current version 1.0.0)\n",
            str(oath_dep.resolve()): f"{oath_dep}:\n",
        }
        runner = FakeOtoolRunner(outputs)
        closure = RuntimeClosurePlanner(runner).discover([oc, oath])
        self.assertEqual([path.name for path in closure][:2], ["openconnect", "oathtool"])
        self.assertIn(oc_dep.resolve(), closure)
        self.assertIn(oath_dep.resolve(), closure)
        self.assertTrue(all(argv[:2] == ["/usr/bin/otool", "-L"] for argv in runner.argv))
        self.assertEqual(copied_runtime_rel(oc, [oc, oath]), "runtime/openconnect/bin/openconnect")
        self.assertEqual(copied_runtime_rel(oath_dep, [oc, oath]), "runtime/openconnect/lib/liboath.0.dylib")
        copied = copy_runtime_closure(closure, [oc, oath], self.build_root / "payload")
        self.assertEqual(copied[str(oc.resolve())], "runtime/openconnect/bin/openconnect")
        self.assertTrue((self.build_root / "payload/runtime/openconnect/lib/liboath.0.dylib").exists())

    def test_preserves_dependency_install_name_basename_for_symlinked_homebrew_libs(self):
        oc = self.root / "Cellar/openconnect/9.21/bin/openconnect"
        real_dep = self.root / "Cellar/nettle/4.0/lib/libhogweed.7.0.dylib"
        alias_dep = self.root / "opt/nettle/lib/libhogweed.7.dylib"
        oc.parent.mkdir(parents=True, exist_ok=True)
        real_dep.parent.mkdir(parents=True, exist_ok=True)
        alias_dep.parent.mkdir(parents=True, exist_ok=True)
        oc.write_text("openconnect", encoding="utf-8")
        real_dep.write_text("hogweed", encoding="utf-8")
        alias_dep.symlink_to(real_dep)
        outputs = {
            str(oc.resolve()): f"{oc}:\n\t{alias_dep} (compatibility version 7.0.0, current version 7.0.0)\n",
            str(alias_dep): f"{alias_dep}:\n",
        }
        closure = RuntimeClosurePlanner(FakeOtoolRunner(outputs)).discover([oc])
        self.assertIn(alias_dep, closure)
        payload = self.build_root / "payload"
        copy_runtime_closure(closure, [oc], payload)
        copied = payload / "runtime/openconnect/lib/libhogweed.7.dylib"
        self.assertTrue(copied.exists())
        self.assertFalse(copied.is_symlink())
        self.assertEqual(copied.read_text(encoding="utf-8"), "hogweed")
        self.assertEqual(loader_replacement_for("runtime/openconnect/bin/openconnect", str(alias_dep)), "@loader_path/../lib/libhogweed.7.dylib")
        verify_rewrite_target_exists(payload, "runtime/openconnect/bin/openconnect", str(alias_dep))

    def test_copy_runtime_closure_dedupes_same_alias_and_real_source_without_recopy(self):
        real_dep = self.root / "Cellar/nettle/4.0/lib/libhogweed.7.0.dylib"
        alias_dep = self.root / "opt/nettle/lib/libhogweed.7.dylib"
        real_dep.parent.mkdir(parents=True, exist_ok=True)
        alias_dep.parent.mkdir(parents=True, exist_ok=True)
        real_dep.write_text("hogweed", encoding="utf-8")
        alias_dep.symlink_to(real_dep)
        payload = self.build_root / "payload-dedupe"
        copied = copy_runtime_closure([alias_dep, real_dep, alias_dep], [], payload)
        self.assertEqual(copied[str(alias_dep)], "runtime/openconnect/lib/libhogweed.7.dylib")
        self.assertEqual((payload / "runtime/openconnect/lib/libhogweed.7.dylib").read_text(encoding="utf-8"), "hogweed")


class DestinationGuardTests(PackagingTestCase):
    def test_rejects_root_repo_system_symlink_and_existing_foreign_directories(self):
        for bad in [Path("/"), REPO, Path("/Applications"), Path("/Library")]:
            with self.subTest(path=bad), self.assertRaises(PackagingError):
                guard_destination(bad, allowed_root=self.build_root)
        link = self.root / "link"
        link.symlink_to(self.build_root)
        with self.assertRaises(PackagingError):
            guard_destination(link, allowed_root=self.build_root)
        foreign = self.root / "foreign"
        foreign.mkdir()
        with self.assertRaises(PackagingError):
            guard_destination(foreign, allowed_root=self.build_root)

    def test_allows_only_absent_or_empty_directory_inside_explicit_root(self):
        target = self.build_root / "release"
        self.assertEqual(guard_destination(target, allowed_root=self.build_root), target.resolve(strict=False))
        target.mkdir()
        self.assertEqual(guard_destination(target, allowed_root=self.build_root), target.resolve(strict=False))
        (target / "old.txt").write_text("x", encoding="utf-8")
        with self.assertRaises(PackagingError):
            guard_destination(target, allowed_root=self.build_root)

    @unittest.skipUnless(sys.platform == "darwin", "macOS /tmp resolves through /private/tmp")
    def test_allows_unresolved_system_var_alias_but_rejects_user_symlink_ancestor(self):
        canonical_tmp = Path(tempfile.mkdtemp(prefix="hyu-var-alias-", dir="/private/tmp"))
        self.addCleanup(lambda: subprocess.run(["/bin/rm", "-rf", str(canonical_tmp)]))
        unresolved = Path(str(canonical_tmp).replace("/private/tmp/", "/tmp/", 1))
        (unresolved / "build").mkdir()
        target = unresolved / "build" / "release"
        self.assertEqual(guard_destination(target, allowed_root=unresolved / "build"), target.resolve(strict=False))
        user_link = self.root / "user-link"
        user_link.symlink_to(unresolved / "build")
        with self.assertRaises(PackagingError):
            guard_destination(user_link / "release", allowed_root=user_link)

    @unittest.skipUnless(sys.platform == "darwin", "macOS /private path policy")
    def test_guard_root_rejects_private_non_temp_locations(self):
        for bad in [Path("/private"), Path("/private/var"), Path("/private/var/db"), Path("/private/etc")]:
            with self.subTest(path=bad), self.assertRaises(PackagingError):
                guard_root(bad)
        self.assertEqual(guard_root(Path("/tmp/hyu-vpn-safe-root")).as_posix(), "/private/tmp/hyu-vpn-safe-root")

    def test_native_assemblers_refuse_repo_root_and_symlink_destinations_before_building(self):
        fixture = self.root / "fixture"
        (fixture / "source").mkdir(parents=True)
        (fixture / "source" / "main.swift").write_text("print(\"x\")\n", encoding="utf-8")
        for script in [ASSEMBLE_MENU_APP, ASSEMBLE_INSTALLER_APP]:
            with self.subTest(script=script.name, destination="repo"):
                arguments = [str(script), str(fixture), str(REPO)]
                arguments.append("0.1.1")
                proc = subprocess.run(arguments, text=True, capture_output=True)
                self.assertNotEqual(proc.returncode, 0)
                self.assertIn("unsafe destination", proc.stderr)
            link = self.root / f"{script.name}.link"
            link.symlink_to(self.build_root)
            with self.subTest(script=script.name, destination="symlink"):
                arguments = [str(script), str(fixture), str(link)]
                arguments.append("0.1.1")
                proc = subprocess.run(arguments, text=True, capture_output=True)
                self.assertNotEqual(proc.returncode, 0)
                self.assertIn("unsafe destination", proc.stderr)

    def test_native_assemblers_allow_empty_descendants_of_repo_target(self):
        target_root = REPO / "target"
        target_root.mkdir(exist_ok=True)
        for script in [ASSEMBLE_MENU_APP, ASSEMBLE_INSTALLER_APP]:
            destination = Path(tempfile.mkdtemp(prefix="assembler-safe-", dir=target_root))
            self.addCleanup(destination.rmdir)
            proc = subprocess.run(
                [str(script), str(target_root / "missing-executable"), str(destination), "0.1.1"],
                text=True, capture_output=True,
            )
            self.assertEqual(proc.returncode, 66, proc.stderr)
            self.assertIn("missing executable", proc.stderr)
            self.assertNotIn("unsafe destination", proc.stderr)



class NoticeTests(PackagingTestCase):
    def test_lab_readme_matches_current_safe_activation_contract(self):
        text = (REPO / "packaging" / "README-lab.md").read_text(encoding="utf-8")
        self.assertNotIn("RunAtLoad=false", text)
        self.assertNotIn("are not bootstrapped during the install transaction", text)
        self.assertNotIn("auto-reconnect=false", text)
        self.assertNotIn("starts idle", text)
        self.assertIn("native GUI distribution", text)
        self.assertIn("auto-reconnect enabled", text)
        self.assertNotIn("hyu-vpn-native-client", text)
        self.assertIn("FINAL-RUNTIME-BINDING.json", text)
        self.assertIn("canonical pre-rewrite/pre-sign", text)

    def test_repository_notices_are_distribution_ready_not_placeholders(self):
        validate_third_party_notices(REPO / "packaging" / "THIRD_PARTY_NOTICES.txt", ["OpenConnect", "oath-toolkit", "vpnc-script"])
        text = (REPO / "packaging" / "THIRD_PARTY_NOTICES.txt").read_text(encoding="utf-8")
        for component in ["libopenconnect", "liboath", "libp11-kit", "libstoken", "libgnutls", "libhogweed", "libnettle", "libgmp", "libintl", "libidn2", "libtasn1", "libtomcrypt", "libtommath", "libunistring"]:
            self.assertIn(component, text)
        self.assertTrue((REPO / "packaging" / "SOURCE-OFFER.txt").exists())

    def test_notice_validation_rejects_template_todo_and_missing_source_offer(self):
        bad = self.root / "bad-notices.txt"
        bad.write_text("template TODO\nOpenConnect\nLicense: LGPL-2.1-only\n", encoding="utf-8")
        with self.assertRaises(PackagingError):
            validate_third_party_notices(bad, ["OpenConnect", "oath-toolkit", "vpnc-script"])


class ReleaseBuilderTests(PackagingTestCase):

    def test_lab_readme_documents_native_gui_installer_without_legacy_terminal_claims(self):
        text = (REPO / "packaging" / "README-lab.md").read_text(encoding="utf-8")
        self.assertIn("Install HYU VPN.app", text)
        self.assertIn("native GUI distribution", text)
        self.assertIn("single macOS administrator authorization", text)
        self.assertIn("AES-GCM", text)
        self.assertIn("Keychain and its authorization prompts are not used", text)
        self.assertIn("auto-reconnect enabled", text)
        self.assertIn("No Terminal installer or uninstaller is packaged", text)
        self.assertIn("AES-GCM encrypted document", text)
        for obsolete in [
            "Install HYU VPN.command",
            "Uninstall HYU VPN.command",
            "defaults to package audit",
            "Re-run with --live-install",
            "auto-reconnect=false",
            "starts idle",
            "Menu LaunchAgent",
            "/usr/bin/security -w",
        ]:
            self.assertNotIn(obsolete, text)

    def test_installer_harness_executes_as_packaging_gate(self):
        proc = subprocess.run(["swift", "run", "--package-path", str(REPO / "macos"), "hyu-vpn-installer-harness"], text=True, capture_output=True, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        self.assertIn("HARNESS PASS", proc.stdout)


    def test_native_installer_source_uses_gui_authorization_not_terminal_or_sudo(self):
        source = (REPO / "macos/Sources/HYUVPNInstallerApp/main.swift").read_text(encoding="utf-8")
        core_source = (REPO / "macos/Sources/HYUVPNInstallerCore/InstallerCore.swift").read_text(encoding="utf-8")
        self.assertIn("NSAlert", source)
        self.assertIn("with administrator privileges", core_source)
        self.assertIn("on run argv", core_source)
        self.assertIn("do shell script (item 1 of argv) with administrator privileges", core_source)
        self.assertIn("RootAdminAuthorizationScript.makeOSAScriptArgv", source)
        self.assertIn("root-admin.sh", source)
        self.assertIn("NativePayloadManifest.verify", source)
        self.assertIn("NativePayloadManifest.stage", source)
        self.assertIn("EncryptedCredentialStore", source)
        self.assertIn("InstallerCredentialBootstrapper", source)
        self.assertIn("RootAdminInvocation.makeInstallArgv", source)
        self.assertIn("RootAdminAuthorizer.authorizeOnce", source)
        self.assertIn("SUDO_USER=", core_source)
        self.assertIn("SUDO_UID=", core_source)
        self.assertIn("INSTALL_FAILED_ROOT_AUTHORIZATION_OR_TRANSACTION", core_source)
        self.assertIn("CredentialValidator.validate", core_source)
        self.assertEqual(source.count("try runWithAdministratorPrivileges(argv)"), 1)
        self.assertNotIn("/usr/bin/security", source)
        self.assertNotIn("/usr/bin/security", core_source)
        self.assertNotIn("/usr/bin/sudo", source)
        self.assertNotIn("Terminal.app", source)
        self.assertNotIn("Install HYU VPN.command", source)
        self.assertNotIn("InstallerError.commandFailed(output", source)
        self.assertNotIn("String(data:", source)
        self.assertNotIn("String(reflecting:", source)
        self.assertIn("Installed with menu-start warning", source)
        self.assertIn("Open /Applications/HYU VPN.app manually", source)
        self.assertIn("ACTIVATION_FAILED_CREDENTIAL_CLEANUP_INCOMPLETE", source)
        self.assertIn("bestEffortDeactivateUserService", source)
        self.assertNotIn("standardError = pipe", source)
        self.assertNotIn("private func validateUsername", source)
        self.assertNotIn("private func validatePassword", source)
        self.assertNotIn("private func validateTOTPSeed", source)
        self.assertIn("stopExistingMenubar", source)
        self.assertIn("waitForMenubarExit", source)
        self.assertIn("waitForSingleMenubar", source)
        self.assertIn("-KILL", source)
        self.assertLess(source.index("try stopExistingMenubar"), source.index("/usr/bin/open"))
        self.assertLess(source.index("/usr/bin/open"), source.index("waitForSingleMenubar"))


    def test_installer_uses_encrypted_file_store_after_root_install(self):
        app_source = (REPO / "macos/Sources/HYUVPNInstallerApp/main.swift").read_text(encoding="utf-8")
        adapter_source = (REPO / "macos/Sources/HYUVPNMenuApp/SystemAdapters.swift").read_text(encoding="utf-8")

        self.assertIn("InstallerEncryptedCredentialStore", app_source)
        self.assertIn("EncryptedCredentialStore", adapter_source)
        self.assertIn("package func contains(_ key: CredentialKey)", adapter_source)
        self.assertIn("AES.GCM.seal", adapter_source)
        self.assertIn("AES.GCM.open", adapter_source)
        self.assertNotIn("import Security", adapter_source)
        self.assertNotIn("SecItem", adapter_source)
        self.assertLess(app_source.index("runWithAdministratorPrivileges(argv)"), app_source.index("writeCollectedCredentials"))
        self.assertLess(app_source.index("writeCollectedCredentials"), app_source.index("try activateUserSession"))
        self.assertNotIn("HYUVPNInstallerCore", adapter_source)

    def test_final_runtime_binding_bridges_canonical_bundle_to_mutated_shipped_runtime(self):
        src = self.make_payload_source()
        runtime_files = {
            rel: src / rel for rel in [
                "runtime/openconnect/bin/openconnect",
                "runtime/oathtool",
                "runtime/openconnect/lib/libopenconnect.5.dylib",
                "runtime/vpnc/vpnc-script",
            ]
        }
        bundle = self.make_source_bundle(runtime_files=runtime_files)
        packaged_bundle = src / "SOURCE-COMPLIANCE-BUNDLE.tar.gz"
        packaged_bundle.write_bytes(bundle.read_bytes())
        packaging_module.validate_source_bundle_matches_payload(packaged_bundle, src)

        openconnect = src / "runtime/openconnect/bin/openconnect"
        openconnect.write_bytes(openconnect.read_bytes() + b"-rewritten-and-signed")
        with self.assertRaisesRegex(
            PackagingError,
            r"runtime closure mismatch: changed=\['runtime/openconnect/bin/openconnect'\] extras=\[\] missing=\[\]",
        ):
            packaging_module.validate_source_bundle_matches_payload(packaged_bundle, src)

        binding = packaging_module.write_final_runtime_binding(packaged_bundle, src)
        packaging_module.validate_final_runtime_binding(binding, packaged_bundle, src)
        data = json.loads(binding.read_text(encoding="utf-8"))
        self.assertEqual(data["source_compliance_bundle"]["semantics"], "canonical-pre-rewrite-pre-sign")
        self.assertEqual(data["source_compliance_bundle"]["scope"], "third-party-runtime-corresponding-source-only")
        final_entry = next(item for item in data["files"] if item["path"] == "runtime/openconnect/bin/openconnect")
        self.assertNotEqual(final_entry["canonical_sha256"], final_entry["final_sha256"])

        openconnect.write_bytes(openconnect.read_bytes() + b"-post-binding-tamper")
        with self.assertRaisesRegex(PackagingError, "final runtime binding mismatch"):
            packaging_module.validate_final_runtime_binding(binding, packaged_bundle, src)

    def test_rebind_source_bundle_updates_exact_runtime_hashes_and_internal_checksums(self):
        src = self.make_payload_source()
        runtime_files = {
            rel: src / rel for rel in [
                "runtime/openconnect/bin/openconnect",
                "runtime/oathtool",
                "runtime/openconnect/lib/libopenconnect.5.dylib",
                "runtime/vpnc/vpnc-script",
            ]
        }
        bundle = self.make_source_bundle(runtime_files=runtime_files)
        packaged_bundle = src / "SOURCE-COMPLIANCE-BUNDLE.tar.gz"
        packaged_bundle.write_bytes(bundle.read_bytes())
        base_sha = packaging_module._sha256(packaged_bundle)
        openconnect = src / "runtime/openconnect/bin/openconnect"
        openconnect.write_bytes(openconnect.read_bytes() + b"-different-homebrew-bottle")

        packaging_module.rebind_source_compliance_bundle(packaged_bundle, src)

        packaging_module.validate_source_compliance_bundle(packaged_bundle)
        packaging_module.validate_source_bundle_matches_payload(packaged_bundle, src)
        with tarfile.open(packaged_bundle, "r:gz") as tf:
            build_info = tf.extractfile("build-info.txt").read().decode("utf-8")
        self.assertIn(base_sha, build_info)
        self.assertIn("runtime hashes rebound", build_info)

    def test_rebind_source_bundle_refuses_changed_noncompiled_resource(self):
        src = self.make_payload_source()
        runtime_files = {
            rel: src / rel for rel in [
                "runtime/openconnect/bin/openconnect",
                "runtime/oathtool",
                "runtime/openconnect/lib/libopenconnect.5.dylib",
                "runtime/vpnc/vpnc-script",
            ]
        }
        bundle = self.make_source_bundle(runtime_files=runtime_files)
        packaged_bundle = src / "SOURCE-COMPLIANCE-BUNDLE.tar.gz"
        packaged_bundle.write_bytes(bundle.read_bytes())
        vpnc = src / "runtime/vpnc/vpnc-script"
        vpnc.write_bytes(vpnc.read_bytes() + b"-tampered")
        with self.assertRaisesRegex(PackagingError, "noncompiled source resource mismatch"):
            packaging_module.rebind_source_compliance_bundle(packaged_bundle, src)

    def test_homebrew_runtime_provenance_requires_exact_bundle_formula_kegs(self):
        cellar = self.root / "Cellar"
        oc = cellar / "openconnect/9.21/bin/openconnect"
        oath = cellar / "oath-toolkit/2.6.14_3/bin/oathtool"
        lib = cellar / "openconnect/9.21/lib/libopenconnect.5.dylib"
        for path in (oc, oath, lib):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(path.name.encode())
        bundle = self.make_source_bundle(runtime_files={
            "runtime/openconnect/bin/openconnect": oc,
            "runtime/oathtool": oath,
            "runtime/openconnect/lib/libopenconnect.5.dylib": lib,
            "runtime/vpnc/vpnc-script": self.make_payload_source() / "runtime/vpnc/vpnc-script",
        })
        packaging_module.validate_homebrew_runtime_provenance(
            bundle, [oc, oath, lib], [oc, oath],
            allowed_cellars=[cellar, self.root / "absent-cellar"],
        )

        wrong = cellar / "openconnect/9.22/lib/libopenconnect.5.dylib"
        wrong.parent.mkdir(parents=True, exist_ok=True)
        wrong.write_bytes(lib.read_bytes())
        with self.assertRaisesRegex(PackagingError, "runtime source keg mismatch"):
            packaging_module.validate_homebrew_runtime_provenance(
                bundle, [oc, oath, wrong], [oc, oath], allowed_cellars=[cellar]
            )

    def test_build_creates_a_missing_explicit_output_root(self):
        src = self.make_payload_source()
        missing_output = self.root / "new-output-root"

        result = ReleaseBuilder(ReleaseToolchain(fake=True)).build(
            source_payload=src,
            build_root=self.build_root,
            output_root=missing_output,
            version="0.1.0-output-root-test",
            arch="arm64",
        )

        self.assertEqual(result.dmg_path.parent, missing_output)
        self.assertTrue(result.dmg_path.is_file())


    def test_signed_installer_app_code_resources_is_allowed_and_manifested(self):
        src = self.make_payload_source()
        code_resources = src / "Install HYU VPN.app/Contents/_CodeSignature/CodeResources"
        code_resources.parent.mkdir(parents=True)
        code_resources.write_text("signed-installer-seal\n", encoding="utf-8")

        result = ReleaseBuilder(ReleaseToolchain(fake=True)).build(
            source_payload=src,
            build_root=self.build_root,
            output_root=self.output_root,
            version="0.1.0-signed-installer-test",
            arch="arm64",
        )

        self.assertIn("Install HYU VPN.app/Contents/_CodeSignature/CodeResources", result.manifest["files"])

    def test_installer_failure_ui_logs_sanitized_operation_codes(self):
        source = (REPO / "macos/Sources/HYUVPNInstallerApp/main.swift").read_text(encoding="utf-8")
        self.assertIn("~/Library/Logs/HYU VPN/installer.log", source)
        self.assertIn("appendInstallerLog", source)
        self.assertIn("HYU VPN/installer.log", source)
        self.assertIn("Operation code:", source)
        self.assertIn("0600", source)
        self.assertNotIn("standardError = pipe", source)
        self.assertNotIn("String(data:", source)
        self.assertNotIn("String(reflecting:", source)
        self.assertIn("Installed with menu-start warning", source)
        self.assertIn("Open /Applications/HYU VPN.app manually", source)
        self.assertIn("ACTIVATION_FAILED_CREDENTIAL_CLEANUP_INCOMPLETE", source)
        self.assertIn("bestEffortDeactivateUserService", source)

    def test_signed_menu_app_code_resources_is_allowed_and_manifested(self):
        src = self.make_payload_source()
        code_resources = src / "HYU VPN.app/Contents/_CodeSignature/CodeResources"
        code_resources.parent.mkdir(parents=True)
        code_resources.write_text("signed-app-seal\n", encoding="utf-8")

        result = ReleaseBuilder(ReleaseToolchain(fake=True)).build(
            source_payload=src,
            build_root=self.build_root,
            output_root=self.output_root,
            version="0.1.0-signed-app-test",
            arch="arm64",
        )

        self.assertIn(
            "HYU VPN.app/Contents/_CodeSignature/CodeResources",
            result.manifest["files"],
        )

    def test_stages_exact_payload_manifest_metadata_checksums_and_dmg_contents(self):
        src = self.make_payload_source()
        toolchain = ReleaseToolchain(fake=True)
        result = ReleaseBuilder(toolchain).build(
            source_payload=src,
            build_root=self.build_root,
            output_root=self.output_root,
            version="0.1.0-test",
            arch="arm64",
        )
        self.assertTrue(result.dmg_path.exists())
        self.assertTrue(result.checksum_path.exists())
        self.assertEqual(result.metadata["architecture"], "arm64")
        self.assertFalse(result.metadata["notarized"])
        self.assertEqual(result.metadata["signing"], "ad-hoc")
        self.assertNotIn("prerequisites", result.metadata)
        self.assertNotIn("python_runtime_contract", result.metadata)
        self.assertIn("bundle exact GPL/LGPL source archives", result.metadata["release_blockers"][0])
        self.assertEqual(result.manifest["schema"], 1)
        self.assertEqual(result.manifest_path.name, "manifest.json")
        files = set(result.manifest["files"])
        expected = {
            "HYU VPN.app/Contents/MacOS/HYUVPNMenuApp",
            "HYU VPN.app/Contents/MacOS/HYUVPNCredentialReader",
            "HYU VPN.app/Contents/Info.plist",
            "HYU VPN.app/Contents/Resources/AppIcon.icns",
            "Install HYU VPN.app/Contents/MacOS/HYUVPNInstallerApp",
            "Install HYU VPN.app/Contents/Info.plist",
            "Install HYU VPN.app/Contents/Resources/AppIcon.icns",
            "README-lab.md",
            "installer/root-admin.sh",
            "runtime/openconnect/bin/openconnect",
            "runtime/oathtool",
            "runtime/openconnect/lib/libopenconnect.5.dylib",
            "runtime/gp-hip-report",
            "runtime/vpnc/vpnc-script",
            "runtime/vpnc/hyu-vpnc-wrapper",
            "runtime/vpnc/hyu-vpnc-wrapperd",
            "hyu-vpn-macos-service",
            "com.hyu.vpn.helper",
            "launchd/com.hyu.vpn.service.plist.in",
            "THIRD_PARTY_NOTICES.txt",
            "SOURCE-OFFER.txt",
            "release-metadata.json",
        }
        self.assertEqual(files, expected)
        self.assertNotIn("/opt/homebrew", json.dumps(result.manifest, sort_keys=True))
        self.assertRegex(result.checksum_path.read_text(encoding="utf-8"), r"^[0-9a-f]{64}  HYU-VPN-0.1.0-test-arm64.dmg\n$")
        rewrite_actions = [action for action in toolchain.actions if action.startswith("rewrite:")]
        self.assertEqual(rewrite_actions[:5], [
            "rewrite:runtime/openconnect/bin/openconnect",
            "rewrite:runtime/openconnect/lib/libopenconnect.5.dylib",
            "rewrite:runtime/oathtool",
            "rewrite:runtime/vpnc/hyu-vpnc-wrapperd",
            "rewrite:com.hyu.vpn.helper",
        ])
        self.assertIn("rewrite:HYU VPN.app/Contents/MacOS/HYUVPNMenuApp", rewrite_actions)
        self.assertIn("rewrite:HYU VPN.app/Contents/MacOS/HYUVPNCredentialReader", rewrite_actions)
        self.assertIn("rewrite:Install HYU VPN.app/Contents/MacOS/HYUVPNInstallerApp", rewrite_actions)
        self.assertLess(toolchain.actions.index("sign:HYU VPN.app/Contents/MacOS/HYUVPNMenuApp"), toolchain.actions.index("sign:HYU VPN.app"))
        self.assertLess(toolchain.actions.index("sign:HYU VPN.app/Contents/MacOS/HYUVPNCredentialReader"), toolchain.actions.index("sign:HYU VPN.app"))
        self.assertLess(toolchain.actions.index("sign:Install HYU VPN.app/Contents/MacOS/HYUVPNInstallerApp"), toolchain.actions.index("sign:Install HYU VPN.app"))
        self.assertLess(toolchain.actions.index("sign:com.hyu.vpn.helper"), toolchain.actions.index("sign:HYU VPN.app"))
        self.assertIn("verify-dmg", toolchain.actions)
        self.assertIn("attach-readonly", toolchain.actions)
        self.assertIn("detach", toolchain.actions)
        self.assertNotIn("payload-manifest.json", result.manifest["files"])



    def test_macos_release_payload_contains_rust_service_and_no_python_backend(self):
        src = self.make_payload_source()
        result = ReleaseBuilder(ReleaseToolchain(fake=True)).build(
            source_payload=src,
            build_root=self.build_root,
            output_root=self.output_root,
            version="0.1.0-test",
            arch="arm64",
        )

        files = set(result.manifest["files"])
        self.assertIn("hyu-vpn-macos-service", files)
        for forbidden in [
            "hyu-vpn-service",
            "hyu-vpn-control",
            "hyu-vpn-connect",
        ]:
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, files)
        self.assertFalse(any(rel == "src/hyu_vpn" or rel.startswith("src/hyu_vpn/") for rel in files))

    def test_release_payload_exposes_native_installer_app_and_no_terminal_launchers(self):
        src = self.make_payload_source()
        result = ReleaseBuilder(ReleaseToolchain(fake=True)).build(
            source_payload=src,
            build_root=self.build_root,
            output_root=self.output_root,
            version="0.1.0-gui-installer",
            arch="arm64",
        )

        files = set(result.manifest["files"])
        self.assertIn(INSTALLER_EXEC_REL, files)
        self.assertIn("Install HYU VPN.app/Contents/Info.plist", files)
        self.assertNotIn("Install HYU VPN.command", files)
        self.assertNotIn("Uninstall HYU VPN.command", files)
        self.assertNotIn("installer/install.sh", files)
        self.assertNotIn("installer/uninstall.sh", files)
        self.assertEqual(result.metadata["installer_ux"], "native-gui-no-terminal")
        self.assertEqual(result.metadata["administrator_authorization"], "macos-ui-once")

    def test_fake_package_manifest_verifies_and_current_task7_audit_passes(self):
        src = self.make_payload_source()
        result = ReleaseBuilder(ReleaseToolchain(fake=True)).build(
            source_payload=src,
            build_root=self.build_root,
            output_root=self.output_root,
            version="0.1.0-test",
            arch="arm64",
        )
        verify = subprocess.run([
            sys.executable, str(INSTALLER_MANIFEST),
            "--payload", str(result.stage_dir),
            "--manifest", str(result.manifest_path),
            "--verify-manifest",
        ], text=True, capture_output=True)
        self.assertEqual(verify.returncode, 0, verify.stderr)
        audit = subprocess.run([
            sys.executable, str(INSTALLER_MANIFEST),
            "--payload", str(result.stage_dir),
            "--manifest", str(result.manifest_path),
            "--package-audit",
        ], text=True, capture_output=True)
        self.assertEqual(audit.returncode, 0, audit.stderr)

    def test_mounted_validation_rejects_hash_mode_or_size_mismatch(self):
        src = self.make_payload_source()
        toolchain = ReleaseToolchain(fake=True, tamper_mounted_file="README-lab.md")
        with self.assertRaises(PackagingError):
            ReleaseBuilder(toolchain).build(
                source_payload=src,
                build_root=self.build_root,
                output_root=self.output_root,
                version="0.1.0-test",
                arch="arm64",
            )
        self.assertIn("detach", toolchain.actions)

    def test_version_tokens_reject_traversal_and_control_characters(self):
        src = self.make_payload_source()
        for version in ["../x", "bad/name", "bad\nname"]:
            with self.subTest(version=version), self.assertRaises(PackagingError):
                ReleaseBuilder(ReleaseToolchain(fake=True)).build(
                    source_payload=src, build_root=self.build_root, output_root=self.output_root, version=version, arch="arm64"
                )

    def test_rewrite_replacements_match_task7_staged_runtime_layout(self):
        self.assertEqual(loader_replacement_for("runtime/openconnect/bin/openconnect", "/opt/homebrew/lib/liboath.0.dylib"), "@loader_path/../lib/liboath.0.dylib")
        self.assertEqual(loader_replacement_for("runtime/oathtool", "/opt/homebrew/lib/liboath.0.dylib"), "@loader_path/../lib/liboath.0.dylib")
        self.assertEqual(loader_replacement_for("runtime/openconnect/lib/libopenconnect.5.dylib", "/opt/homebrew/lib/libgnutls.30.dylib"), "@loader_path/libgnutls.30.dylib")
        with self.assertRaises(PackagingError):
            loader_replacement_for("com.hyu.vpn.helper", "/opt/homebrew/lib/libbad.dylib")

    def test_real_toolchain_records_absolute_tool_argv_in_dry_boundary_mode(self):
        toolchain = ReleaseToolchain(fake=True)
        self.assertEqual(toolchain.command_plan("sign", Path("/tmp/app")), ["/usr/bin/codesign", "--force", "--sign", "-", "/tmp/app"])
        self.assertEqual(toolchain.command_plan("verify_dmg", Path("/tmp/a.dmg")), ["/usr/bin/hdiutil", "verify", "/tmp/a.dmg"])
        self.assertEqual(toolchain.command_plan("lipo_archs", Path("/tmp/a")), ["/usr/bin/lipo", "-archs", "/tmp/a"])

    def test_primary_mount_validation_error_survives_detach_failure(self):
        src = self.make_payload_source()
        toolchain = ReleaseToolchain(fake=True, tamper_mounted_file="README-lab.md", detach_fails=True)
        with self.assertRaisesRegex(PackagingError, "mounted manifest content mismatch|hash/mode/size mismatch"):
            ReleaseBuilder(toolchain).build(
                source_payload=src, build_root=self.build_root, output_root=self.output_root, version="0.1.0-test", arch="arm64"
            )
        self.assertIn("detach", toolchain.actions)

    def test_cleanup_detaches_readonly_mount_when_validation_fails(self):
        src = self.make_payload_source()
        toolchain = ReleaseToolchain(fake=True, fail_mounted_validation=True)
        with self.assertRaises(PackagingError):
            ReleaseBuilder(toolchain).build(
                source_payload=src,
                build_root=self.build_root,
                output_root=self.output_root,
                version="0.1.0-test",
                arch="arm64",
            )
        self.assertIn("attach-readonly", toolchain.actions)
        self.assertIn("detach", toolchain.actions)


    def test_repo_payload_assembler_rejects_nested_app_symlink_before_copying_outside_file(self):
        oc = self.root / "runtime-inputs/openconnect"
        oath = self.root / "runtime-inputs/oathtool"
        vpnc = self.root / "runtime-inputs/vpnc-script"
        service = self.root / "build-products/hyu-vpn-macos-service"
        hip = self.root / "build-products/hyu-vpn-hip"
        helper = self.root / "build-products/com.hyu.vpn.helper"
        wrapperd = self.root / "build-products/hyu-vpnc-wrapperd"
        app = self.root / "build-products/HYU VPN.app"
        installer_app = self.root / "build-products/Install HYU VPN.app"
        outside = self.root / "outside-secret.txt"
        outside.write_text("secret", encoding="utf-8")
        for path in [oc, oath, vpnc, service, hip, helper, wrapperd, app / "Contents/MacOS/HYUVPNMenuApp", app / "Contents/MacOS/HYUVPNCredentialReader", app / "Contents/Info.plist", app / "Contents/Resources/AppIcon.icns", installer_app / "Contents/MacOS/HYUVPNInstallerApp", installer_app / "Contents/Info.plist", installer_app / "Contents/Resources/AppIcon.icns"]:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(path.name, encoding="utf-8")
            path.chmod(0o755)
        (app / "Contents/Resources").mkdir(exist_ok=True)
        (app / "Contents/Resources/outside-link").symlink_to(outside)
        outputs = {str(oc.resolve()): f"{oc}:\n", str(oath.resolve()): f"{oath}:\n"}
        with self.assertRaisesRegex(PackagingError, "symlink"):
            assemble_payload_from_repo(
                repo_root=REPO, payload_root=self.build_root / "repo-payload", openconnect=oc, oathtool=oath, service_executable=service, hip_executable=hip,
                vpnc_script=vpnc, helper_executable=helper, wrapperd_executable=wrapperd, menu_app=app, installer_app=installer_app, closure_runner=FakeOtoolRunner(outputs),
            )
        self.assertFalse((self.build_root / "repo-payload/HYU VPN.app/Contents/Resources/outside-link").exists())

    def test_source_payload_rejects_extras_and_symlinks_in_contract(self):
        src = self.make_payload_source()
        (src / "unexpected.txt").write_text("extra", encoding="utf-8")
        with self.assertRaises(PackagingError):
            ReleaseBuilder(ReleaseToolchain(fake=True)).build(
                source_payload=src,
                build_root=self.build_root,
                output_root=self.output_root,
                version="0.1.0-test",
                arch="arm64",
            )

    def test_no_stale_preinstall_runtime_manifest_or_helper_hash_template_in_release(self):
        src = self.make_payload_source()
        result = ReleaseBuilder(ReleaseToolchain(fake=True)).build(
            source_payload=src,
            build_root=self.build_root,
            output_root=self.output_root,
            version="0.1.0-test",
            arch="arm64",
        )
        self.assertNotIn("config/final-runtime-manifest.json", result.manifest["files"])
        self.assertNotIn("config/helper-config.template.json", result.manifest["files"])
        self.assertNotIn("task7_followups", result.metadata)


class ReleaseCliTests(PackagingTestCase):
    def test_source_compliance_bundle_validation_rejects_malicious_members(self):
        from release_packaging import validate_source_compliance_bundle
        for malicious in ["absolute", "traversal", "symlink", "unchecked_extra", "bad_checksum_format", "missing_inventory_reference", "duplicate_key_inventory"]:
            with self.subTest(malicious=malicious), self.assertRaises(PackagingError):
                case_root = self.root / malicious
                case_root.mkdir()
                old_root = self.root
                self.root = case_root
                try:
                    validate_source_compliance_bundle(self.make_source_bundle(malicious=malicious))
                finally:
                    self.root = old_root

    def test_assemble_from_repo_copies_explicit_source_compliance_bundle(self):
        oc = self.root / "runtime-inputs/openconnect"
        oath = self.root / "runtime-inputs/oathtool"
        vpnc = self.root / "runtime-inputs/vpnc-script"
        service = self.root / "build-products/hyu-vpn-macos-service"
        hip = self.root / "build-products/hyu-vpn-hip"
        helper = self.root / "build-products/com.hyu.vpn.helper"
        wrapperd = self.root / "build-products/hyu-vpnc-wrapperd"
        app = self.root / "build-products/HYU VPN.app"
        installer_app = self.root / "build-products/Install HYU VPN.app"
        for path in [oc, oath, vpnc, service, hip, helper, wrapperd, app / "Contents/MacOS/HYUVPNMenuApp", app / "Contents/MacOS/HYUVPNCredentialReader", app / "Contents/Info.plist", app / "Contents/Resources/AppIcon.icns", installer_app / "Contents/MacOS/HYUVPNInstallerApp", installer_app / "Contents/Info.plist", installer_app / "Contents/Resources/AppIcon.icns"]:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(path.name, encoding="utf-8")
            path.chmod(0o755)
        bundle = self.make_source_bundle()
        payload = assemble_payload_from_repo(
            repo_root=REPO, payload_root=self.build_root / "repo-payload-with-source",
            openconnect=oc, oathtool=oath, service_executable=service, hip_executable=hip, vpnc_script=vpnc, helper_executable=helper, wrapperd_executable=wrapperd, menu_app=app, installer_app=installer_app,
            source_compliance_bundle=bundle, closure_runner=FakeOtoolRunner({str(oc.resolve()): f"{oc}:\n", str(oath.resolve()): f"{oath}:\n"}),
        )
        self.assertEqual((payload / "SOURCE-COMPLIANCE-BUNDLE.tar.gz").read_bytes(), bundle.read_bytes())
        self.assertFalse((payload / "installer" / "install.sh").exists())
        self.assertFalse((payload / "installer" / "uninstall.sh").exists())
        self.assertTrue((payload / INSTALLER_EXEC_REL).is_file())
        self.assertFalse((payload / "Install HYU VPN.command").exists())
        self.assertFalse((payload / "Uninstall HYU VPN.command").exists())

    def test_non_fake_release_requires_source_compliance_bundle_before_real_tools(self):
        src = self.make_payload_source()
        with self.assertRaisesRegex(PackagingError, "SOURCE-COMPLIANCE-BUNDLE"):
            ReleaseBuilder(ReleaseToolchain(fake=False)).build(
                source_payload=src, build_root=self.build_root, output_root=self.output_root, version="0.1.0-test", arch="arm64"
            )


    def test_real_source_bundle_runtime_closure_must_match_payload_runtime_files(self):
        src = self.make_payload_source()
        bundle = self.make_source_bundle()
        (src / "SOURCE-COMPLIANCE-BUNDLE.tar.gz").write_bytes(bundle.read_bytes())
        with self.assertRaisesRegex(PackagingError, "runtime closure mismatch"):
            ReleaseBuilder(ReleaseToolchain(fake=False)).build(
                source_payload=src, build_root=self.build_root, output_root=self.output_root, version="0.1.0-test", arch="arm64"
            )

    def test_real_source_bundle_runtime_closure_match_clears_bundle_gate_then_reaches_real_tool_boundary(self):
        src = self.make_payload_source()
        runtime_files = {
            rel: src / rel for rel in [
                "runtime/openconnect/bin/openconnect", "runtime/oathtool", "runtime/openconnect/lib/libopenconnect.5.dylib", "runtime/vpnc/vpnc-script"
            ]
        }
        bundle = self.make_source_bundle(runtime_files=runtime_files)
        (src / "SOURCE-COMPLIANCE-BUNDLE.tar.gz").write_bytes(bundle.read_bytes())
        with self.assertRaisesRegex(PackagingError, "not exactly arm64"):
            ReleaseBuilder(ReleaseToolchain(fake=False)).build(
                source_payload=src, build_root=self.build_root, output_root=self.output_root, version="0.1.0-test", arch="arm64"
            )

    def test_metadata_has_no_release_blockers_when_source_bundle_present(self):
        src = self.make_payload_source()
        runtime_files = {
            rel: src / rel for rel in [
                "runtime/openconnect/bin/openconnect",
                "runtime/oathtool",
                "runtime/openconnect/lib/libopenconnect.5.dylib",
                "runtime/vpnc/vpnc-script",
            ]
        }
        bundle = self.make_source_bundle(runtime_files=runtime_files)
        (src / "SOURCE-COMPLIANCE-BUNDLE.tar.gz").write_bytes(bundle.read_bytes())
        result = ReleaseBuilder(ReleaseToolchain(fake=True)).build(
            source_payload=src,
            build_root=self.build_root,
            output_root=self.output_root,
            version="0.1.0-test",
            arch="arm64",
            git_commit="a" * 40,
        )
        self.assertEqual(result.metadata["release_blockers"], [])
        self.assertEqual(result.metadata["final_runtime_binding"], "FINAL-RUNTIME-BINDING.json")
        self.assertEqual(result.metadata["git_commit"], "a" * 40)
        self.assertEqual(result.metadata["source_compliance_bundle_scope"], "third-party-runtime-corresponding-source-only")
        self.assertIn("FINAL-RUNTIME-BINDING.json", result.manifest["files"])
        self.assertNotIn("task7_followups", result.metadata)

    def test_invalid_git_commit_is_rejected(self):
        src = self.make_payload_source()

        with self.assertRaisesRegex(PackagingError, "git commit"):
            ReleaseBuilder(ReleaseToolchain(fake=True)).build(
                source_payload=src,
                build_root=self.build_root,
                output_root=self.output_root,
                version="0.1.0-test",
                arch="arm64",
                git_commit="not-a-sha",
            )

    def test_cli_without_fake_tools_fails_closed_before_claiming_dmg(self):
        src = self.make_payload_source()
        proc = subprocess.run([
            str(PACKAGE_RELEASE),
            "--source-payload", str(src),
            "--build-root", str(self.build_root),
            "--output-root", str(self.output_root),
            "--version", "0.1.0-test",
            "--arch", "arm64",
        ], text=True, capture_output=True)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("SOURCE-COMPLIANCE-BUNDLE", proc.stderr)

    def test_cli_fake_build_accepts_unresolved_tmp_roots(self):
        src = self.make_payload_source()
        canonical_tmp = Path(tempfile.mkdtemp(prefix="hyu-cli-var-", dir="/private/tmp"))
        self.addCleanup(lambda: subprocess.run(["/bin/rm", "-rf", str(canonical_tmp)]))
        unresolved = Path(str(canonical_tmp).replace("/private/tmp/", "/tmp/", 1))
        (unresolved / "build").mkdir()
        (unresolved / "out").mkdir()
        proc = subprocess.run([
            str(PACKAGE_RELEASE), "--fake-tools", "--source-payload", str(src),
            "--build-root", str(unresolved / "build"), "--output-root", str(unresolved / "out"),
            "--version", "0.1.0-test", "--arch", "arm64",
        ], text=True, capture_output=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_cli_fake_build_uses_strict_payload_contract_and_writes_checksum(self):
        src = self.make_payload_source()
        proc = subprocess.run([
            str(PACKAGE_RELEASE),
            "--fake-tools",
            "--source-payload", str(src),
            "--build-root", str(self.build_root),
            "--output-root", str(self.output_root),
            "--version", "0.1.0-test",
            "--arch", "arm64",
        ], text=True, capture_output=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        data = json.loads(proc.stdout)
        self.assertTrue(Path(data["dmg"]).exists())
        self.assertTrue(Path(data["checksum"]).exists())

    def test_cli_assemble_from_repo_accepts_source_compliance_bundle(self):
        oc = self.root / "runtime-inputs/openconnect"
        oath = self.root / "runtime-inputs/oathtool"
        vpnc = self.root / "runtime-inputs/vpnc-script"
        service = self.root / "build-products/hyu-vpn-macos-service"
        hip = self.root / "build-products/hyu-vpn-hip"
        helper = self.root / "build-products/com.hyu.vpn.helper"
        wrapperd = self.root / "build-products/hyu-vpnc-wrapperd"
        app = self.root / "build-products/HYU VPN.app"
        installer_app = self.root / "build-products/Install HYU VPN.app"
        for path in [oc, oath, vpnc, service, hip, helper, wrapperd, app / "Contents/MacOS/HYUVPNMenuApp", app / "Contents/MacOS/HYUVPNCredentialReader", app / "Contents/Info.plist", app / "Contents/Resources/AppIcon.icns", installer_app / "Contents/MacOS/HYUVPNInstallerApp", installer_app / "Contents/Info.plist", installer_app / "Contents/Resources/AppIcon.icns"]:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(path.name, encoding="utf-8")
            path.chmod(0o755)
        bundle = self.make_source_bundle(runtime_files={
            "runtime/openconnect/bin/openconnect": oc,
            "runtime/oathtool": oath,
            "runtime/vpnc/vpnc-script": vpnc,
        })
        proc = subprocess.run([
            str(PACKAGE_RELEASE),
            "--fake-tools",
            "--assemble-from-repo",
            "--repo-root", str(REPO),
            "--openconnect", str(oc),
            "--oathtool", str(oath),
            "--vpnc-script", str(vpnc),
            "--service-executable", str(service),
            "--hip-executable", str(hip),
            "--helper-executable", str(helper),
            "--wrapperd-executable", str(wrapperd),
            "--menu-app", str(app),
            "--installer-app", str(installer_app),
            "--source-compliance-bundle", str(bundle),
            "--build-root", str(self.build_root),
            "--output-root", str(self.output_root),
            "--version", "0.1.0-test",
            "--arch", "arm64",
        ], text=True, capture_output=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        data = json.loads(proc.stdout)
        stage = Path(data["stage"])
        self.assertTrue(stage.exists())
        self.assertTrue((stage / "SOURCE-COMPLIANCE-BUNDLE.tar.gz").exists())
        self.assertRegex(data["git_commit"], r"^[0-9a-f]{40}$")
        metadata = json.loads((stage / "release-metadata.json").read_text(encoding="utf-8"))
        self.assertEqual(metadata["git_commit"], data["git_commit"])
        self.assertEqual(metadata["source_compliance_bundle_scope"], "third-party-runtime-corresponding-source-only")
        binding = json.loads((stage / "FINAL-RUNTIME-BINDING.json").read_text(encoding="utf-8"))
        self.assertEqual(binding["source_compliance_bundle"]["scope"], "third-party-runtime-corresponding-source-only")



    def test_mounted_validation_scans_recursive_text_payload_not_only_manifest_and_launchd(self):
        payload = self.make_payload_source()
        root_admin = payload / "installer" / "root-admin.sh"
        root_admin.write_text("#!/bin/sh\necho hyu-vpn-native-client\n", encoding="utf-8")
        root_admin.chmod(0o755)
        with self.assertRaisesRegex(PackagingError, "mounted text payload contains forbidden legacy token"):
            ReleaseBuilder(ReleaseToolchain(fake=True)).build(
                source_payload=payload,
                build_root=self.root / "mounted recursive build",
                output_root=self.root / "mounted recursive dist",
                version="1.2.3",
                arch="arm64",
                git_commit="a" * 40,
            )

    def test_mounted_validation_rejects_split_python_path_evasions_in_payload_text(self):
        payload = self.make_payload_source()
        root_admin = payload / "installer" / "root-admin.sh"
        root_admin.write_text('PYTHON3_PATH="/usr/bin/py"; PYTHON3_PATH="${PYTHON3_PATH}thon3"\nexec "$PYTHON3_PATH"\n', encoding="utf-8")
        root_admin.chmod(0o755)
        with self.assertRaisesRegex(PackagingError, "forbidden legacy token"):
            ReleaseBuilder(ReleaseToolchain(fake=True)).build(
                source_payload=payload,
                build_root=self.root / "mounted split python build",
                output_root=self.root / "mounted split python dist",
                version="1.2.5",
                arch="arm64",
                git_commit="c" * 40,
            )

class Task7ReviewRegressionTests(unittest.TestCase):
    def test_release_builder_treats_rust_service_as_macho_signed_artifact(self):
        text = (REPO / "scripts/release_packaging.py").read_text(encoding="utf-8")
        self.assertIn('"hyu-vpn-macos-service"', text[text.index('def mach_o_payload_files'):text.index('class ReleaseBuilder')])

    def test_release_assembly_forbids_legacy_native_client_payload(self):
        text = (REPO / "scripts/release_packaging.py").read_text(encoding="utf-8")
        for forbidden in ["hyu-vpn-native-client", "src/hyu_vpn"]:
            self.assertNotIn(forbidden, text)

if __name__ == "__main__":
    unittest.main()
