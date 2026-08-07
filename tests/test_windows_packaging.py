import re
import unittest
from pathlib import Path
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
WXS = ROOT / "packaging" / "windows" / "Product.wxs"
SCRIPT = ROOT / "scripts" / "package-windows.ps1"
NOTICE = ROOT / "packaging" / "windows" / "THIRD_PARTY_NOTICES.txt"
OPENCONNECT_PATCH = ROOT / "packaging" / "windows" / "openconnect-windows-hip.patch"
OPENCONNECT_BUILD = ROOT / "scripts" / "build-openconnect-windows.sh"
WINDOWS_WORKFLOW = ROOT / ".github" / "workflows" / "windows.yml"
OPENCONNECT_HIP_TEST = ROOT / "scripts" / "test-openconnect-windows-hip.sh"
OPENCONNECT_FAKE_SERVER = ROOT / "scripts" / "fake-gp-hip-server.py"
PINNED_VPNC_SCRIPT = ROOT / "packaging" / "windows" / "vpnc-script-win.js"
RUNTIME = {
    "iconv.dll", "libgcc_s_seh-1.dll", "libgmp-10.dll", "libgnutls-30.dll",
    "libhogweed-6.dll", "libintl-8.dll", "liblz4.dll", "libnettle-8.dll",
    "libopenconnect-5.dll", "libstoken-1.dll", "libtasn1-6.dll",
    "libwinpthread-1.dll", "libxml2-2.dll", "list-system-keys.exe",
    "openconnect.exe", "vpnc-script-win.js", "wintun.dll", "zlib1.dll",
}

class WindowsPackagingTests(unittest.TestCase):
    def test_wix_installs_service_recovery_and_private_state(self):
        text = WXS.read_text(encoding="utf-8")
        root = ET.fromstring(text)
        ns = {"w": "http://wixtoolset.org/schemas/v4/wxs",
              "u": "http://wixtoolset.org/schemas/v4/wxs/util"}
        service = root.find(".//w:ServiceInstall", ns)
        self.assertEqual(service.attrib["Name"], "HYUVPN")
        self.assertEqual(service.attrib["Start"], "auto")
        self.assertEqual(service.attrib["Account"], "LocalSystem")
        control = root.find(".//w:ServiceControl", ns)
        self.assertEqual((control.attrib["Start"], control.attrib["Stop"], control.attrib["Remove"]),
                         ("install", "both", "uninstall"))
        recovery = root.find(".//u:ServiceConfig", ns)
        self.assertEqual(recovery.attrib["FirstFailureActionType"], "restart")
        permissions = root.findall(".//w:CreateFolder/u:PermissionEx", ns)
        self.assertEqual({p.attrib["User"] for p in permissions}, {"SYSTEM", "Administrators"})
        self.assertTrue(all(p.attrib["GenericAll"] == "yes" for p in permissions))
        self.assertNotIn("password", text.lower())
        self.assertNotIn("totp_seed", text.lower())

    def test_wix_preserves_encrypted_state_during_major_upgrade(self):
        root = ET.fromstring(WXS.read_text(encoding="utf-8"))
        ns = {"w": "http://wixtoolset.org/schemas/v4/wxs"}
        state = root.find('.//w:Component[@Id="StateDirectoryComponent"]', ns)
        self.assertIsNotNone(state)
        self.assertRegex(state.attrib["Guid"], r"^[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}$")
        self.assertNotEqual(state.attrib["Guid"], "*")
        self.assertIsNone(state.find("w:RemoveFile", ns))
        self.assertIsNone(state.find("w:RemoveFolder", ns))
        workflow = WINDOWS_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("upgrade-preservation-canary", workflow)
        self.assertIn("-Version '0.2.1'", workflow)
        self.assertIn("Encrypted state was not preserved across MSI major upgrade", workflow)

    def test_script_pins_hashes_and_copies_exact_runtime(self):
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("jobs/14877945030/artifacts", text)
        self.assertGreaterEqual(len(re.findall(r"'([0-9a-f]{64})'", text)), 2)
        self.assertIn("Assert-Sha256 $OpenConnectArtifactZip", text)
        self.assertIn("Assert-Sha256 $OpenConnectInstaller", text)
        listed = set(re.findall(r"^\s*'([^']+\.(?:dll|exe|js))',?$", text, re.MULTILINE))
        self.assertEqual(listed, RUNTIME)
        self.assertIn("cargo build --locked --release", text)
        self.assertIn("$WixPath msi validate", text)
        for forbidden in ("credentials.enc", "credentials.dpapi", "totp-counter"):
            self.assertNotIn(forbidden, text)

    def test_wix_declares_runtime_and_notice_source_offer(self):
        declared = set(re.findall(r"runtime\\([^\"$]+)", WXS.read_text(encoding="utf-8")))
        self.assertEqual(declared, RUNTIME)
        notice = NOTICE.read_text(encoding="utf-8")
        self.assertIn("OpenConnect v9.21", notice)
        self.assertIn("Source:", notice)
        self.assertIn("openconnect-windows-hip.patch", notice)
        self.assertIn("ef0c875f3f8d8cc00e9647f36f87f2dd7d4ccad02c47c82f2dc5ba6b37edab06", notice)
        self.assertIn("OPENCONNECT-PATCHED-SHA256SUMS.txt", WXS.read_text(encoding="utf-8"))
        self.assertIn("artifact-manifest.sha256", notice)

    def test_patched_openconnect_build_is_pinned_tested_and_packaged(self):
        patch = OPENCONNECT_PATCH.read_text(encoding="utf-8")
        build = OPENCONNECT_BUILD.read_text(encoding="utf-8")
        package = SCRIPT.read_text(encoding="utf-8")
        workflow = WINDOWS_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("OPTION(\"csd-wrapper\"", patch)
        self.assertIn("CreateProcessW", patch)
        self.assertIn("TerminateProcess", patch)
        self.assertIn("ReadFile", patch)
        self.assertIn("PROC_THREAD_ATTRIBUTE_HANDLE_LIST", patch)
        self.assertIn("--cookie-on-stdin", patch)
        self.assertNotIn('win32_append_hip_argument(command, "--cookie")', patch)
        self.assertIn("CancelSynchronousIo", patch)
        self.assertIn("WIN32_HIP_READER_TIMEOUT_MS", patch)
        self.assertIn("--client-os", patch)
        self.assertIn("openconnect-v9.21.tar.gz", build)
        self.assertIn("ef0c875f3f8d8cc00e9647f36f87f2dd7d4ccad02c47c82f2dc5ba6b37edab06", build)
        self.assertIn("git -C \"$SOURCE_DIR\" apply --check -p1", build)
        self.assertIn("e196fdf0cc8b325180154535f843034dc0ae9eb43ead9980adfcfc57c58069b2", build)
        self.assertTrue(PINNED_VPNC_SCRIPT.is_file())
        self.assertIn("make VERBOSE=1", build)
        self.assertIn("check", build)
        self.assertIn("openconnect.exe", build)
        self.assertIn("libopenconnect-5.dll", build)
        self.assertIn("PatchedOpenConnectDirectory", package)
        self.assertIn("Assert-PatchedOpenConnect", package)
        self.assertIn("registry.gitlab.com/openconnect/build-images@sha256:ea03ac6c281cb137382e9069b26b96cce972242adf632d96adb8fd0cb0a9be2c", workflow)
        self.assertIn("build-openconnect-windows.sh", workflow)
        self.assertIn("download-artifact", workflow)

    def test_openconnect_hip_patch_has_wine_end_to_end_test(self):
        test = OPENCONNECT_HIP_TEST.read_text(encoding="utf-8")
        build = OPENCONNECT_BUILD.read_text(encoding="utf-8")
        workflow = WINDOWS_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("fake-gp-hip-server.py", test)
        server = OPENCONNECT_FAKE_SERVER.read_text(encoding="utf-8")
        self.assertIn("ThreadingHTTPServer", server)
        self.assertIn("/ssl-vpn/hipreport.esp", server)
        self.assertIn("x86_64-w64-mingw32-gcc", test)
        self.assertIn("winepath -w", test)
        self.assertIn("--csd-wrapper", test)
        self.assertIn("hipreport.esp", server)
        self.assertIn("HIP report submitted successfully", test)
        self.assertIn("test-openconnect-windows-hip.sh", build)
        self.assertNotIn("dnf install", workflow)
        self.assertNotIn("python3-flask", workflow)
        self.assertNotIn("docker run --rm --privileged", workflow)
        self.assertIn("--security-opt no-new-privileges", workflow)
        self.assertIn("--proto '=https'", OPENCONNECT_BUILD.read_text(encoding="utf-8"))
        self.assertIn("--tlsv1.2", OPENCONNECT_BUILD.read_text(encoding="utf-8"))

    def test_windows_ipc_and_credential_ui_are_hardened(self):
        service = (ROOT / "rust/apps/hyu-vpn-windows-service/src/runtime.rs").read_text(encoding="utf-8")
        client = (ROOT / "rust/apps/hyu-vpn-windows-tray/src/client.rs").read_text(encoding="utf-8")
        dialog = (ROOT / "rust/apps/hyu-vpn-windows-tray/src/main.rs").read_text(encoding="utf-8")
        storage = (ROOT / "rust/crates/hyu-vpn-platform-windows/src/storage.rs").read_text(encoding="utf-8")
        process = (ROOT / "rust/crates/hyu-vpn-platform-windows/src/process.rs").read_text(encoding="utf-8")
        self.assertIn("first_pipe_instance(true)", service)
        self.assertIn("authorize_pipe_server_system", client)
        self.assertIn("edit_style | ES_PASSWORD as u32", dialog)
        self.assertGreaterEqual(dialog.count("edit_style | ES_PASSWORD as u32"), 2)
        self.assertIn("key_copy.as_mut_ptr()", storage)
        self.assertIn("request_graceful_termination", process)
        self.assertIn("GenerateConsoleCtrlEvent", process)

    def test_icon_is_multi_resolution_ico(self):
        raw = (ROOT / "packaging" / "windows" / "hyu-vpn.ico").read_bytes()
        self.assertGreater(len(raw), 4096)
        self.assertEqual(raw[:4], bytes([0, 0, 1, 0]))
        self.assertGreaterEqual(int.from_bytes(raw[4:6], "little"), 8)

if __name__ == "__main__":
    unittest.main()
