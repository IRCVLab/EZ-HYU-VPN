import json
import os
import plistlib
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hyu_vpn.hip_cli import main as hip_main
from hyu_vpn.hip_contract import CookieIdentity, HipInvocation
from hyu_vpn.hip_xml import HostInfo, MacPosture, NetworkInterface, Product, build_hip_xml
from hyu_vpn.macos_posture import CommandResult, MacPostureCollector
from hyu_vpn.control import AutoReconnectPreference
from hyu_vpn.supervisor import Supervisor, SupervisorConfig

ROOT = Path(__file__).resolve().parents[1]
FAKE_OATHTOOL = ROOT / "tests" / "helpers" / "fake_oathtool.py"
NATIVE_FIXTURE = ROOT / "tests" / "fixtures" / "native_hip_sanitized.xml"
GP_HIP_REPORT = ROOT / "bin" / "gp-hip-report"


def _write_executable(path: Path, source: str) -> None:
    dedented = textwrap.dedent(source).lstrip()
    lines = [line[16:] if line.startswith(" " * 16) else line for line in dedented.splitlines()]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    path.chmod(0o755)


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _wait_for(predicate, *, timeout: float = 5.0) -> None:
    deadline = time.time() + timeout
    last_error = None
    while time.time() < deadline:
        try:
            if predicate():
                return
        except Exception as exc:
            last_error = exc
        time.sleep(0.02)
    if last_error is not None:
        raise AssertionError(f"timed out waiting for offline integration condition; last error: {last_error!r}")
    raise AssertionError("timed out waiting for offline integration condition")


def _path_signature(root: ET.Element) -> set[str]:
    paths = set()

    def walk(node: ET.Element, path: str) -> None:
        name = node.attrib.get("name")
        suffix = f"[@name='{name}']" if name and node.tag == "entry" else ""
        current = f"{path}/{node.tag}{suffix}" if path else f"/{node.tag}{suffix}"
        paths.add(current)
        for child in list(node):
            walk(child, current)

    walk(root, "")
    return paths


class OfflineEndToEndTests(unittest.TestCase):
    def test_real_subprocess_connector_invokes_fake_hip_wrapper_establishes_and_tears_down_group(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            marker = root / "openconnect.json"
            wrapper_marker = root / "wrapper.json"
            runner_marker = root / "runner.json"
            oathtool_state = root / "oathtool.json"
            oathtool_state.write_text(json.dumps({"values": ["111111", "222222"]}), encoding="utf-8")
            fake_wrapper = root / "fake_hip_wrapper.py"
            fake_openconnect = root / "fake_openconnect.py"
            runner = root / "run_session.py"

            _write_executable(fake_wrapper, r'''
                import json, os, sys, xml.etree.ElementTree as ET
                from pathlib import Path
                marker = Path(os.environ["E2E_WRAPPER_MARKER"])
                argv = sys.argv[1:]
                xml = b"""<?xml version="1.0" encoding="utf-8"?>
<hip-report name="hip-report"><generate-time>08/04/2026 01:02:03</generate-time><categories><entry name="host-info"><host-name>HOST &amp; &lt;safe&gt;</host-name></entry></categories></hip-report>"""
                ET.fromstring(xml)
                marker.write_text(json.dumps({"argv": argv, "root": "hip-report", "paths": ["/hip-report/categories/entry[@name='host-info']"]}, sort_keys=True), encoding="utf-8")
                sys.stdout.buffer.write(xml)
            ''')
            _write_executable(fake_openconnect, r'''
                #!/usr/bin/env python3
                import json, os, signal, subprocess, sys, time, xml.etree.ElementTree as ET
                from pathlib import Path
                marker = Path(os.environ["E2E_MARKER"])
                wrapper_marker = Path(os.environ["E2E_WRAPPER_MARKER"])
                responses = []
                established = False
                def snapshot(**extra):
                    payload = {"argv": sys.argv[1:], "responses": responses, "pid": os.getpid(), "pgid": os.getpgrp(), "established": established}
                    payload.update(extra)
                    marker.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
                def handler(signum, _frame):
                    snapshot(signal=signum)
                    raise SystemExit(0)
                signal.signal(signal.SIGTERM, handler)
                signal.signal(signal.SIGINT, handler)
                def read_line():
                    line = sys.stdin.readline()
                    if line == "":
                        raise SystemExit(7)
                    responses.append(line.rstrip("\n"))
                    snapshot()
                    return responses[-1]
                def write_prompt(text):
                    os.write(sys.stdout.fileno(), text.encode("utf-8")); sys.stdout.flush()
                snapshot()
                read_line()
                write_prompt("Chal"); time.sleep(0.02); write_prompt("lenge:")
                read_line()
                write_prompt("Pass"); time.sleep(0.02); write_prompt("word:")
                read_line()
                write_prompt("Challenge:")
                read_line()
                wrapper = next(arg.split("=", 1)[1] for arg in sys.argv[1:] if arg.startswith("--csd-wrapper="))
                wrapper_argv = [sys.executable, wrapper, "--cookie", "user=E2E-USER&domain=E2E-DOMAIN&computer=E2E-HOST", "--md5", "0123456789abcdef0123456789abcdef", "--client-ip", "192.0.2.200", "--client-ipv6", "2001:db8::200", "--client-os", "mac"]
                completed = subprocess.run(wrapper_argv, capture_output=True, check=False, timeout=5)
                root = ET.fromstring(completed.stdout)
                established = completed.returncode == 0 and root.tag == "hip-report"
                snapshot(wrapper_rc=completed.returncode, wrapper_stdout_len=len(completed.stdout))
                os.write(sys.stdout.fileno(), b"HIP report submitted successfully.\nconnected\n")
                while True:
                    time.sleep(0.1)
            ''')
            _write_executable(runner, r'''
                import json, os, sys
                from pathlib import Path
                sys.path.insert(0, sys.argv[1])
                from hyu_vpn.connector import ConnectorConfig, PromptSession, build_openconnect_argv
                from hyu_vpn.otp import TotpProvider
                marker = Path(os.environ["E2E_RUNNER_MARKER"])
                argv = build_openconnect_argv("E2E-USER", config=ConnectorConfig(openconnect_path=sys.argv[2], hip_wrapper=sys.argv[3], sudo_path=None))
                provider = TotpProvider("SEED-CANARY", oathtool_path=sys.argv[4], environ=os.environ)
                rc = PromptSession(argv, password="PASSWORD-CANARY", totp_provider=provider, environ=os.environ, stdout=None, stderr=None, terminate_timeout=1.0).run()
                marker.write_text(json.dumps({"rc": rc}, sort_keys=True), encoding="utf-8")
                raise SystemExit(rc)
            ''')
            env = os.environ.copy()
            env.update({
                "E2E_MARKER": str(marker),
                "E2E_WRAPPER_MARKER": str(wrapper_marker),
                "E2E_RUNNER_MARKER": str(runner_marker),
                "FAKE_OATHTOOL_STATE": str(oathtool_state),
            })
            proc = subprocess.Popen([sys.executable, str(runner), str(ROOT / "src"), str(fake_openconnect), str(fake_wrapper), str(FAKE_OATHTOOL)], env=env)
            try:
                try:
                    _wait_for(lambda: marker.exists() and _read_json(marker).get("established"))
                except AssertionError as exc:
                    marker_text = marker.read_text(encoding="utf-8") if marker.exists() else "<missing>"
                    wrapper_text = wrapper_marker.read_text(encoding="utf-8") if wrapper_marker.exists() else "<missing>"
                    raise AssertionError(f"{exc}; marker={marker_text}; wrapper={wrapper_text}; proc={proc.poll()}") from None
                state = _read_json(marker)
                self.assertEqual(state["responses"], ["PASSWORD-CANARY", "111111", "PASSWORD-CANARY", "222222"])
                self.assertTrue(wrapper_marker.exists())
                wrapper_state = _read_json(wrapper_marker)
                self.assertIn("--cookie", wrapper_state["argv"])
                self.assertIn("--client-ip", wrapper_state["argv"])
                self.assertEqual(wrapper_state["root"], "hip-report")
                proc.send_signal(signal.SIGTERM)
                self.assertEqual(proc.wait(timeout=3), 0)
                state = _read_json(marker)
                self.assertEqual(state.get("signal"), signal.SIGTERM)
                with self.assertRaises(ProcessLookupError):
                    os.kill(state["pid"], 0)
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait(timeout=3)

    def test_signal_during_totp_reuse_wait_tears_down_without_orphan(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            marker = root / "openconnect.json"
            runner_marker = root / "runner.json"
            oathtool_state = root / "oathtool.json"
            oathtool_state.write_text(json.dumps({"values": ["111111", "111111", "222222"]}), encoding="utf-8")
            fake_openconnect = root / "fake_openconnect.py"
            runner = root / "run_wait.py"
            _write_executable(fake_openconnect, r'''
                import json, os, signal, sys, time
                from pathlib import Path
                marker = Path(os.environ["WAIT_MARKER"]); responses=[]
                def snap(**extra):
                    payload={"responses": responses, "pid": os.getpid(), "pgid": os.getpgrp()}; payload.update(extra); marker.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
                def handler(signum, _frame): snap(signal=signum); raise SystemExit(0)
                signal.signal(signal.SIGTERM, handler)
                snap()
                for prompt in (None, "Challenge:", "Challenge:"):
                    if prompt:
                        os.write(sys.stdout.fileno(), prompt.encode()); sys.stdout.flush()
                    line=sys.stdin.readline()
                    if not line: raise SystemExit(7)
                    responses.append(line.rstrip("\n")); snap()
                while True: time.sleep(0.1)
            ''')
            _write_executable(runner, r'''
                import json, os, sys, time
                from pathlib import Path
                sys.path.insert(0, sys.argv[1])
                from hyu_vpn.connector import PromptSession
                from hyu_vpn.otp import TotpProvider
                provider = TotpProvider("SEED-CANARY", oathtool_path=sys.argv[3], environ=os.environ, clock=lambda: 1, max_wait=2.0)
                rc = PromptSession([sys.executable, sys.argv[2]], password="PASSWORD-CANARY", totp_provider=provider, environ=os.environ, stdout=None, stderr=None, terminate_timeout=1.0).run()
                Path(os.environ["WAIT_RUNNER_MARKER"]).write_text(json.dumps({"rc": rc}), encoding="utf-8")
                raise SystemExit(rc)
            ''')
            env = os.environ.copy()
            env.update({"WAIT_MARKER": str(marker), "WAIT_RUNNER_MARKER": str(runner_marker), "FAKE_OATHTOOL_STATE": str(oathtool_state)})
            proc = subprocess.Popen([sys.executable, str(runner), str(ROOT / "src"), str(fake_openconnect), str(FAKE_OATHTOOL)], env=env)
            try:
                _wait_for(lambda: json.loads(oathtool_state.read_text(encoding="utf-8")).get("calls", 0) >= 2)
                proc.send_signal(signal.SIGTERM)
                self.assertIn(proc.wait(timeout=3), (0, 1))
                state = _read_json(marker)
                self.assertEqual(state.get("signal"), signal.SIGTERM)
                with self.assertRaises(ProcessLookupError):
                    os.kill(state["pid"], 0)
            finally:
                if proc.poll() is None:
                    proc.kill(); proc.wait(timeout=3)


class OfflineAdversarialTests(unittest.TestCase):
    def test_malformed_cookie_missing_binary_hostile_xml_and_broken_cache_edges_are_safe(self):
        with tempfile.TemporaryDirectory() as td:
            stdout = type("Stdout", (), {"buffer": __import__("io").BytesIO()})()
            stderr = __import__("io").StringIO()
            rc = hip_main(["--cookie", "domain=D&computer=H", "--md5", "m", "--client-ip", "192.0.2.10"], _stdout=stdout, _stderr=stderr)
            self.assertNotEqual(rc, 0)
            self.assertEqual(stdout.buffer.getvalue(), b"")
            self.assertNotIn("domain=D", stderr.getvalue())

            from hyu_vpn.connector import PromptSession
            err = __import__("io").StringIO()
            missing_rc = PromptSession([str(Path(td) / "missing-openconnect")], password="PASSWORD-CANARY", totp_provider=None, stdout=None, stderr=err).run()
            self.assertNotEqual(missing_rc, 0)
            self.assertIn("OpenConnect launch failed", err.getvalue())
            self.assertNotIn("PASSWORD-CANARY", err.getvalue())

            dangerous = "Amp & <tag> > quote ' \" $(rm -rf /) 한글"
            xml = build_hip_xml(
                HipInvocation("COOKIE", "192.0.2.10", None, "m"),
                CookieIdentity(dangerous, "D&<", "H>"),
                MacPosture(host_info=HostInfo(host_name=dangerous, interfaces=(NetworkInterface(name="en&0", description=dangerous, mac_address="00:00:00:00:00:00"),))),
                datetime(2026, 8, 4, tzinfo=timezone.utc),
            )
            parsed = ET.fromstring(xml)
            self.assertEqual(parsed.findtext("user-name"), dangerous)

            cache = Path(td) / "broken-cache.json"
            cache.write_text("not json", encoding="utf-8")
            class Runner:
                def run(self, argv, timeout):
                    if tuple(argv) == ("/usr/sbin/softwareupdate", "--list"):
                        return CommandResult(tuple(argv), 0, "No new software available.\n", "")
                    return CommandResult(tuple(argv), 127, "", "missing")
            posture = MacPostureCollector(runner=Runner(), software_update_cache=cache).collect()
            self.assertEqual(posture.patches, ())
            self.assertEqual(cache.stat().st_mode & 0o777, 0o600)

    def test_rapid_crashes_backoff_and_concurrent_supervisor_lock_are_offline_safe(self):
        with tempfile.TemporaryDirectory() as td:
            crash = Path(td) / "crash.py"
            _write_executable(crash, """#!/usr/bin/env python3\nraise SystemExit(9)\n""")
            sleeps = []
            preference_path = Path(td) / "auto-reconnect.json"
            AutoReconnectPreference(preference_path).write(True)
            config = SupervisorConfig(connect_path=str(crash), lock_path=str(Path(td) / "lock"), status_path=str(Path(td) / "status.json"), preference_path=str(preference_path), control_socket_path=str(Path(td) / "control.sock"), max_iterations=3)
            rc = Supervisor(config, conflict_detector=type("Detector", (), {"conflict_active": lambda self: False})(), sleep=sleeps.append).run()
            self.assertEqual(rc, 9)
            self.assertEqual(sleeps, [10, 20])

            lock = Path(td) / "shared.lock"
            sleeper = Path(td) / "sleeper.py"
            runner = Path(td) / "supervisor_runner.py"
            _write_executable(sleeper, """#!/usr/bin/env python3\nimport time\ntime.sleep(5)\n""")
            _write_executable(runner, r'''
                import sys
                sys.path.insert(0, sys.argv[1])
                from hyu_vpn.supervisor import Supervisor, SupervisorConfig
                class Detector:
                    def conflict_active(self): return False
                raise SystemExit(Supervisor(SupervisorConfig(connect_path=sys.argv[2], lock_path=sys.argv[3], status_path=sys.argv[3] + ".status", preference_path=sys.argv[3] + ".auto", control_socket_path=sys.argv[3] + ".sock", max_iterations=1), conflict_detector=Detector()).run())
            ''')
            AutoReconnectPreference(str(lock) + ".auto").write(True)
            first = subprocess.Popen([sys.executable, str(runner), str(ROOT / "src"), str(sleeper), str(lock)])
            try:
                _wait_for(lambda: lock.exists())
                second = subprocess.run([sys.executable, str(runner), str(ROOT / "src"), str(sleeper), str(lock)], timeout=3, check=False)
                self.assertEqual(second.returncode, 75)
            finally:
                if first.poll() is None:
                    try:
                        first.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        first.kill(); first.wait(timeout=3)

    def test_offline_live_posture_xml_uses_synthetic_inputs_and_native_shape_signature(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / "home"
            cache = home / ".cache" / "hyu-openconnect" / "softwareupdate-cache.json"
            cache.parent.mkdir(parents=True)
            cache.write_text(json.dumps({"created_at": datetime.now(timezone.utc).isoformat(), "patches": []}), encoding="utf-8")
            env = os.environ.copy()
            env.update({"HOME": str(home), "APP_VERSION": "OpenConnect TEST"})
            completed = subprocess.run([
                str(GP_HIP_REPORT),
                "--cookie", "user=SYNTH-USER&domain=SYNTH-DOMAIN&computer=SYNTH-HOST",
                "--md5", "0123456789abcdef0123456789abcdef",
                "--client-ip", "192.0.2.44",
                "--client-ipv6", "2001:db8::44",
                "--client-os", "mac",
            ], env=env, capture_output=True, check=False, timeout=20)
            self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8", "replace"))
            self.assertEqual(completed.stderr, b"")
            generated = ET.fromstring(completed.stdout)
            native = ET.parse(NATIVE_FIXTURE).getroot()
            generated_paths = _path_signature(generated)
            native_paths = _path_signature(native)
            required_paths = {path for path in native_paths if "missing-patches/entry" not in path and "network-interface/entry" not in path}
            self.assertTrue(required_paths.issubset(generated_paths), sorted(required_paths - generated_paths))
            self.assertEqual([node.attrib["name"] for node in generated.findall("./categories/entry")], [node.attrib["name"] for node in native.findall("./categories/entry")])


class DocumentationTests(unittest.TestCase):
    def test_readme_documents_install_prereqs_disabled_service_rollback_and_privacy(self):
        text = (ROOT / "README.md").read_text(encoding="utf-8")
        required = [
            "Install after merge", "Prerequisites", "gp-vpn-username", "gp-vpn-password", "gp-vpn-totp",
            "Foreground use", "service disabled by default", "launchctl", "after live acceptance",
            "Stop and rollback", "Recovery", "Logs and privacy", "no passwords", "no TOTP seeds",
            "no OTP values", "no authentication cookies", "no raw HIP XML", "GlobalProtect is not uninstalled",
        ]
        for phrase in required:
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, text)

    def test_reverse_engineering_doc_is_sanitized_and_covers_evidence_and_limits(self):
        text = (ROOT / "docs" / "reverse-engineering.md").read_text(encoding="utf-8")
        required = [
            "38 native reports", "sanitized evidence", "false-positive schema", "categories/entry",
            "ProductInfo", "dual OTP", "portal Challenge", "gateway Password", "gateway Challenge",
            "HIP flow", "hipreportcheck.esp", "hipreport.esp", "no native runtime dependency",
            "PanGPS", "PanGPA", "PanGpHip", "known PF n/a limitation", "documentation IP ranges",
        ]
        for phrase in required:
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, text)
        forbidden = ["PASSWORD-CANARY", "SEED-CANARY", "AUTHCOOKIE-CANARY"]
        for phrase in forbidden:
            self.assertNotIn(phrase, text)


if __name__ == "__main__":
    unittest.main()
