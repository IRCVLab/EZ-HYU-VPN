import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hyu_vpn.connector import ConnectorConfig, PromptSession, build_openconnect_argv, main
from hyu_vpn.otp import Keychain, TotpError, TotpProvider

ROOT = Path(__file__).resolve().parents[1]
FAKE_OPENCONNECT = ROOT / "tests" / "helpers" / "fake_openconnect.py"
FAKE_OATHTOOL = ROOT / "tests" / "helpers" / "fake_oathtool.py"


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


class ConnectorTests(unittest.TestCase):
    def test_uses_distinct_totp_for_portal_and_gateway(self):
        with tempfile.TemporaryDirectory() as td:
            marker = Path(td) / "openconnect.json"
            oathtool_state = Path(td) / "oathtool.json"
            oathtool_state.write_text(json.dumps({"values": ["111111", "111111", "222222"]}), encoding="utf-8")
            env = {"FAKE_OPENCONNECT_MARKER": str(marker), "FAKE_OATHTOOL_STATE": str(oathtool_state)}
            sleeps = []
            provider = TotpProvider("BASE32-SEED", oathtool_path=str(FAKE_OATHTOOL), environ=env, sleep=sleeps.append, clock=lambda: 1)
            session = PromptSession(
                [sys.executable, str(FAKE_OPENCONNECT)],
                password="PASSWORD-CANARY",
                totp_provider=provider,
                environ=env,
                stdout=None,
            )

            rc = session.run()
            responses = read_json(marker)["responses"]
            oathtool_calls = read_json(oathtool_state)["calls"]

        self.assertEqual(rc, 0)
        self.assertEqual(responses, ["PASSWORD-CANARY", "111111", "PASSWORD-CANARY", "222222"])
        self.assertEqual(oathtool_calls, 3)
        self.assertEqual(sleeps, [29])

    def test_totp_failure_returns_error_without_secret_material(self):
        with tempfile.TemporaryDirectory() as td:
            marker = Path(td) / "openconnect.json"
            oathtool_state = Path(td) / "oathtool.json"
            oathtool_state.write_text(json.dumps({"values": ["__FAIL__"]}), encoding="utf-8")
            env = {"FAKE_OPENCONNECT_MARKER": str(marker), "FAKE_OATHTOOL_STATE": str(oathtool_state)}
            stderr = mock.Mock()
            session = PromptSession(
                [sys.executable, str(FAKE_OPENCONNECT)],
                password="PASSWORD-CANARY",
                totp_provider=TotpProvider("SEED-CANARY", oathtool_path=str(FAKE_OATHTOOL), environ=env, sleep=lambda _s: None),
                environ=env,
                stdout=None,
                stderr=stderr,
                terminate_timeout=0.2,
            )

            rc = session.run()

        self.assertEqual(rc, 1)
        written = "".join(call.args[0] for call in stderr.write.call_args_list)
        self.assertIn("TOTP generation failed", written)
        self.assertNotIn("SEED-CANARY", written)
        self.assertNotIn("PASSWORD-CANARY", written)

    def test_later_identical_bare_challenge_is_a_new_prompt(self):
        with tempfile.TemporaryDirectory() as td:
            marker = Path(td) / "openconnect.json"
            env = {"FAKE_OPENCONNECT_MARKER": str(marker), "FAKE_OPENCONNECT_MODE": "duplicate_prompts"}
            provider = mock.Mock()
            provider.current.side_effect = ["123456", "654321"]
            session = PromptSession([sys.executable, str(FAKE_OPENCONNECT)], password="pw", totp_provider=provider, environ=env, stdout=None)

            rc = session.run()
            responses = read_json(marker)["responses"]

        self.assertEqual(rc, 0)
        self.assertEqual(responses, ["pw", "123456", "654321"])
        self.assertEqual(provider.current.call_count, 2)

    def test_missing_executable_returns_redacted_error(self):
        stderr = mock.Mock()
        session = PromptSession(
            ["/definitely/not/openconnect"],
            password="PASSWORD-CANARY",
            totp_provider=mock.Mock(),
            stdout=None,
            stderr=stderr,
        )

        rc = session.run()

        self.assertNotEqual(rc, 0)
        written = "".join(call.args[0] for call in stderr.write.call_args_list)
        self.assertIn("launch failed", written.lower())
        self.assertNotIn("PASSWORD-CANARY", written)
        self.assertNotIn("/definitely/not/openconnect", written)

    def test_broken_child_stdin_returns_redacted_error_and_reaps_child(self):
        with tempfile.TemporaryDirectory() as td:
            marker = Path(td) / "openconnect.json"
            env = {"FAKE_OPENCONNECT_MARKER": str(marker), "FAKE_OPENCONNECT_MODE": "close_stdin_on_challenge"}
            stderr = mock.Mock()
            provider = mock.Mock()
            provider.current.return_value = "123456"
            session = PromptSession(
                [sys.executable, str(FAKE_OPENCONNECT)],
                password="PASSWORD-CANARY",
                totp_provider=provider,
                environ=env,
                stdout=None,
                stderr=stderr,
                terminate_timeout=0.5,
            )

            rc = session.run()
            child_pid = read_json(marker)["pid"]

        self.assertNotEqual(rc, 0)
        written = "".join(call.args[0] for call in stderr.write.call_args_list)
        self.assertIn("child input failed", written.lower())
        self.assertNotIn("PASSWORD-CANARY", written)
        with self.assertRaises(ProcessLookupError):
            os.kill(child_pid, 0)

    def test_eof_after_prompt_returns_child_status(self):
        with tempfile.TemporaryDirectory() as td:
            marker = Path(td) / "openconnect.json"
            env = {"FAKE_OPENCONNECT_MARKER": str(marker), "FAKE_OPENCONNECT_MODE": "eof_after_password"}
            session = PromptSession([sys.executable, str(FAKE_OPENCONNECT)], password="pw", totp_provider=mock.Mock(), environ=env, stdout=None)

            self.assertEqual(session.run(), 4)

    def test_child_error_status_is_returned(self):
        with tempfile.TemporaryDirectory() as td:
            marker = Path(td) / "openconnect.json"
            env = {"FAKE_OPENCONNECT_MARKER": str(marker), "FAKE_OPENCONNECT_MODE": "error"}
            session = PromptSession([sys.executable, str(FAKE_OPENCONNECT)], password="pw", totp_provider=mock.Mock(), environ=env, stdout=None)

            self.assertEqual(session.run(), 5)

    def test_forwards_sigterm_to_child_process_group_without_orphan(self):
        self._assert_forwards_signal(signal.SIGTERM)

    def test_forwards_sigint_to_child_process_group_without_orphan(self):
        self._assert_forwards_signal(signal.SIGINT)

    def _assert_forwards_signal(self, signum):
        with tempfile.TemporaryDirectory() as td:
            marker = Path(td) / "openconnect.json"
            env = os.environ.copy()
            env.update({"FAKE_OPENCONNECT_MARKER": str(marker), "FAKE_OPENCONNECT_MODE": "sleep"})
            proc = subprocess.Popen([
                sys.executable,
                "-c",
                (
                    "import os, signal, sys; "
                    f"sys.path.insert(0, {str(ROOT / 'src')!r}); "
                    "from hyu_vpn.connector import PromptSession; "
                    "rc=PromptSession([sys.executable, sys.argv[1]], password='pw', totp_provider=None, environ=os.environ, stdout=None, terminate_timeout=1.0).run(); "
                    "raise SystemExit(rc)"
                ),
                str(FAKE_OPENCONNECT),
            ], env=env)
            deadline = time.time() + 3
            while time.time() < deadline and not marker.exists():
                time.sleep(0.02)
            self.assertTrue(marker.exists())

            proc.send_signal(signum)
            self.assertEqual(proc.wait(timeout=3), 0)
            data = read_json(marker)
            self.assertEqual(data.get("signal"), signum)
            with self.assertRaises(ProcessLookupError):
                os.kill(data["pid"], 0)

    def test_build_openconnect_argv_uses_gp_hip_wrapper_and_no_native_globalprotect(self):
        argv = build_openconnect_argv("alice", config=ConnectorConfig(hip_wrapper="/repo/bin/gp-hip-report"))

        self.assertIn("--protocol=gp", argv)
        self.assertIn("--csd-wrapper=/repo/bin/gp-hip-report", argv)
        self.assertIn("--script=/opt/homebrew/etc/vpnc/vpnc-script", argv)
        self.assertIn("secure.hanyang.ac.kr", argv)
        self.assertIn("/opt/homebrew/bin/openconnect", argv)
        self.assertEqual(argv[:2], ["/usr/bin/sudo", "-n"])
        self.assertFalse(any("PanGP" in part or "GlobalProtect" in part for part in argv))

    def test_main_reads_keychain_services_by_absolute_security_argv(self):
        calls = []
        def fake_run(argv, **kwargs):
            calls.append(tuple(argv))
            service = argv[argv.index("-s") + 1]
            return mock.Mock(returncode=0, stdout={
                "gp-vpn-username": "alice\n",
                "gp-vpn-password": "pw\n",
                "gp-vpn-totp": "seed\n",
            }[service], stderr="")

        with mock.patch("hyu_vpn.otp.subprocess.run", side_effect=fake_run), \
             mock.patch("hyu_vpn.connector.PromptSession") as session_cls:
            session_cls.return_value.run.return_value = 0
            rc = main(config=ConnectorConfig(openconnect_path="/bin/echo", hip_wrapper="/repo/bin/gp-hip-report"))

        self.assertEqual(rc, 0)
        self.assertEqual(calls, [
            ("/usr/bin/security", "find-generic-password", "-s", "gp-vpn-username", "-w"),
            ("/usr/bin/security", "find-generic-password", "-s", "gp-vpn-password", "-w"),
            ("/usr/bin/security", "find-generic-password", "-s", "gp-vpn-totp", "-w"),
        ])
        provider = session_cls.call_args.kwargs["totp_provider"]
        self.assertEqual(provider.state_path.name, "totp-counter.json")
        self.assertIn("hyu-openconnect", str(provider.state_path))


class TotpProviderTests(unittest.TestCase):
    def test_oathtool_failure_raises_redacted_error(self):
        def fake_run(argv, **kwargs):
            return mock.Mock(returncode=8, stdout="", stderr="bad SEED-CANARY")

        provider = TotpProvider("SEED-CANARY", runner=fake_run)

        with self.assertRaises(TotpError) as cm:
            provider.current()
        self.assertNotIn("SEED-CANARY", str(cm.exception))

    def test_rejects_non_digit_or_wrong_length_oathtool_output(self):
        for value in ("warning", "12345", "1234567", "123456\nwarning"):
            with self.subTest(value=value):
                provider = TotpProvider(
                    "SEED-CANARY",
                    runner=lambda *_args, **_kwargs: mock.Mock(returncode=0, stdout=value, stderr=""),
                )
                with self.assertRaises(TotpError):
                    provider.current()


    def test_persisted_counter_guard_waits_across_processes_without_storing_secret_or_otp(self):
        with tempfile.TemporaryDirectory() as td:
            state_path = Path(td) / "totp-state.json"
            state_path.write_text(json.dumps({"last_counter": 0}), encoding="utf-8")
            state_path.chmod(0o600)
            clocks = iter([1, 31, 31])
            sleeps = []
            values = iter(["222222"])

            def fake_run(argv, **kwargs):
                return mock.Mock(returncode=0, stdout=next(values), stderr="")

            provider = TotpProvider(
                "SEED-CANARY",
                runner=fake_run,
                clock=lambda: next(clocks),
                sleep=sleeps.append,
                state_path=state_path,
            )

            self.assertEqual(provider.current(), "222222")
            data = json.loads(state_path.read_text(encoding="utf-8"))
            mode = state_path.stat().st_mode & 0o777

        self.assertEqual(sleeps, [29])
        self.assertEqual(data, {"last_counter": 1})
        self.assertEqual(mode, 0o600)
        serialized = json.dumps(data)
        self.assertNotIn("111111", serialized)
        self.assertNotIn("222222", serialized)
        self.assertNotIn("SEED-CANARY", serialized)


    def test_persisted_counter_guard_sleeps_before_first_generate_and_records_generated_window(self):
        with tempfile.TemporaryDirectory() as td:
            state_path = Path(td) / "totp-state.json"
            state_path.write_text(json.dumps({"last_counter": 0}), encoding="utf-8")
            events = []
            clocks = iter([1, 31, 31])

            def fake_run(argv, **kwargs):
                events.append("generate")
                return mock.Mock(returncode=0, stdout="222222", stderr="")

            provider = TotpProvider("SEED-CANARY", runner=fake_run, clock=lambda: next(clocks), sleep=lambda delay: events.append(("sleep", delay)), state_path=state_path)

            self.assertEqual(provider.current(), "222222")
            data = json.loads(state_path.read_text(encoding="utf-8"))

        self.assertEqual(events, [("sleep", 29), "generate"])
        self.assertEqual(data, {"last_counter": 1})


    def test_persisted_counter_guard_regenerates_when_generation_crosses_window_boundary(self):
        with tempfile.TemporaryDirectory() as td:
            state_path = Path(td) / "totp-state.json"
            state_path.write_text(json.dumps({"last_counter": 0}), encoding="utf-8")
            events = []
            clocks = iter([31, 61, 61])
            values = iter(["111111", "222222"])

            def fake_run(argv, **kwargs):
                value = next(values)
                events.append(("generate", value))
                return mock.Mock(returncode=0, stdout=value, stderr="")

            provider = TotpProvider("SEED-CANARY", runner=fake_run, clock=lambda: next(clocks), sleep=lambda delay: events.append(("sleep", delay)), state_path=state_path)

            self.assertEqual(provider.current(), "222222")
            data = json.loads(state_path.read_text(encoding="utf-8"))

        self.assertEqual(events, [("generate", "111111"), ("generate", "222222")])
        self.assertEqual(data, {"last_counter": 2})

    def test_corrupt_persisted_counter_fails_safe_without_generating_totp(self):
        with tempfile.TemporaryDirectory() as td:
            state_path = Path(td) / "totp-state.json"
            state_path.write_text("not json", encoding="utf-8")
            calls = []

            def fake_run(argv, **kwargs):
                calls.append(argv)
                return mock.Mock(returncode=0, stdout="123456", stderr="")

            provider = TotpProvider("SEED-CANARY", runner=fake_run, state_path=state_path)

            with self.assertRaises(TotpError):
                provider.current()

        self.assertEqual(calls, [])

    def test_keychain_and_oathtool_timeouts_are_redacted(self):
        def timeout(*_args, **_kwargs):
            raise subprocess.TimeoutExpired(cmd=["SECRET-CANARY"], timeout=5)

        with self.assertRaisesRegex(RuntimeError, "gp-vpn-password") as keychain_error:
            Keychain(runner=timeout).read("gp-vpn-password")
        self.assertNotIn("SECRET-CANARY", str(keychain_error.exception))

        with self.assertRaises(TotpError) as totp_error:
            TotpProvider("SEED-CANARY", runner=timeout).current()
        self.assertNotIn("SEED-CANARY", str(totp_error.exception))

    def test_keychain_missing_item_raises_redacted_error(self):
        def fake_run(argv, **kwargs):
            return mock.Mock(returncode=44, stdout="", stderr="no PASSWORD-CANARY")

        with self.assertRaisesRegex(RuntimeError, "gp-vpn-password") as cm:
            Keychain(runner=fake_run).read("gp-vpn-password")
        self.assertNotIn("PASSWORD-CANARY", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
