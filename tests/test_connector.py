import hashlib
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

from hyu_vpn.connector import (
    ConnectorConfig,
    ConnectorEvent,
    ConnectorEventParser,
    ConnectorRuntimeConfigError,
    INSTALLED_CONNECTOR_CONFIG_PATH,
    INSTALLED_OATHTOOL_PATH,
    PromptSession,
    build_helper_argv,
    build_openconnect_argv,
    load_connector_runtime_config,
    main,
    parse_connector_event_line,
)
from hyu_vpn.otp import KEYCHAIN_READER, Keychain, TotpError, TotpProvider

ROOT = Path(__file__).resolve().parents[1]
FAKE_OPENCONNECT = ROOT / "tests" / "helpers" / "fake_openconnect.py"
FAKE_OATHTOOL = ROOT / "tests" / "helpers" / "fake_oathtool.py"


def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _write_fake_executable(path, body="#!/bin/sh\necho 123456\n"):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)
    return path


def _write_runtime_config(config_path, oathtool_path, *, sha256=None):
    config_path = Path(config_path)
    config_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": 1,
        "oathtool_path": str(oathtool_path),
        "oathtool_sha256": sha256 if sha256 is not None else _sha256(oathtool_path),
    }
    config_path.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
    config_path.chmod(0o644)
    return payload


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


class ConnectorTests(unittest.TestCase):
    def test_build_helper_argv_is_fixed_and_contains_no_username_or_runtime_override(self):
        argv = build_helper_argv(config=ConnectorConfig(helper_path="/Library/PrivilegedHelperTools/com.hyu.vpn.helper"))

        self.assertEqual(argv, [
            "/usr/bin/sudo",
            "-n",
            "/Library/PrivilegedHelperTools/com.hyu.vpn.helper",
            "start",
        ])
        self.assertNotIn("alice", "\n".join(argv))
        self.assertFalse(any("openconnect" in value.lower() or "--script" in value for value in argv))

    def test_helper_start_header_precedes_password_and_prompt_responses(self):
        with tempfile.TemporaryDirectory() as td:
            marker = Path(td) / "helper.json"
            env = {"FAKE_OPENCONNECT_MARKER": str(marker), "FAKE_OPENCONNECT_MODE": "helper_header"}
            provider = mock.Mock()
            provider.current.side_effect = ["111111", "222222"]
            session = PromptSession(
                [sys.executable, str(FAKE_OPENCONNECT)],
                password="PASSWORD-CANARY",
                totp_provider=provider,
                start_username="alice@hanyang.ac.kr",
                environ=env,
                stdout=None,
            )

            rc = session.run()
            responses = read_json(marker)["responses"]

        self.assertEqual(rc, 0)
        self.assertEqual(responses, [
            "HYU-Username: alice@hanyang.ac.kr",
            "",
            "PASSWORD-CANARY",
            "111111",
            "PASSWORD-CANARY",
            "222222",
        ])

    def test_invalid_helper_username_is_rejected_before_child_launch(self):
        stderr = mock.Mock()
        session = PromptSession(
            ["/should/not/launch"],
            password="PASSWORD-CANARY",
            totp_provider=mock.Mock(),
            start_username="bad\nheader",
            stdout=None,
            stderr=stderr,
        )
        with mock.patch("hyu_vpn.connector.subprocess.Popen") as popen:
            rc = session.run()

        self.assertEqual(rc, 1)
        popen.assert_not_called()
        written = "".join(call.args[0] for call in stderr.write.call_args_list)
        self.assertIn("start request invalid", written.lower())
        self.assertNotIn("bad", written)
        self.assertNotIn("PASSWORD-CANARY", written)

    def test_event_parser_emits_only_bounded_sanitized_events(self):
        parser = ConnectorEventParser()
        hostile = "PASSWORD-CANARY authcookie=COOKIE-CANARY username=USER-CANARY\n"

        first = parser.feed(hostile + "HIP report submitted successfully.\nSession authentication will exp")
        second = parser.feed(
            "ire at Tue, 04 Aug 2026 21:59:30 KST\n"
            "ESP session established with server\n"
            "hyu-vpnc-wrapperd-event: network configuration verified tunnel=utun7\n"
        )

        self.assertEqual([event.kind for event in first + second], ["hip-succeeded", "session-expiry", "connected"])
        serialized = repr(first + second)
        for secret in ("PASSWORD-CANARY", "COOKIE-CANARY", "USER-CANARY", "authcookie"):
            self.assertNotIn(secret, serialized)
        expiry_event = next(event for event in second if event.kind == "session-expiry")
        self.assertEqual(expiry_event.timestamp.isoformat(), "2026-08-04T12:59:30+00:00")
        connected_event = next(event for event in second if event.kind == "connected")
        self.assertEqual(connected_event.tunnel_interface, "utun7")

    def test_connector_event_wire_format_is_exact_bounded_and_rejects_secrets(self):
        event = ConnectorEvent("session-expiry", __import__("datetime").datetime(2026, 8, 4, 12, 59, 30, tzinfo=__import__("datetime").timezone.utc))

        line = event.to_json_line()

        self.assertLessEqual(len(line.encode("utf-8")), 512)
        self.assertEqual(parse_connector_event_line(line), event)
        document = json.loads(line)
        self.assertEqual(set(document), {"schema_version", "event", "timestamp"})
        connected = ConnectorEvent(
            "connected",
            __import__("datetime").datetime(2026, 8, 4, 12, 59, 30, tzinfo=__import__("datetime").timezone.utc),
            tunnel_interface="utun7",
        )
        connected_line = connected.to_json_line()
        self.assertEqual(parse_connector_event_line(connected_line), connected)
        self.assertEqual(set(json.loads(connected_line)), {"schema_version", "event", "timestamp", "tunnel_interface"})
        for malformed in (
            '{"schema_version":1,"event":"connected","timestamp":"2026-08-04T12:59:30Z"}',
            '{"schema_version":1,"event":"connected","timestamp":"2026-08-04T12:59:30Z","tunnel_interface":"en0"}',
            '{"schema_version":1,"event":"connected","timestamp":"2026-08-04T12:59:30Z","password":"CANARY"}',
            '{"schema_version":1,"event":"raw-output","timestamp":"2026-08-04T12:59:30Z"}',
            '{"schema_version":true,"event":"connected","timestamp":"2026-08-04T12:59:30Z"}',
            '{"schema_version":1,"event":"connected","timestamp":"2026-08-04T21:59:30+09:00"}',
            '{"schema_version":1,"event":"connected","timestamp":"2026-08-04T12:59:30.123Z"}',
            "not-json",
            "{}",
        ):
            with self.subTest(malformed=malformed):
                with self.assertRaises(ValueError):
                    parse_connector_event_line(malformed)

    def test_generic_connected_text_does_not_create_a_false_session_event(self):
        parser = ConnectorEventParser()

        self.assertEqual(parser.feed("connected\n"), [])
        self.assertEqual(parser.feed("ESP session established with server\n"), [])
        self.assertEqual(parser.feed("hyu-vpnc-wrapperd-event: network configuration verified\n"), [])
        self.assertEqual(
            parser.feed("hyu-vpnc-wrapperd-event: network configuration verified tunnel=utun12\n")[0].tunnel_interface,
            "utun12",
        )

    def test_wrapper_error_becomes_one_sanitized_fatal_event_and_suppresses_connected(self):
        parser = ConnectorEventParser(now=lambda: __import__("datetime").datetime(2026, 8, 5, 1, 0, tzinfo=__import__("datetime").timezone.utc))

        events = parser.feed(
            "PASSWORD-CANARY authcookie=COOKIE-CANARY\n"
            "hyu-vpnc-wrapperd: bad helper configuration\n"
            "hyu-vpnc-wrapperd-event: network configuration verified tunnel=utun7\n"
        )

        self.assertEqual([event.kind for event in events], ["network-script-bad-configuration"])
        self.assertEqual(parser.feed("hyu-vpnc-wrapperd-event: network configuration verified tunnel=utun7\n"), [])
        serialized = repr(events) + events[0].to_json_line()
        self.assertNotIn("PASSWORD-CANARY", serialized)
        self.assertNotIn("COOKIE-CANARY", serialized)

    def test_wrapper_error_categories_never_serialize_raw_detail(self):
        cases = (
            ("bad helper configuration", "network-script-bad-configuration"),
            ("recorded process did not match live process", "network-script-state-mismatch"),
            ("insecure path: /tmp/PASSWORD-CANARY", "network-script-security-failure"),
            ("teardown incomplete: COOKIE-CANARY", "network-script-teardown-incomplete"),
            ("child exited with status 70 USER-CANARY", "network-script-failed"),
            ("network preflight drift", "network-script-preflight-drift"),
            ("network upstream failed", "network-script-upstream-failed"),
            ("network postcondition failed", "network-script-postcondition-failed"),
        )
        for raw_detail, expected_kind in cases:
            with self.subTest(raw_detail=raw_detail):
                parser = ConnectorEventParser(
                    now=lambda: __import__("datetime").datetime(
                        2026, 8, 5, 1, 0, tzinfo=__import__("datetime").timezone.utc
                    )
                )
                events = parser.feed(f"hyu-vpnc-wrapperd: {raw_detail}\n")

                self.assertEqual([event.kind for event in events], [expected_kind])
                serialized = events[0].to_json_line()
                for forbidden in (raw_detail, "/tmp", "PASSWORD-CANARY", "COOKIE-CANARY", "USER-CANARY"):
                    self.assertNotIn(forbidden, serialized)

    def test_wrapper_error_terminates_child_and_returns_redacted_failure(self):
        with tempfile.TemporaryDirectory() as td:
            marker = Path(td) / "helper.json"
            env = {"FAKE_OPENCONNECT_MARKER": str(marker), "FAKE_OPENCONNECT_MODE": "network_script_error"}
            stderr = mock.Mock()
            events = []
            session = PromptSession(
                [sys.executable, str(FAKE_OPENCONNECT)],
                password="PASSWORD-CANARY",
                totp_provider=mock.Mock(),
                environ=env,
                stdout=None,
                stderr=stderr,
                event_sink=events.append,
                terminate_timeout=1,
            )

            rc = session.run()
            recorded = json.loads(marker.read_text(encoding="utf-8"))

        self.assertEqual(rc, 1)
        self.assertEqual([event.kind for event in events], ["network-script-state-mismatch"])
        self.assertEqual(recorded.get("signal"), signal.SIGTERM)
        written = "".join(call.args[0] for call in stderr.write.call_args_list)
        self.assertIn("event channel failed", written.lower())
        for secret in ("PASSWORD-CANARY", "COOKIE-CANARY", "USER-CANARY"):
            self.assertNotIn(secret, repr(events) + written)

    def test_prompt_session_sends_sanitized_events_without_forwarding_raw_output(self):
        with tempfile.TemporaryDirectory() as td:
            marker = Path(td) / "helper.json"
            env = {"FAKE_OPENCONNECT_MARKER": str(marker), "FAKE_OPENCONNECT_MODE": "helper_header"}
            provider = mock.Mock()
            provider.current.side_effect = ["111111", "222222"]
            events = []
            session = PromptSession(
                [sys.executable, str(FAKE_OPENCONNECT)],
                password="PASSWORD-CANARY",
                totp_provider=provider,
                start_username="alice",
                environ=env,
                stdout=None,
                event_sink=events.append,
            )

            self.assertEqual(session.run(), 0)

        self.assertEqual([event.kind for event in events], ["hip-succeeded", "session-expiry", "connected"])

    def test_event_sink_failure_returns_redacted_error_and_reaps_child(self):
        with tempfile.TemporaryDirectory() as td:
            marker = Path(td) / "helper.json"
            env = {"FAKE_OPENCONNECT_MARKER": str(marker), "FAKE_OPENCONNECT_MODE": "helper_header"}
            provider = mock.Mock()
            provider.current.side_effect = ["111111", "222222"]
            stderr = mock.Mock()
            session = PromptSession(
                [sys.executable, str(FAKE_OPENCONNECT)],
                password="PASSWORD-CANARY",
                totp_provider=provider,
                start_username="alice",
                environ=env,
                stdout=None,
                stderr=stderr,
                event_sink=lambda _event: (_ for _ in ()).throw(RuntimeError("COOKIE-CANARY")),
            )

            rc = session.run()

        self.assertEqual(rc, 1)
        written = "".join(call.args[0] for call in stderr.write.call_args_list)
        self.assertIn("event channel failed", written.lower())
        self.assertNotIn("COOKIE-CANARY", written)
        self.assertNotIn("PASSWORD-CANARY", written)

    def test_main_rejects_all_arguments_before_keychain_access(self):
        with mock.patch("hyu_vpn.connector.Keychain") as keychain:
            self.assertEqual(main(["--helper", "/tmp/evil"]), 2)
        keychain.assert_not_called()
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

    def test_production_runtime_config_contract_uses_fixed_installed_paths(self):
        self.assertEqual(str(INSTALLED_CONNECTOR_CONFIG_PATH), "/Library/Application Support/HYU VPN/connector-config.json")
        self.assertEqual(str(INSTALLED_OATHTOOL_PATH), "/Library/Application Support/HYU VPN/runtime/current/bin/oathtool")

    def test_load_runtime_config_accepts_only_exact_schema_and_verified_runtime_oathtool(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "HYU VPN"
            oathtool = _write_fake_executable(root / "runtime" / "oathtool")
            config_path = root / "connector-config.json"
            payload = _write_runtime_config(config_path, oathtool)

            expected_hash = _sha256(oathtool)
            runtime = load_connector_runtime_config(
                config_path=config_path,
                expected_oathtool_path=oathtool,
                trusted_parent=root,
                required_uid=os.getuid(),
            )

            self.assertEqual(runtime.oathtool_path, str(oathtool))
            self.assertEqual(payload, {
                "schema_version": 1,
                "oathtool_path": str(oathtool),
                "oathtool_sha256": expected_hash,
            })
        self.assertRegex(payload["oathtool_sha256"], r"^[0-9a-f]{64}$")



    def test_load_runtime_config_requires_user_readable_0644_config_and_0755_artifact_modes(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "HYU VPN"
            oathtool = _write_fake_executable(root / "runtime" / "oathtool")
            config_path = root / "connector-config.json"
            _write_runtime_config(config_path, oathtool)
            config_path.chmod(0o644)

            runtime = load_connector_runtime_config(
                config_path=config_path,
                expected_oathtool_path=oathtool,
                trusted_parent=root,
                required_uid=os.getuid(),
            )
            self.assertEqual(runtime.oathtool_path, str(oathtool))

            config_path.chmod(0o600)
            with self.assertRaises(ConnectorRuntimeConfigError):
                load_connector_runtime_config(
                    config_path=config_path,
                    expected_oathtool_path=oathtool,
                    trusted_parent=root,
                    required_uid=os.getuid(),
                )

            config_path.chmod(0o644)
            oathtool.chmod(0o755)
            load_connector_runtime_config(
                config_path=config_path,
                expected_oathtool_path=oathtool,
                trusted_parent=root,
                required_uid=os.getuid(),
            )
            oathtool.chmod(0o700)
            with self.assertRaises(ConnectorRuntimeConfigError):
                load_connector_runtime_config(
                    config_path=config_path,
                    expected_oathtool_path=oathtool,
                    trusted_parent=root,
                    required_uid=os.getuid(),
                )

    def test_load_runtime_config_rejects_duplicate_json_keys_for_each_contract_key(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "HYU VPN"
            oathtool = _write_fake_executable(root / "runtime" / "oathtool")
            config_path = root / "connector-config.json"
            digest = _sha256(oathtool)
            duplicated = {
                "schema_version": '{"schema_version":1,"schema_version":1,"oathtool_path":"%s","oathtool_sha256":"%s"}' % (oathtool, digest),
                "oathtool_path": '{"schema_version":1,"oathtool_path":"%s","oathtool_path":"%s","oathtool_sha256":"%s"}' % (oathtool, oathtool, digest),
                "oathtool_sha256": '{"schema_version":1,"oathtool_path":"%s","oathtool_sha256":"%s","oathtool_sha256":"%s"}' % (oathtool, digest, digest),
            }
            for key, raw in duplicated.items():
                with self.subTest(key=key):
                    config_path.write_text(raw, encoding="utf-8")
                    config_path.chmod(0o644)
                    with self.assertRaises(ConnectorRuntimeConfigError):
                        load_connector_runtime_config(
                            config_path=config_path,
                            expected_oathtool_path=oathtool,
                            trusted_parent=root,
                            required_uid=os.getuid(),
                        )

    def test_load_runtime_config_rejects_traversal_and_oversize_config(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "HYU VPN"
            oathtool = _write_fake_executable(root / "runtime" / "oathtool")
            config_path = root / "connector-config.json"
            _write_runtime_config(config_path, oathtool)
            config_path.chmod(0o644)

            with self.assertRaises(ConnectorRuntimeConfigError):
                load_connector_runtime_config(
                    config_path=f"{root}/./connector-config.json",
                    expected_oathtool_path=oathtool,
                    trusted_parent=root,
                    required_uid=os.getuid(),
                )
            with self.assertRaises(ConnectorRuntimeConfigError):
                load_connector_runtime_config(
                    config_path=root / "runtime" / ".." / "connector-config.json",
                    expected_oathtool_path=oathtool,
                    trusted_parent=root,
                    required_uid=os.getuid(),
                )

            config_path.write_text(" " * 4097, encoding="utf-8")
            config_path.chmod(0o644)
            with self.assertRaises(ConnectorRuntimeConfigError):
                load_connector_runtime_config(
                    config_path=config_path,
                    expected_oathtool_path=oathtool,
                    trusted_parent=root,
                    required_uid=os.getuid(),
                )

    def test_load_runtime_config_rejects_symlink_config_before_reading_target(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "HYU VPN"
            oathtool = _write_fake_executable(root / "runtime" / "oathtool")
            target = root / "real-config.json"
            _write_runtime_config(target, oathtool)
            target.chmod(0o644)
            config_path = root / "connector-config.json"
            config_path.symlink_to(target)

            with self.assertRaises(ConnectorRuntimeConfigError):
                load_connector_runtime_config(
                    config_path=config_path,
                    expected_oathtool_path=oathtool,
                    trusted_parent=root,
                    required_uid=os.getuid(),
                )

    def test_load_runtime_config_rejects_extra_keys_and_non_lowercase_hash(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "HYU VPN"
            oathtool = _write_fake_executable(root / "runtime" / "oathtool")
            config_path = root / "connector-config.json"
            valid = _write_runtime_config(config_path, oathtool)

            for payload in (
                {**valid, "unexpected": "value"},
                {**valid, "oathtool_sha256": valid["oathtool_sha256"].upper()},
            ):
                with self.subTest(payload=payload):
                    config_path.write_text(json.dumps(payload), encoding="utf-8")
                    config_path.chmod(0o644)
                    with self.assertRaises(ConnectorRuntimeConfigError):
                        load_connector_runtime_config(
                            config_path=config_path,
                            expected_oathtool_path=oathtool,
                            trusted_parent=root,
                            required_uid=os.getuid(),
                        )

    def test_load_runtime_config_rejects_untrusted_or_mutated_oathtool(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "HYU VPN"
            oathtool = _write_fake_executable(root / "runtime" / "oathtool")
            config_path = root / "connector-config.json"
            _write_runtime_config(config_path, oathtool)
            oathtool.write_text("#!/bin/sh\necho 654321\n", encoding="utf-8")

            with self.assertRaises(ConnectorRuntimeConfigError):
                load_connector_runtime_config(
                    config_path=config_path,
                    expected_oathtool_path=oathtool,
                    trusted_parent=root,
                    required_uid=os.getuid(),
                )

    def test_load_runtime_config_rejects_symlink_and_writable_runtime_artifact(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "HYU VPN"
            real = _write_fake_executable(root / "runtime" / "real-oathtool")
            linked = root / "runtime" / "oathtool"
            linked.symlink_to(real)
            config_path = root / "connector-config.json"
            config_path.parent.mkdir(parents=True, exist_ok=True)
            config_path.write_text(json.dumps({
                "schema_version": 1,
                "oathtool_path": str(linked),
                "oathtool_sha256": _sha256(real),
            }), encoding="utf-8")
            config_path.chmod(0o644)

            with self.assertRaises(ConnectorRuntimeConfigError):
                load_connector_runtime_config(
                    config_path=config_path,
                    expected_oathtool_path=linked,
                    trusted_parent=root,
                    required_uid=os.getuid(),
                )

            linked.unlink()
            _write_fake_executable(linked)
            _write_runtime_config(config_path, linked)
            linked.chmod(0o777)
            with self.assertRaises(ConnectorRuntimeConfigError):
                load_connector_runtime_config(
                    config_path=config_path,
                    expected_oathtool_path=linked,
                    trusted_parent=root,
                    required_uid=os.getuid(),
                )


    def test_load_runtime_config_rejects_symlink_runtime_parent_even_when_target_stays_under_root(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "HYU VPN"
            real_runtime = root / "real-runtime"
            oathtool = _write_fake_executable(real_runtime / "oathtool")
            runtime_link = root / "runtime"
            runtime_link.symlink_to(real_runtime, target_is_directory=True)
            linked_oathtool = runtime_link / "oathtool"
            config_path = root / "connector-config.json"
            _write_runtime_config(config_path, linked_oathtool, sha256=_sha256(oathtool))

            with self.assertRaises(ConnectorRuntimeConfigError):
                load_connector_runtime_config(
                    config_path=config_path,
                    expected_oathtool_path=linked_oathtool,
                    trusted_parent=root,
                    required_uid=os.getuid(),
                )

    def test_main_fails_closed_before_keychain_when_runtime_config_missing(self):
        with tempfile.TemporaryDirectory() as td, mock.patch("hyu_vpn.connector.Keychain") as keychain:
            rc = main(runtime_config_path=Path(td) / "missing.json", runtime_required_uid=os.getuid())

        self.assertEqual(rc, 1)
        keychain.assert_not_called()

    def test_main_uses_verified_installed_oathtool_instead_of_homebrew_fallback(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "HYU VPN"
            oathtool = _write_fake_executable(root / "runtime" / "oathtool")
            config_path = root / "connector-config.json"
            _write_runtime_config(config_path, oathtool)
            with mock.patch("hyu_vpn.otp.subprocess.run") as security_run, \
                 mock.patch("hyu_vpn.connector.PromptSession") as session_cls:
                def fake_reader(argv, **kwargs):
                    service = argv[1]
                    return mock.Mock(returncode=0, stdout={
                        "gp-vpn-username": "alice\n",
                        "gp-vpn-password": "pw\n",
                        "gp-vpn-totp": "seed\n",
                    }[service], stderr="")
                security_run.side_effect = fake_reader
                session_cls.return_value.run.return_value = 0

                rc = main(
                    config=ConnectorConfig(helper_path="/bin/echo"),
                    runtime_config_path=config_path,
                    runtime_expected_oathtool_path=oathtool,
                    runtime_trusted_parent=root,
                    runtime_required_uid=os.getuid(),
                )

        self.assertEqual(rc, 0)
        provider = session_cls.call_args.kwargs["totp_provider"]
        self.assertEqual(provider.oathtool_path, str(oathtool))
        self.assertNotEqual(provider.oathtool_path, "/opt/homebrew/bin/oathtool")

    def test_main_reads_keychain_services_by_absolute_native_reader_argv(self):
        calls = []
        def fake_run(argv, **kwargs):
            calls.append(tuple(argv))
            service = argv[1]
            return mock.Mock(returncode=0, stdout={
                "gp-vpn-username": "alice\n",
                "gp-vpn-password": "pw\n",
                "gp-vpn-totp": "seed\n",
            }[service], stderr="")

        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "HYU VPN"
            oathtool = _write_fake_executable(root / "runtime" / "oathtool")
            config_path = root / "connector-config.json"
            _write_runtime_config(config_path, oathtool)
            with mock.patch("hyu_vpn.otp.subprocess.run", side_effect=fake_run), \
                 mock.patch("hyu_vpn.connector.PromptSession") as session_cls:
                session_cls.return_value.run.return_value = 0
                rc = main(
                    config=ConnectorConfig(helper_path="/bin/echo"),
                    runtime_config_path=config_path,
                    runtime_expected_oathtool_path=oathtool,
                    runtime_trusted_parent=root,
                    runtime_required_uid=os.getuid(),
                )

        self.assertEqual(rc, 0)
        self.assertEqual(calls, [
            (KEYCHAIN_READER, "gp-vpn-username"),
            (KEYCHAIN_READER, "gp-vpn-password"),
            (KEYCHAIN_READER, "gp-vpn-totp"),
        ])
        provider = session_cls.call_args.kwargs["totp_provider"]
        self.assertEqual(provider.state_path.name, "totp-counter.json")
        self.assertIn("hyu-openconnect", str(provider.state_path))
        self.assertEqual(session_cls.call_args.args[0], ["/usr/bin/sudo", "-n", "/bin/echo", "start"])
        self.assertEqual(session_cls.call_args.kwargs["start_username"], "alice")
        self.assertIsNone(session_cls.call_args.kwargs["stdout"])
        self.assertTrue(callable(session_cls.call_args.kwargs["event_sink"]))



    def test_keychain_reads_use_fixed_native_reader(self):
        calls = []
        def fake_run(argv, **kwargs):
            calls.append(tuple(argv))
            return mock.Mock(returncode=0, stdout="value\n", stderr="")

        self.assertEqual(Keychain(runner=fake_run).read("gp-vpn-password"), "value")

        self.assertEqual(KEYCHAIN_READER, "/Applications/HYU VPN.app/Contents/MacOS/HYUVPNCredentialReader")
        self.assertEqual(calls, [
            (KEYCHAIN_READER, "gp-vpn-password"),
        ])

    def test_keychain_missing_item_error_is_redacted_and_does_not_expose_account_query_output(self):
        def fake_run(argv, **kwargs):
            self.assertEqual(argv, [KEYCHAIN_READER, "gp-vpn-password"])
            return mock.Mock(returncode=44, stdout="", stderr="multiple accounts PASSWORD-CANARY SEED-CANARY hyu-vpn")

        with self.assertRaisesRegex(RuntimeError, "gp-vpn-password") as cm:
            Keychain(runner=fake_run).read("gp-vpn-password")

        message = str(cm.exception)
        self.assertNotIn("PASSWORD-CANARY", message)
        self.assertNotIn("SEED-CANARY", message)
        self.assertNotIn("hyu-vpn", message)

class TotpProviderTests(unittest.TestCase):
    def test_oathtool_receives_seed_only_over_stdin(self):
        calls = []

        def fake_run(argv, **kwargs):
            calls.append((tuple(argv), kwargs))
            return mock.Mock(returncode=0, stdout="123456\n", stderr="")

        provider = TotpProvider("SEED-CANARY", runner=fake_run, environ={"PATH": "/usr/bin"})

        self.assertEqual(provider.current(), "123456")
        self.assertEqual(len(calls), 1)
        argv, kwargs = calls[0]
        self.assertEqual(argv, ("/opt/homebrew/bin/oathtool", "--totp", "-b", "-"))
        self.assertEqual(kwargs["input"], "SEED-CANARY\n")
        self.assertNotIn("SEED-CANARY", argv)
        self.assertNotIn("SEED-CANARY", kwargs["env"].values())

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
