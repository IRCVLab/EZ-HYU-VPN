import io
import json
import os
import stat
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hyu_vpn.status import (
    ALLOWED_STATUS_FIELDS,
    MAX_STATUS_BYTES,
    SESSION_EXPIRY_LINE,
    VALID_STATES,
    ExpiryCountdown,
    OpenConnectExpiryParser,
    StatusProtocolError,
    VpnStatus,
    read_status,
    write_status,
)

UTC = timezone.utc


def sample_document(**overrides):
    document = {
        "schema_version": 1,
        "state": "connected",
        "automatic_reconnect_enabled": True,
        "connected_at": "2026-08-04T12:00:00Z",
        "session_expires_at": "2026-08-04T12:59:30Z",
        "last_successful_hip_at": "2026-08-04T11:59:00Z",
        "tunnel_interface": "utun7",
        "next_retry_at": None,
        "error_code": None,
        "last_transition_at": "2026-08-04T12:00:01Z",
        "backend_build_version": "2026.08.04+menubar",
    }
    document.update(overrides)
    return document


class StatusProtocolTests(unittest.TestCase):
    def test_status_document_uses_approved_exact_sanitized_field_allowlist_and_iso_timestamps(self):
        status = VpnStatus(
            state="connected",
            automatic_reconnect_enabled=True,
            connected_at=datetime(2026, 8, 4, 12, 0, 0, tzinfo=UTC),
            session_expires_at=datetime(2026, 8, 4, 12, 59, 30, tzinfo=UTC),
            last_successful_hip_at=datetime(2026, 8, 4, 11, 59, 0, tzinfo=UTC),
            tunnel_interface="utun7",
            next_retry_at=None,
            error_code=None,
            last_transition_at=datetime(2026, 8, 4, 12, 0, 1, tzinfo=UTC),
            backend_build_version="2026.08.04+menubar",
        )

        document = status.to_dict()

        self.assertEqual(
            tuple(document.keys()),
            (
                "schema_version",
                "state",
                "automatic_reconnect_enabled",
                "connected_at",
                "session_expires_at",
                "last_successful_hip_at",
                "tunnel_interface",
                "next_retry_at",
                "error_code",
                "last_transition_at",
                "backend_build_version",
            ),
        )
        self.assertEqual(ALLOWED_STATUS_FIELDS, tuple(document.keys()))
        self.assertEqual(document, sample_document())
        for removed in ["updated_at", "expires_at", "last_error", "reconnecting"]:
            self.assertNotIn(removed, document)
        for forbidden in ["username", "password", "otp", "cookie", "authcookie", "seed"]:
            self.assertNotIn(forbidden, document)

    def test_status_states_are_the_approved_menu_bar_states_only(self):
        self.assertEqual(
            VALID_STATES,
            ("disabled", "waiting-for-network", "connecting", "connected", "disconnecting", "backoff", "error"),
        )
        for state in VALID_STATES:
            VpnStatus.from_dict(sample_document(state=state))
        for state in ["disconnected", "reconnecting", "authenticated", ""]:
            with self.subTest(state=state), self.assertRaisesRegex(StatusProtocolError, "state"):
                VpnStatus.from_dict(sample_document(state=state))

    def test_status_rejects_unknown_missing_secret_and_removed_fields(self):
        for key in ["username", "password", "otp", "cookie", "authcookie", "seed", "portal"]:
            with self.subTest(key=key), self.assertRaisesRegex(StatusProtocolError, key):
                VpnStatus.from_dict(sample_document(**{key: "CANARY"}))
        for key in ["updated_at", "expires_at", "last_error", "extra"]:
            with self.subTest(key=key), self.assertRaisesRegex(StatusProtocolError, "unknown"):
                VpnStatus.from_dict(sample_document(**{key: "value"}))
        for key in ALLOWED_STATUS_FIELDS:
            incomplete = sample_document()
            del incomplete[key]
            with self.subTest(key=key), self.assertRaisesRegex(StatusProtocolError, "missing"):
                VpnStatus.from_dict(incomplete)

    def test_status_validates_strict_bool_timestamps_error_token_interface_and_build_version(self):
        invalid_values = [
            ("automatic_reconnect_enabled", "true", "bool"),
            ("connected_at", "2026-08-04T12:00:00", "timezone"),
            ("session_expires_at", 123, "ISO-8601"),
            ("last_successful_hip_at", "not-a-date", "ISO-8601"),
            ("next_retry_at", "2026-08-04T12:01:00", "timezone"),
            ("last_transition_at", None, "ISO-8601"),
            ("error_code", "portal password leaked", "error_code"),
            ("error_code", "X" * 65, "error_code"),
            ("tunnel_interface", "en0", "tunnel_interface"),
            ("tunnel_interface", "utun7;rm -rf", "tunnel_interface"),
            ("backend_build_version", "v" * 129, "backend_build_version"),
            ("backend_build_version", "bad version!", "backend_build_version"),
        ]
        for key, value, pattern in invalid_values:
            with self.subTest(key=key, value=value), self.assertRaisesRegex(StatusProtocolError, pattern):
                VpnStatus.from_dict(sample_document(**{key: value}))

    def test_status_uses_the_shared_bounded_utun_contract(self):
        self.assertEqual(VpnStatus.from_dict(sample_document(tunnel_interface="utun12345678")).tunnel_interface, "utun12345678")
        with self.assertRaisesRegex(StatusProtocolError, "tunnel_interface"):
            VpnStatus.from_dict(sample_document(tunnel_interface="utun123456789"))

    def test_status_roundtrip_preserves_null_optional_fields_and_rejects_malformed_or_oversized_documents(self):
        status = VpnStatus.from_dict(sample_document(
            connected_at=None,
            session_expires_at=None,
            last_successful_hip_at=None,
            tunnel_interface=None,
            next_retry_at=None,
            error_code="NETWORK_SCRIPT_BAD_CONFIGURATION",
            backend_build_version=None,
        ))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "status.json"
            write_status(path, status)
            self.assertEqual(read_status(path), status)

            path.write_text("{not json", encoding="utf-8")
            with self.assertRaisesRegex(StatusProtocolError, "malformed"):
                read_status(path)

            path.write_text("x" * (MAX_STATUS_BYTES + 1), encoding="utf-8")
            with self.assertRaisesRegex(StatusProtocolError, "oversized"):
                read_status(path)

    def test_read_status_bounds_the_same_descriptor_when_file_grows_after_size_observation(self):
        replacement = json.dumps(sample_document()).encode("utf-8")
        self.assertGreater(len(replacement), 64)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "status.json"
            path.write_text("{}", encoding="utf-8")
            observed_small_stat = path.stat()

            with mock.patch("pathlib.Path.stat", return_value=observed_small_stat), \
                 mock.patch("pathlib.Path.read_text", return_value=replacement.decode("utf-8")), \
                 mock.patch("pathlib.Path.open", return_value=io.BytesIO(replacement)):
                with self.assertRaisesRegex(StatusProtocolError, "oversized"):
                    read_status(path, max_bytes=64)

    def test_read_status_rejects_invalid_max_bytes_limits(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "status.json"
            path.write_text(json.dumps(sample_document()), encoding="utf-8")
            for max_bytes in [0, -1, 1024 * 1024 + 1]:
                with self.subTest(max_bytes=max_bytes), self.assertRaisesRegex(StatusProtocolError, "max_bytes"):
                    read_status(path, max_bytes=max_bytes)

    def test_write_status_is_atomic_and_sets_private_directory_and_file_modes(self):
        status = VpnStatus.from_dict(sample_document(state="disabled", connected_at=None, session_expires_at=None, tunnel_interface=None))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "private" / "status.json"
            with mock.patch("hyu_vpn.status.os.replace", wraps=os.replace) as replace:
                write_status(path, status)

            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), status.to_dict())
            self.assertEqual(replace.call_count, 1)
            temp_source, final_target = replace.call_args.args
            self.assertEqual(Path(final_target), path)
            self.assertEqual(Path(temp_source).parent, path.parent)
            self.assertNotEqual(Path(temp_source).name, path.name)
            self.assertFalse(Path(temp_source).exists())


class OpenConnectExpiryParserTests(unittest.TestCase):
    def test_parser_extracts_real_kst_expiry_line_as_utc_timestamp(self):
        parser = OpenConnectExpiryParser()

        expiry = parser.feed(SESSION_EXPIRY_LINE.encode("utf-8"))

        self.assertEqual(expiry, datetime(2026, 8, 4, 12, 59, 30, tzinfo=UTC))

    def test_parser_handles_split_chunks_duplicates_and_hostile_text_without_secret_leakage(self):
        parser = OpenConnectExpiryParser()
        hostile = b"Password: PASSWORD-CANARY\nauthcookie=AUTHCOOKIE-CANARY\n"
        self.assertIsNone(parser.feed(hostile + b"Session authentication will exp"))
        first = parser.feed(b"ire at Tue, 04 Aug 2026 21:59:30 KST\n")
        duplicate = parser.feed(b"noise\nSession authentication will expire at Tue, 04 Aug 2026 21:59:30 KST\n")

        self.assertEqual(first, datetime(2026, 8, 4, 12, 59, 30, tzinfo=UTC))
        self.assertIsNone(duplicate)
        self.assertLessEqual(len(parser.buffer.encode("utf-8")), parser.max_buffer_bytes)
        self.assertNotIn("PASSWORD-CANARY", parser.buffer)
        self.assertNotIn("AUTHCOOKIE-CANARY", parser.buffer)

    def test_parser_ignores_missing_values_malformed_values_and_bounds_hostile_text_by_bytes(self):
        parser = OpenConnectExpiryParser(max_buffer_bytes=128)

        self.assertIsNone(parser.feed(b"Session authentication will expire at \n"))
        self.assertIsNone(parser.feed(b"Session authentication will expire at someday soon KST\n"))
        self.assertIsNone(parser.feed(b"A" * 10000))

        self.assertLessEqual(len(parser.buffer.encode("utf-8")), 128)

    def test_parser_bounds_multibyte_hostile_text_by_bytes_not_characters(self):
        parser = OpenConnectExpiryParser(max_buffer_bytes=9)

        self.assertIsNone(parser.feed("한글한글한글한글"))

        self.assertLessEqual(len(parser.buffer.encode("utf-8")), 9)

    def test_parser_handles_clock_rollover_to_following_year(self):
        parser = OpenConnectExpiryParser(now=lambda: datetime(2026, 12, 31, 15, 0, 0, tzinfo=UTC))

        expiry = parser.feed(b"Session authentication will expire at Fri, 01 Jan 2027 00:30:00 KST\n")

        self.assertEqual(expiry, datetime(2026, 12, 31, 15, 30, 0, tzinfo=UTC))

    def test_countdown_reports_unknown_or_bounded_remaining_seconds(self):
        unknown = ExpiryCountdown(None, now=lambda: datetime(2026, 8, 4, 12, 0, 0, tzinfo=UTC))
        active = ExpiryCountdown(
            datetime(2026, 8, 4, 12, 59, 30, tzinfo=UTC),
            now=lambda: datetime(2026, 8, 4, 12, 0, 0, tzinfo=UTC),
        )
        expired = ExpiryCountdown(
            datetime(2026, 8, 4, 11, 59, 30, tzinfo=UTC),
            now=lambda: datetime(2026, 8, 4, 12, 0, 0, tzinfo=UTC),
        )

        self.assertIsNone(unknown.remaining_seconds())
        self.assertEqual(active.remaining_seconds(), 3570)
        self.assertEqual(expired.remaining_seconds(), 0)


if __name__ == "__main__":
    unittest.main()
