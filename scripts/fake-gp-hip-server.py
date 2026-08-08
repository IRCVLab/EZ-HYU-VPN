#!/usr/bin/env python3
"""Minimal TLS GlobalProtect server for the patched Windows HIP integration test."""
from __future__ import annotations

import argparse
import os
import ssl
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit


class GlobalProtectHandler(BaseHTTPRequestHandler):
    server_version = "HYUVPNTest/1"
    user = "test"
    computer = "hyu-test"
    authcookie = "hyu-integration-auth-cookie"
    portal = "HYU-Portal"
    domain = "HYU"
    preferred_ip = "192.168.77.10"

    def log_message(self, fmt: str, *args: object) -> None:
        print(fmt % args, file=sys.stderr, flush=True)

    def _read_form(self) -> dict[str, str]:
        length = int(self.headers.get("Content-Length", "0"))
        if length < 0 or length > 1_048_576:
            self.send_error(413)
            return {}
        values = parse_qs(self.rfile.read(length).decode("utf-8", "strict"), keep_blank_values=True)
        return {key: items[-1] for key, items in values.items() if items}

    def _respond(self, body: str, status: int = 200, content_type: str = "application/xml") -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        path = urlsplit(self.path).path
        if path == "/CONFIGURE":
            self._respond("ready\n", content_type="text/plain")
        elif path == "/ssl-tunnel-connect.sslvpn":
            self._respond("expected tunnel rejection\n", status=502, content_type="text/plain")
        else:
            self.send_error(404)

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        path = urlsplit(self.path).path
        form = self._read_form()
        if path == "/ssl-vpn/prelogin.esp":
            self._respond(
                "<prelogin-response><status>Success</status><ccusername/>"
                "<autosubmit>false</autosubmit><msg/><newmsg/>"
                "<authentication-message>HYU integration test</authentication-message>"
                "<username-label>Username</username-label><password-label>Password</password-label>"
                "<panos-version>1</panos-version><region>EARTH</region></prelogin-response>"
            )
        elif path == "/ssl-vpn/login.esp":
            if not form.get("user") or not form.get("passwd"):
                self._respond("Invalid username or password", status=401, content_type="text/plain")
                return
            type(self).user = form["user"]
            type(self).computer = form.get("computer", "hyu-test")
            type(self).preferred_ip = form.get("preferred-ip", "192.168.77.10")
            arguments = [
                "(null)", self.authcookie, "PersistentCookie", self.portal, self.user,
                "TestAuth", "vsys1", self.domain, "(null)", "", "", "", "tunnel",
                "-1", "4100", self.preferred_ip, "", "", "",
            ]
            rendered = "".join(f"<argument>{value}</argument>" for value in arguments)
            self._respond(
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
                f"<jnlp><application-desc>{rendered}</application-desc></jnlp>"
            )
        elif path == "/ssl-vpn/getconfig.esp":
            self._respond(
                "<response>"
                f"<ip-address>{self.preferred_ip}</ip-address>"
                "<gw-address>127.0.0.1</gw-address>"
                "<ssl-tunnel-url>/ssl-tunnel-connect.sslvpn</ssl-tunnel-url>"
                "</response>"
            )
        elif path == "/ssl-vpn/hipreportcheck.esp":
            self._respond("<response><hip-report-needed>yes</hip-report-needed></response>")
        elif path == "/ssl-vpn/hipreport.esp":
            report = form.get("report", "")
            if "<hip-report" not in report or "hyu-openconnect-win32-e2e" not in report:
                self._respond("invalid HIP report", status=400, content_type="text/plain")
                return
            marker = Path(os.environ["HYU_HIP_MARKER"])
            marker.write_text(report, encoding="utf-8")
            self._respond('<response status="success"/>')
        elif path == "/ssl-vpn/logout.esp":
            self._respond('<response status="success"/>')
        else:
            self.send_error(404)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument("certificate")
    parser.add_argument("private_key")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port is out of range")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.certificate, args.private_key)
    server = ThreadingHTTPServer((args.host, args.port), GlobalProtectHandler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
