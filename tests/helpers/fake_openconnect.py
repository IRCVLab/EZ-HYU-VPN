#!/usr/bin/env python3
import json
import os
import signal
import sys
import time
from pathlib import Path

responses = []
marker = Path(os.environ["FAKE_OPENCONNECT_MARKER"])
mode = os.environ.get("FAKE_OPENCONNECT_MODE", "dual")

def write(text):
    os.write(sys.stdout.fileno(), text.encode("utf-8"))
    sys.stdout.flush()

def read_line():
    line = sys.stdin.readline()
    if line == "":
        raise SystemExit(7)
    responses.append(line.rstrip("\n"))
    marker.write_text(json.dumps({"responses": responses, "pid": os.getpid(), "pgid": os.getpgrp()}, sort_keys=True), encoding="utf-8")
    return responses[-1]

def record_signal(signum, _frame):
    marker.write_text(json.dumps({"responses": responses, "pid": os.getpid(), "pgid": os.getpgrp(), "signal": signum}, sort_keys=True), encoding="utf-8")
    raise SystemExit(0)

signal.signal(signal.SIGINT, record_signal)
signal.signal(signal.SIGTERM, record_signal)
marker.write_text(json.dumps({"responses": responses, "pid": os.getpid(), "pgid": os.getpgrp()}, sort_keys=True), encoding="utf-8")

if mode == "helper_header":
    read_line()
    read_line()
    read_line()
    write("Challenge:")
    read_line()
    write("Password:")
    read_line()
    write("Challenge:")
    read_line()
    write("HIP report submitted successfully.\n")
    write("Session authentication will expire at Tue, 04 Aug 2026 21:59:30 KST\n")
    write("ESP session established with server\n")
    write("hyu-vpnc-wrapperd-event: network configuration verified\n")
    raise SystemExit(0)
elif mode == "sleep":
    while True:
        time.sleep(0.1)
elif mode == "error":
    write("fatal authentication error\n")
    raise SystemExit(5)
elif mode == "network_script_error":
    read_line()
    write("hyu-vpnc-wrapperd: recorded process did not match live process\n")
    write("PASSWORD-CANARY authcookie=COOKIE-CANARY USER-CANARY\n")
    while True:
        time.sleep(0.1)
elif mode == "eof_after_password":
    read_line()
    raise SystemExit(4)
elif mode == "close_stdin_on_challenge":
    read_line()
    os.close(sys.stdin.fileno())
    write("Chal")
    time.sleep(0.02)
    write("lenge:")
    time.sleep(0.2)
    raise SystemExit(6)
elif mode == "duplicate_prompts":
    read_line()
    write("Challenge:")
    read_line()
    write("Challenge:")
    read_line()
    raise SystemExit(0)
else:
    # --passwd-on-stdin consumes the initial portal password without a prompt.
    read_line()
    write("Chal")
    time.sleep(0.02)
    write("lenge:")
    read_line()
    # The gateway asks for the password again, then presents another bare Challenge:.
    write("Pass")
    time.sleep(0.02)
    write("word:")
    read_line()
    write("Chal")
    time.sleep(0.02)
    write("lenge:")
    read_line()
    write("connected\n")
    raise SystemExit(0)
