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

if mode == "sleep":
    while True:
        time.sleep(0.1)
elif mode == "error":
    write("fatal authentication error\n")
    raise SystemExit(5)
elif mode == "eof_after_password":
    write("Pass")
    time.sleep(0.02)
    write("word:")
    read_line()
    raise SystemExit(4)
elif mode == "duplicate_prompts":
    write("Pass")
    time.sleep(0.02)
    write("word:")
    read_line()
    write("Challenge:")
    read_line()
    write("Challenge:")
    # Exit without reading a duplicate response; parent must not send twice for unchanged prompt tail.
    raise SystemExit(0)
else:
    write("Pass")
    time.sleep(0.02)
    write("word:")
    read_line()
    write("Chal")
    time.sleep(0.02)
    write("lenge:")
    read_line()
    write("Gateway Chal")
    time.sleep(0.02)
    write("lenge:")
    read_line()
    write("connected\n")
    raise SystemExit(0)
