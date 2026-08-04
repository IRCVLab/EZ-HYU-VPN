#!/usr/bin/env python3
import json
import os
from pathlib import Path

path = Path(os.environ["FAKE_OATHTOOL_STATE"])
state = json.loads(path.read_text(encoding="utf-8"))
calls = int(state.get("calls", 0))
values = list(state.get("values", []))
value = values[calls] if calls < len(values) else values[-1]
state["calls"] = calls + 1
path.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
if value == "__FAIL__":
    raise SystemExit(3)
print(value)
