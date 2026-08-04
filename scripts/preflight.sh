#!/bin/sh
set -eu

/usr/bin/python3 - <<'PY'
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
from pathlib import Path

SEARCHED_HOMEBREW_PREFIXES = ["/opt/homebrew", "/usr/local"]
REQUIRED_TOOLS = {
    "codesign": "/usr/bin/codesign",
    "hdiutil": "/usr/bin/hdiutil",
    "plutil": "/usr/bin/plutil",
    "security": "/usr/bin/security",
    "visudo": "/usr/sbin/visudo",
}
BREW_DEPENDENCIES = [
    ("openconnect", "openconnect"),
    ("oath-toolkit", "oathtool"),
]


def executable(path: str) -> bool:
    return os.path.isfile(path) and os.access(path, os.X_OK)


def run_quiet(argv):
    return subprocess.run(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)


def swift_metadata():
    swift = "/usr/bin/swift"
    swiftc = "/usr/bin/swiftc"
    result = run_quiet([swift, "--version"]) if executable(swift) else None
    version_output = result.stdout.strip() if result and result.returncode == 0 else ""
    match = re.search(r"Apple Swift version (\d+)(?:\.(\d+))?", version_output)
    major = int(match.group(1)) if match else 0
    minor = int(match.group(2) or 0) if match else 0

    appkit_compiles = False
    if executable(swiftc):
        with tempfile.TemporaryDirectory(prefix="hyu-vpn-preflight-") as tmp:
            source = Path(tmp) / "AppKitProbe.swift"
            source.write_text("import AppKit\nlet _ = NSApplication.self\n", encoding="utf-8")
            compile_result = run_quiet([swiftc, "-typecheck", str(source)])
            appkit_compiles = compile_result.returncode == 0

    return {
        "path": swift,
        "compiler_path": swiftc,
        "available": executable(swift) and executable(swiftc),
        "version": version_output.splitlines()[0] if version_output else "",
        "major_version": major,
        "minor_version": minor,
        "appkit_compiles": appkit_compiles,
    }


def tool_metadata():
    return {
        name: {"path": path, "available": executable(path)}
        for name, path in REQUIRED_TOOLS.items()
    }


def discover_brew():
    for prefix in SEARCHED_HOMEBREW_PREFIXES:
        brew = Path(prefix) / "bin" / "brew"
        if executable(str(brew)):
            return prefix, str(brew)
    return "", ""


def dependency_metadata(brew_path: str):
    dependencies = []
    for package, binary in BREW_DEPENDENCIES:
        prefix = ""
        if brew_path:
            result = run_quiet([brew_path, "--prefix", package])
            if result.returncode == 0:
                prefix = result.stdout.strip().splitlines()[0]
        binary_path = str(Path(prefix) / "bin" / binary) if prefix else ""
        dependencies.append(
            {
                "name": package,
                "binary": binary,
                "prefix": prefix,
                "executable": binary_path,
                "available": bool(prefix) and executable(binary_path),
            }
        )
    return dependencies


brew_prefix, brew_path = discover_brew()
metadata = {
    "schema_version": 1,
    "read_only": True,
    "host_arch": platform.machine(),
    "supported_host_architectures": ["arm64", "x86_64"],
    "swift": swift_metadata(),
    "tools": tool_metadata(),
    "homebrew": {
        "searched_prefixes": SEARCHED_HOMEBREW_PREFIXES,
        "prefix": brew_prefix,
        "brew_path": brew_path,
        "dependencies": dependency_metadata(brew_path),
    },
}

json.dump(metadata, sys.stdout, sort_keys=True, indent=2)
sys.stdout.write("\n")
PY
