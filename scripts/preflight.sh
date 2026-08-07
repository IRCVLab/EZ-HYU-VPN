#!/bin/sh
set -eu
export PYTHONDONTWRITEBYTECODE=1

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
    "visudo": "/usr/sbin/visudo",
}
BREW_DEPENDENCIES = [
    ("openconnect", "openconnect"),
    ("oath-toolkit", "oathtool"),
]


def executable(path: str) -> bool:
    return os.path.isfile(path) and os.access(path, os.X_OK)


def run_quiet(argv, *, input_text=None, env=None):
    return subprocess.run(
        argv,
        input=input_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        check=False,
    )


def run_with_private_tmp(argv, *, input_text=None, output_name=None):
    with tempfile.TemporaryDirectory(prefix="hyu-vpn-preflight-") as tmp:
        private_tmp = Path(tmp) / "tmp"
        private_tmp.mkdir()
        env = os.environ.copy()
        env["TMPDIR"] = f"{private_tmp}/"
        command = list(argv)
        if output_name is not None:
            command.extend(["-o", str(private_tmp / output_name)])
        return run_quiet(command, input_text=input_text, env=env)


def swift_metadata():
    swift = "/usr/bin/swift"
    swiftc = "/usr/bin/swiftc"
    result = run_with_private_tmp([swift, "--version"]) if executable(swift) else None
    version_output = result.stdout.strip() if result and result.returncode == 0 else ""
    match = re.search(r"Apple Swift version (\d+)(?:\.(\d+))?", version_output)
    major = int(match.group(1)) if match else 0
    minor = int(match.group(2) or 0) if match else 0

    appkit_compiles = False
    if executable(swiftc):
        with tempfile.TemporaryDirectory(prefix="hyu-vpn-preflight-swift-") as tmp:
            swift_env = os.environ.copy()
            swift_env["TMPDIR"] = f"{tmp}/"
            compile_result = run_quiet(
                [swiftc, "-", "-o", str(Path(tmp) / "AppKitProbe")],
                input_text="import AppKit\nlet _ = NSApplication.self\n",
                env=swift_env,
            )
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


def discover_brew_prefix():
    for prefix in SEARCHED_HOMEBREW_PREFIXES:
        brew = Path(prefix) / "bin" / "brew"
        if executable(str(brew)):
            return prefix, str(brew)
    return "", ""


def dependency_metadata(brew_prefix: str):
    dependencies = []
    for package, binary in BREW_DEPENDENCIES:
        package_prefix = str(Path(brew_prefix) / "opt" / package) if brew_prefix else ""
        binary_path = str(Path(package_prefix) / "bin" / binary) if package_prefix else ""
        dependencies.append(
            {
                "name": package,
                "binary": binary,
                "prefix": package_prefix if Path(package_prefix).is_dir() else "",
                "executable": binary_path if executable(binary_path) else "",
                "available": Path(package_prefix).is_dir() and executable(binary_path),
            }
        )
    return dependencies


brew_prefix, brew_path = discover_brew_prefix()
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
        "dependencies": dependency_metadata(brew_prefix),
    },
}

json.dump(metadata, sys.stdout, sort_keys=True, indent=2)
sys.stdout.write("\n")
PY
