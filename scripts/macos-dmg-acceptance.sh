#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
DMG="${1:-}"
if [[ $# -ne 1 || -z "$DMG" ]]; then
  echo "usage: scripts/macos-dmg-acceptance.sh path/to/EZ-HYU-VPN-arm64.dmg" >&2
  exit 2
fi
case "$DMG" in
  /*) ;;
  *) DMG="$PWD/$DMG" ;;
esac
DMG="$(cd "$(dirname "$DMG")" && pwd -P)/$(basename "$DMG")"
if [[ ! -f "$DMG" || -L "$DMG" ]]; then
  echo "macos-dmg-acceptance: DMG must be a regular file: $DMG" >&2
  exit 2
fi
case "$DMG" in
  "$ROOT"/dist/*|/private/tmp/*|/var/folders/*) ;;
  *) echo "macos-dmg-acceptance: refusing DMG outside repo dist or temp roots: $DMG" >&2; exit 2 ;;
esac

MOUNT_PARENT="$(mktemp -d /private/tmp/hyu-vpn-dmg-acceptance.XXXXXX)"
mountpoint="$MOUNT_PARENT/mount"
mkdir "$mountpoint"
attached=0
cleanup_error=0
cleanup_detach() {
  local attempt
  for attempt in 1 2 3; do
    if hdiutil detach "$mountpoint" >/dev/null 2>"$MOUNT_PARENT/detach.err"; then
      rm -f -- "$MOUNT_PARENT/detach.err"
      attached=0
      return 0
    fi
    sleep 1
  done
  printf 'macos-dmg-acceptance: cleanup-failed:detach\n' >&2
  return 1
}
cleanup_dirs() {
  rm -f -- "$MOUNT_PARENT/detach.err"
  rmdir "$mountpoint" >/dev/null 2>&1 || true
  rmdir "$MOUNT_PARENT" >/dev/null 2>&1 || true
}
cleanup() {
  local status=$?
  if [[ "$attached" = 1 ]]; then
    if ! cleanup_detach; then
      cleanup_error=1
    fi
  fi
  cleanup_dirs
  if [[ "$status" -ne 0 ]]; then
    exit "$status"
  fi
  if [[ "$cleanup_error" -ne 0 ]]; then
    exit 1
  fi
}
trap cleanup EXIT HUP INT TERM

hdiutil verify "$DMG"
hdiutil attach -readonly -nobrowse -mountpoint "$mountpoint" "$DMG" >/dev/null
attached=1

for required_path in \
  "HYU VPN.app/Contents/MacOS/HYUVPNMenuApp" \
  "Install HYU VPN.app/Contents/MacOS/HYUVPNInstallerApp" \
  "hyu-vpn-macos-service" \
  "com.hyu.vpn.helper" \
  "runtime/gp-hip-report" \
  "launchd/com.hyu.vpn.service.plist.in"; do
  test -f "$mountpoint/$required_path"
  shasum -a 256 "$mountpoint/$required_path" >/dev/null
  stat -f '%OLp %z' "$mountpoint/$required_path" >/dev/null
done

python3 - "$mountpoint" <<'PY'
import hashlib
import json
import os
import plistlib
import stat
import sys
from pathlib import Path

MAX_FILE_BYTES = int(os.environ.get("HYU_DMG_ACCEPTANCE_MAX_FILE_BYTES", str(128 * 1024 * 1024)))
MAX_TOTAL_BYTES = int(os.environ.get("HYU_DMG_ACCEPTANCE_MAX_TOTAL_BYTES", str(768 * 1024 * 1024)))
CHUNK_SIZE = 1024 * 1024
FORBIDDEN = [
    (b"hyu-vpn-service", "legacy-backend"),
    (b"hyu-vpn-control", "legacy-backend"),
    (b"hyu-vpn-connect", "legacy-backend"),
    (b"hyu-vpn-native-client", "legacy-backend"),
    (b"src/hyu_vpn", "legacy-backend"),
    (b"/usr/bin/python3", "python-runtime"),
    (b"/usr/bin/py", "python-runtime"),
    (b"thon3", "python-runtime"),
    (b"PYTHON3_PATH", "python-runtime"),
]
OPAQUE_CONTENT_EXEMPT = {"SOURCE-COMPLIANCE-BUNDLE.tar.gz"}
BINARY_CONTENT_PREFIX_EXEMPT = (
    "HYU VPN.app/Contents/MacOS/",
    "Install HYU VPN.app/Contents/MacOS/",
)
BINARY_CONTENT_SUFFIX_EXEMPT = (".icns",)
REQUIRED_PATHS = {
    "HYU VPN.app/Contents/MacOS/HYUVPNMenuApp",
    "Install HYU VPN.app/Contents/MacOS/HYUVPNInstallerApp",
    "hyu-vpn-macos-service",
    "com.hyu.vpn.helper",
    "runtime/gp-hip-report",
    "launchd/com.hyu.vpn.service.plist.in",
}

def fail(code: str, rel: str = "") -> None:
    if rel:
        safe = rel.encode("unicode_escape", "backslashreplace").decode("ascii")[:240]
        raise SystemExit(f"macos-dmg-acceptance: {code}:{safe}")
    raise SystemExit(f"macos-dmg-acceptance: {code}")

def reject_forbidden_path(rel: str) -> None:
    rel_bytes = rel.encode("utf-8", "surrogateescape")
    for token, category in FORBIDDEN:
        if token in rel_bytes:
            fail(f"forbidden-token:path:{category}", rel)

def streaming_sha256(path: Path, expected_size: int) -> str:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb", buffering=0) as fh:
        while True:
            chunk = fh.read(CHUNK_SIZE)
            if not chunk:
                break
            total += len(chunk)
            if total > expected_size:
                fail("size-mismatch:file", path.name)
            digest.update(chunk)
    if total != expected_size:
        fail("size-mismatch:file", path.name)
    return digest.hexdigest()

def should_scan_content(rel: str, path: Path) -> bool:
    if rel in OPAQUE_CONTENT_EXEMPT:
        return False
    if rel.startswith(BINARY_CONTENT_PREFIX_EXEMPT) or rel.endswith(BINARY_CONTENT_SUFFIX_EXEMPT):
        return False
    with path.open("rb", buffering=0) as fh:
        sample = fh.read(4096)
    if b"\0" in sample:
        return False
    return True

def scan_content(rel: str, path: Path) -> None:
    if not should_scan_content(rel, path):
        return
    tails = b""
    max_token = max(len(token) for token, _ in FORBIDDEN)
    with path.open("rb", buffering=0) as fh:
        while True:
            chunk = fh.read(CHUNK_SIZE)
            if not chunk:
                break
            window = tails + chunk
            for token, category in FORBIDDEN:
                if token in window:
                    fail(f"forbidden-token:content:{category}", rel)
            tails = window[-max_token:]

root = Path(sys.argv[1]).resolve(strict=True)
manifest_path = root / "manifest.json"
manifest_stat = os.lstat(manifest_path)
if not stat.S_ISREG(manifest_stat.st_mode) or stat.S_IMODE(manifest_stat.st_mode) != 0o644 or manifest_stat.st_size > 4 * 1024 * 1024:
    fail("manifest-metadata")
try:
    expected_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
except Exception:
    fail("manifest-parse")
if expected_manifest.get("schema") != 1 or not isinstance(expected_manifest.get("files"), dict):
    fail("manifest-schema")
for rel in REQUIRED_PATHS:
    if rel not in expected_manifest["files"]:
        fail("manifest-missing-required", rel)
for rel, meta in expected_manifest["files"].items():
    reject_forbidden_path(rel)
    if not isinstance(meta, dict) or set(meta) != {"sha256", "size", "mode"}:
        fail("manifest-entry-schema", rel)
    if not isinstance(meta["sha256"], str) or len(meta["sha256"]) != 64 or any(ch not in "0123456789abcdef" for ch in meta["sha256"]):
        fail("manifest-entry-sha", rel)
    if not isinstance(meta["size"], int) or meta["size"] < 0:
        fail("manifest-entry-size", rel)
    if not isinstance(meta["mode"], str) or not meta["mode"].isdigit() or len(meta["mode"]) != 4:
        fail("manifest-entry-mode", rel)
    if meta["size"] > MAX_FILE_BYTES:
        fail("size-limit:file", rel)
if sum(meta["size"] for meta in expected_manifest["files"].values()) > MAX_TOTAL_BYTES:
    fail("size-limit:total")

actual_manifest = {key: expected_manifest[key] for key in expected_manifest if key != "files"}
actual_manifest["files"] = {}
for current, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
    current_path = Path(current)
    current_rel = current_path.relative_to(root).as_posix() if current_path != root else "."
    reject_forbidden_path(current_rel)
    for dirname in list(dirnames):
        child = current_path / dirname
        rel = child.relative_to(root).as_posix()
        reject_forbidden_path(rel)
        st = os.lstat(child)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            fail("special-entry", rel)
    for filename in filenames:
        child = current_path / filename
        rel = child.relative_to(root).as_posix()
        reject_forbidden_path(rel)
        st = os.lstat(child)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            fail("special-entry", rel)
        if rel == "manifest.json":
            continue
        if rel not in expected_manifest["files"]:
            fail("unmanifested-file", rel)
        expected = expected_manifest["files"][rel]
        actual_size = st.st_size
        if actual_size > MAX_FILE_BYTES:
            fail("size-limit:file", rel)
        if actual_size != expected["size"]:
            fail("size-mismatch:file", rel)
        actual = {
            "sha256": streaming_sha256(child, actual_size),
            "size": actual_size,
            "mode": f"{stat.S_IMODE(st.st_mode):04o}",
        }
        actual_manifest["files"][rel] = actual
        scan_content(rel, child)

expected_files = set(expected_manifest["files"])
actual_files = set(actual_manifest["files"])
if expected_files != actual_files:
    fail("file-set-mismatch")
if actual_manifest != expected_manifest:
    fail("manifest-identity-mismatch")

plist_path = root / "launchd/com.hyu.vpn.service.plist.in"
plist_st = os.lstat(plist_path)
if plist_st.st_size > MAX_FILE_BYTES:
    fail("size-limit:file", "launchd/com.hyu.vpn.service.plist.in")
plist_text = plist_path.read_text(encoding="utf-8")
rendered = plist_text.replace("@USER_HOME@", "/Users/tester").replace("@SERVICE_PATH@", "/Library/Application Support/HYU VPN/bin/hyu-vpn-macos-service")
try:
    service = plistlib.loads(rendered.encode("utf-8"))
except Exception:
    fail("launchd-parse")
if service.get("ProgramArguments") != ["/Library/Application Support/HYU VPN/bin/hyu-vpn-macos-service"]:
    fail("launchd-rust-direct")
PY

codesign --verify --deep --strict "$mountpoint/HYU VPN.app"
codesign --verify --deep --strict "$mountpoint/Install HYU VPN.app"
for executable in \
  "HYU VPN.app/Contents/MacOS/HYUVPNMenuApp" \
  "Install HYU VPN.app/Contents/MacOS/HYUVPNInstallerApp" \
  "hyu-vpn-macos-service" \
  "com.hyu.vpn.helper" \
  "runtime/gp-hip-report"; do
  test -x "$mountpoint/$executable"
  test "$(lipo -archs "$mountpoint/$executable")" = arm64
  codesign --verify --deep --strict "$mountpoint/$executable"
done

cleanup_detach
attached=0
cleanup_dirs
printf 'macos-dmg-acceptance: PASS %s\n' "$DMG"
