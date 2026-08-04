#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: $0 FIXTURE_ROOT DESTINATION_DIR" >&2
  exit 64
fi

fixture_root=$1
destination_dir=$2
case "$fixture_root" in
  /*) ;;
  *) fixture_root="$PWD/$fixture_root" ;;
esac
case "$destination_dir" in
  /*) ;;
  *) destination_dir="$PWD/$destination_dir" ;;
esac
/usr/bin/python3 - "$destination_dir" "$(cd "$(dirname "$0")/.." && pwd -P)" <<'PY'
import pathlib, stat, sys
dest = pathlib.Path(sys.argv[1])
repo = pathlib.Path(sys.argv[2]).resolve(strict=False)
resolved = dest.resolve(strict=False)
forbidden = [pathlib.Path('/'), repo, pathlib.Path('/Applications'), pathlib.Path('/Library'), pathlib.Path('/System'), pathlib.Path('/usr')]
if dest.is_symlink() or any(resolved == root or (root != pathlib.Path('/') and root in resolved.parents) for root in forbidden):
    print(f"unsafe destination: {dest}", file=sys.stderr)
    raise SystemExit(73)
original = dest if dest.is_absolute() else pathlib.Path.cwd() / dest
probe = pathlib.Path('/')
for part in original.parts[1:-1]:
    probe = probe / part
    try:
        mode = probe.lstat().st_mode
    except FileNotFoundError:
        continue
    allowed = {pathlib.Path('/var'): pathlib.Path('/private/var'), pathlib.Path('/tmp'): pathlib.Path('/private/tmp')}
    is_allowed = probe in allowed and probe.resolve(strict=False) == allowed[probe]
    if stat.S_ISLNK(mode) and not is_allowed:
        print(f"unsafe destination symlink ancestor: {probe}", file=sys.stderr)
        raise SystemExit(73)
if pathlib.Path('/private') in resolved.parents or resolved == pathlib.Path('/private'):
    if not (resolved == pathlib.Path('/private/tmp') or pathlib.Path('/private/tmp') in resolved.parents or pathlib.Path('/private/var/folders') in resolved.parents or resolved == pathlib.Path('/private/var/folders')):
        print(f"unsafe non-temp private destination: {dest}", file=sys.stderr)
        raise SystemExit(73)
if dest.exists() and (not dest.is_dir() or any(dest.iterdir())):
    print(f"unsafe destination existing non-empty directory: {dest}", file=sys.stderr)
    raise SystemExit(73)
PY

app_name="HYU VPN.app"
executable_name="HYUVPNMenuApp"
bundle_id="com.hyu.vpn.menubar"
version="0.1.0"

source_file="$fixture_root/source/main.swift"
resources_dir="$fixture_root/resources"
app_dir="$destination_dir/$app_name"
contents_dir="$app_dir/Contents"
macos_dir="$contents_dir/MacOS"
resources_out="$contents_dir/Resources"
plist="$contents_dir/Info.plist"

if [ ! -f "$source_file" ]; then
  echo "missing fixture source: $source_file" >&2
  exit 66
fi

/bin/rm -rf "$app_dir"
/bin/mkdir -p "$macos_dir" "$resources_out"

/usr/bin/swiftc "$source_file" -o "$macos_dir/$executable_name"
/bin/chmod 0755 "$macos_dir/$executable_name"

if [ -d "$resources_dir" ]; then
  /usr/bin/find "$resources_dir" -type f ! -name '.DS_Store' -print | while IFS= read -r item; do
    rel=${item#"$resources_dir"/}
    target="$resources_out/$rel"
    /bin/mkdir -p "$(/usr/bin/dirname "$target")"
    /bin/cp "$item" "$target"
  done
fi

/usr/bin/python3 - "$plist" "$bundle_id" "$version" "$executable_name" <<'PY'
import plistlib
import sys
from pathlib import Path

plist_path = Path(sys.argv[1])
bundle_id = sys.argv[2]
version = sys.argv[3]
executable = sys.argv[4]
plist = {
    "CFBundleDevelopmentRegion": "en",
    "CFBundleExecutable": executable,
    "CFBundleIdentifier": bundle_id,
    "CFBundleInfoDictionaryVersion": "6.0",
    "CFBundleName": "HYU VPN",
    "CFBundlePackageType": "APPL",
    "CFBundleShortVersionString": version,
    "CFBundleVersion": version,
    "LSMinimumSystemVersion": "14.0",
    "LSUIElement": True,
    "NSHighResolutionCapable": True,
}
with plist_path.open("wb") as fh:
    plistlib.dump(plist, fh, sort_keys=True)
PY

/usr/bin/plutil -lint "$plist" >/dev/null
/usr/bin/codesign --force --sign - "$app_dir" >/dev/null
printf '%s\n' "$app_dir"
