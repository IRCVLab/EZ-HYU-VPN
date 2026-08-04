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
