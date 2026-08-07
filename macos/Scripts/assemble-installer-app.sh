#!/bin/sh
set -eu
if [ "$#" -ne 3 ]; then echo "usage: $0 RELEASE_EXECUTABLE DESTINATION_DIR VERSION" >&2; exit 64; fi
exe=$1
dest=$2
version=$3
/usr/bin/python3 - "$version" <<'PY'
import re, sys
if re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", sys.argv[1]) is None:
    print("invalid semantic version", file=sys.stderr)
    raise SystemExit(64)
PY
case "$exe" in /*) ;; *) exe="$PWD/$exe" ;; esac
case "$dest" in /*) ;; *) dest="$PWD/$dest" ;; esac
app="$dest/Install HYU VPN.app"
contents="$app/Contents"
macos_dir="$contents/MacOS"
resources="$contents/Resources"
plist="$contents/Info.plist"
if [ ! -x "$exe" ]; then echo "missing executable: $exe" >&2; exit 66; fi
rm -rf "$app"
mkdir -p "$macos_dir" "$resources"
cp "$exe" "$macos_dir/HYUVPNInstallerApp"
cp "$(dirname "$0")/../Resources/AppIcon.icns" "$resources/AppIcon.icns"
chmod 0755 "$macos_dir/HYUVPNInstallerApp"
cp "$(dirname "$0")/../Resources/HYUVPNInstallerApp/Info.plist" "$plist"
plutil -insert CFBundleShortVersionString -string "$version" "$plist"
plutil -insert CFBundleVersion -string "$version" "$plist"
plutil -lint "$plist" >/dev/null
codesign --force --sign - "$macos_dir/HYUVPNInstallerApp" >/dev/null
codesign --force --sign - "$app" >/dev/null
codesign --verify --deep --strict "$app" >/dev/null
printf '%s\n' "$app"
