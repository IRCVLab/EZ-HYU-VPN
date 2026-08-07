#!/bin/sh
set -eu
if [ "$#" -ne 2 ]; then echo "usage: $0 RELEASE_EXECUTABLE DESTINATION_DIR" >&2; exit 64; fi
exe=$1
dest=$2
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
plutil -lint "$plist" >/dev/null
codesign --force --sign - "$macos_dir/HYUVPNInstallerApp" >/dev/null
codesign --force --sign - "$app" >/dev/null
codesign --verify --deep --strict "$app" >/dev/null
printf '%s\n' "$app"
