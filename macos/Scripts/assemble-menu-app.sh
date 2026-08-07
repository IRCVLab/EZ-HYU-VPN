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
reader="$(dirname "$exe")/hyu-vpn-credential-reader"
/usr/bin/python3 - "$dest" "$(cd "$(dirname "$0")/../.." && pwd -P)" <<'PY'
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
app="$dest/HYU VPN.app"
contents="$app/Contents"
macos_dir="$contents/MacOS"
resources="$contents/Resources"
plist="$contents/Info.plist"
if [ ! -x "$exe" ]; then echo "missing executable: $exe" >&2; exit 66; fi
if [ ! -x "$reader" ]; then echo "missing executable: $reader" >&2; exit 66; fi
rm -rf "$app"
mkdir -p "$macos_dir" "$resources"
cp "$exe" "$macos_dir/HYUVPNMenuApp"
cp "$reader" "$macos_dir/HYUVPNCredentialReader"
cp "$(dirname "$0")/../Resources/AppIcon.icns" "$resources/AppIcon.icns"
chmod 0755 "$macos_dir/HYUVPNMenuApp"
chmod 0755 "$macos_dir/HYUVPNCredentialReader"
cp "$(dirname "$0")/../Resources/HYUVPNMenuApp/Info.plist" "$plist"
plutil -insert CFBundleShortVersionString -string "$version" "$plist"
plutil -insert CFBundleVersion -string "$version" "$plist"
plutil -insert HYUUpdateFeedURL -string "https://raw.githubusercontent.com/IRCVLab/EZ-HYU-VPN/main/update.json" "$plist"
plutil -insert HYUUpdateAllowedReleaseHost -string "github.com" "$plist"
plutil -insert HYUUpdateAllowedReleasePathPrefix -string "/IRCVLab/EZ-HYU-VPN/releases/" "$plist"
plutil -lint "$plist" >/dev/null
codesign --force --sign - "$macos_dir/HYUVPNMenuApp" >/dev/null
codesign --force --sign - "$macos_dir/HYUVPNCredentialReader" >/dev/null
codesign --force --sign - "$app" >/dev/null
codesign --verify --deep --strict "$app" >/dev/null
printf '%s\n' "$app"
