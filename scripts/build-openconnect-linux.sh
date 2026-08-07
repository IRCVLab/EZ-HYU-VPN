#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION=9.12
SHA256=a2bedce3aa4dfe75e36e407e48e8e8bc91d46def5335ac9564fbf91bd4b2413e
CACHE="${HYU_VPN_OPENCONNECT_CACHE:-$HOME/.cache/hyu-vpn-build/openconnect}"
ARCHIVE="${HYU_VPN_OPENCONNECT_ARCHIVE:-$CACHE/openconnect-$VERSION.tar.gz}"
OUTPUT="${HYU_VPN_OPENCONNECT_OUT:-$ROOT/target/openconnect-root}"
mkdir -p "$CACHE"

verify_archive() {
    [[ -f "$ARCHIVE" ]] &&
        printf '%s  %s\n' "$SHA256" "$ARCHIVE" | sha256sum -c - >/dev/null
}

if ! verify_archive; then
    partial="$(mktemp "$ARCHIVE.partial.XXXXXX")"
    cleanup_partial() {
        [[ -z "${partial:-}" ]] || rm -f -- "$partial"
    }
    trap cleanup_partial EXIT HUP INT TERM
    curl -fL --proto '=https' --tlsv1.2         --connect-timeout 15 --max-time 180         --retry 3 --retry-all-errors --retry-delay 2         "https://www.infradead.org/openconnect/download/openconnect-$VERSION.tar.gz"         -o "$partial"
    printf '%s  %s\n' "$SHA256" "$partial" | sha256sum -c -
    mv -- "$partial" "$ARCHIVE"
    partial=""
    trap - EXIT HUP INT TERM
fi

BUILD="$(mktemp -d)"
trap 'rm -rf "$BUILD"' EXIT
tar -xzf "$ARCHIVE" -C "$BUILD"
cd "$BUILD/openconnect-$VERSION"
./configure     --prefix=/usr/lib/hyu-vpn/runtime     --without-lz4     --without-libproxy     --without-stoken     --without-libpcsclite     --without-libpskc     --without-gssapi     --disable-nls
make -j"$(nproc)"
make check
make install DESTDIR="$BUILD/install"
python3 - "$OUTPUT" <<'PY'
import pathlib, shutil, sys
out=pathlib.Path(sys.argv[1])
if out.exists(): shutil.rmtree(out)
(out/"usr/lib/hyu-vpn/runtime/lib").mkdir(parents=True)
PY
install -m 0755     "$BUILD/install/usr/lib/hyu-vpn/runtime/sbin/openconnect"     "$OUTPUT/usr/lib/hyu-vpn/runtime/openconnect"
install -m 0644     "$BUILD/install/usr/lib/hyu-vpn/runtime/lib/libopenconnect.so.5.9.0"     "$OUTPUT/usr/lib/hyu-vpn/runtime/lib/libopenconnect.so.5.9.0"
ln -s libopenconnect.so.5.9.0 "$OUTPUT/usr/lib/hyu-vpn/runtime/lib/libopenconnect.so.5"
install -m 0644 COPYING.LGPL "$OUTPUT/usr/lib/hyu-vpn/runtime/COPYING.LGPL"
LD_LIBRARY_PATH="$OUTPUT/usr/lib/hyu-vpn/runtime/lib"     "$OUTPUT/usr/lib/hyu-vpn/runtime/openconnect" --version | grep -F "v$VERSION"
