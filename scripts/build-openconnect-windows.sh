#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
VERSION=v9.21
SOURCE_URL="https://gitlab.com/openconnect/openconnect/-/archive/${VERSION}/openconnect-${VERSION}.tar.gz"
SOURCE_SHA256=ef0c875f3f8d8cc00e9647f36f87f2dd7d4ccad02c47c82f2dc5ba6b37edab06
CACHE_DIR=${OPENCONNECT_CACHE_DIR:-"$ROOT/target/openconnect-source-cache"}
BUILD_ROOT=${OPENCONNECT_BUILD_ROOT:-"$ROOT/target/openconnect-windows-build"}
OUTPUT_DIR=${OPENCONNECT_OUTPUT_DIR:-"$ROOT/target/openconnect-windows-patched"}
ARCHIVE="$CACHE_DIR/openconnect-v9.21.tar.gz"
SOURCE_DIR="$BUILD_ROOT/openconnect-v9.21"
PATCH_FILE="$ROOT/packaging/windows/openconnect-windows-hip.patch"
VPNC_SCRIPT="$ROOT/packaging/windows/vpnc-script-win.js"
VPNC_SCRIPT_SHA256=e196fdf0cc8b325180154535f843034dc0ae9eb43ead9980adfcfc57c58069b2
JOBS=${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)}

mkdir -p "$CACHE_DIR"
if [[ ! -f "$ARCHIVE" ]]; then
    partial=$(mktemp "$ARCHIVE.partial.XXXXXX")
    trap 'rm -f "$partial"' EXIT HUP INT TERM
    curl --fail --location --retry 3 --proto '=https' --tlsv1.2 \
        --connect-timeout 15 --max-time 180 --output "$partial" "$SOURCE_URL"
    printf '%s  %s\n' "$SOURCE_SHA256" "$partial" | sha256sum --check --strict
    mv -- "$partial" "$ARCHIVE"
    trap - EXIT HUP INT TERM
fi
printf '%s  %s\n' "$SOURCE_SHA256" "$ARCHIVE" | sha256sum --check --strict
rm -rf "$BUILD_ROOT" "$OUTPUT_DIR"
mkdir -p "$BUILD_ROOT" "$OUTPUT_DIR"
tar -xzf "$ARCHIVE" -C "$BUILD_ROOT"
git -C "$SOURCE_DIR" apply --check -p1 "$PATCH_FILE"
git -C "$SOURCE_DIR" apply -p1 "$PATCH_FILE"
printf '%s  %s\n' "$VPNC_SCRIPT_SHA256" "$VPNC_SCRIPT" | sha256sum --check --strict
install -m 0644 "$VPNC_SCRIPT" "$SOURCE_DIR/vpnc-script-win.js"

cd "$SOURCE_DIR"
export RPM_PACKAGE_VERSION=9.21
export RPM_PACKAGE_RELEASE=hyu1
./autogen.sh
mingw64-configure --without-gnutls-version-check CFLAGS='-O2 -g -fstack-protector-strong'
make -j"$JOBS"
export WINEPATH='/usr/x86_64-w64-mingw/bin;/usr/x86_64-w64-mingw32/sys-root/mingw/bin;.'
make VERBOSE=1 XFAIL_TESTS='list-taps.exe wintun-names.exe' -j"$JOBS" check
HELP_OUTPUT=$(WINEDEBUG=-all wine64 ./openconnect.exe --help 2>&1 || true)
grep -F -- '--csd-wrapper=SCRIPT' <<<"$HELP_OUTPUT"
"$ROOT/scripts/test-openconnect-windows-hip.sh" "$SOURCE_DIR"

install -m 0755 openconnect.exe "$OUTPUT_DIR/openconnect.exe"
install -m 0755 .libs/libopenconnect-5.dll "$OUTPUT_DIR/libopenconnect-5.dll"
(
    cd "$OUTPUT_DIR"
    sha256sum openconnect.exe libopenconnect-5.dll > SHA256SUMS
)
printf 'Patched OpenConnect %s Windows runtime built and tested at %s\n' "$VERSION" "$OUTPUT_DIR"
