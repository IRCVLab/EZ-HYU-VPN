#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$ROOT/Cargo.toml" | head -1)"
ARCH="$(dpkg --print-architecture)"
[[ "$ARCH" == amd64 ]] || { echo "Ubuntu package build requires amd64" >&2; exit 1; }
OUT="${HYU_VPN_OUT_DIR:-$ROOT/dist/linux}"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
PKG="$STAGE/hyu-vpn_${VERSION}_${ARCH}"

if [[ "${HYU_VPN_SKIP_OPENCONNECT_BUILD:-0}" != 1 ]]; then
    "$ROOT/scripts/build-openconnect-linux.sh"
fi
if [[ "${HYU_VPN_SKIP_BUILD:-0}" != 1 ]]; then
    # shellcheck source=/dev/null
    . "$HOME/.cargo/env" 2>/dev/null || true
    cargo build --manifest-path "$ROOT/Cargo.toml" --release \
        -p hyu-vpn-linux-service -p hyu-vpn-hip -p hyu-vpn-gtk --features hyu-vpn-gtk/gtk-ui
fi
install -d "$PKG/DEBIAN" "$PKG/usr/lib/hyu-vpn" "$PKG/usr/bin" \
    "$PKG/usr/lib/systemd/system" "$PKG/usr/share/applications" \
    "$PKG/usr/share/icons/hicolor/scalable/apps" "$PKG/usr/share/polkit-1/actions" \
    "$PKG/usr/share/doc/hyu-vpn"
install -m 0644 "$ROOT/packaging/linux/debian/control" "$PKG/DEBIAN/control"
for script in postinst prerm postrm; do
    install -m 0755 "$ROOT/packaging/linux/debian/$script" "$PKG/DEBIAN/$script"
done
test -x "$ROOT/target/openconnect-root/usr/lib/hyu-vpn/runtime/openconnect"
install -d "$PKG/usr/lib/hyu-vpn/runtime"
cp -a "$ROOT/target/openconnect-root/usr/lib/hyu-vpn/runtime/." "$PKG/usr/lib/hyu-vpn/runtime/"
install -m 0755 "$ROOT/target/release/hyu-vpn-linux-service" "$PKG/usr/lib/hyu-vpn/hyu-vpn-service"
install -m 0755 "$ROOT/target/release/hyu-vpn-hip" "$PKG/usr/lib/hyu-vpn/hyu-vpn-hip"
install -m 0755 "$ROOT/packaging/linux/hyu-vpnc-script" "$PKG/usr/lib/hyu-vpn/hyu-vpnc-script"
install -m 0755 "$ROOT/target/release/hyu-vpn-gtk" "$PKG/usr/bin/hyu-vpn"
install -m 0644 "$ROOT/packaging/linux/hyu-vpn.service" "$PKG/usr/lib/systemd/system/hyu-vpn.service"
install -m 0644 "$ROOT/packaging/linux/hyu-vpn.desktop" "$PKG/usr/share/applications/hyu-vpn.desktop"
install -m 0644 "$ROOT/assets/icons/hyu-vpn.svg" "$PKG/usr/share/icons/hicolor/scalable/apps/hyu-vpn.svg"
install -m 0644 "$ROOT/packaging/linux/com.hyu.vpn.policy" "$PKG/usr/share/polkit-1/actions/com.hyu.vpn.policy"
install -m 0644 "$ROOT/LICENSE" "$PKG/usr/share/doc/hyu-vpn/copyright"
printf 'OpenConnect 9.12 is bundled under LGPL-2.1; source and build recipe: https://www.infradead.org/openconnect/download/openconnect-9.12.tar.gz and scripts/build-openconnect-linux.sh. vpnc-scripts is a system dependency.\n' \
    > "$PKG/usr/share/doc/hyu-vpn/third-party-notices"
chmod 0644 "$PKG/usr/share/doc/hyu-vpn/third-party-notices"
find "$PKG" -type d -exec chmod 0755 {} +
mkdir -p "$OUT"
DEB="$OUT/hyu-vpn_${VERSION}_${ARCH}.deb"
dpkg-deb --build --root-owner-group "$PKG" "$DEB"
sha256sum "$DEB" > "$DEB.sha256"
printf '%s\n' "$DEB"
