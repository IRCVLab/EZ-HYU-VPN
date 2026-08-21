#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
WORKSPACE_VERSION="$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$ROOT/Cargo.toml" | head -1)"
VERSION="${VERSION:-$WORKSPACE_VERSION}"
SOURCE_COMPLIANCE_BUNDLE="${SOURCE_COMPLIANCE_BUNDLE:-}"
BUILD_ROOT="$(mktemp -d /private/tmp/hyu-vpn-macos-build.XXXXXX)"
RELEASE_OUTPUT_ROOT="$(mktemp -d /private/tmp/hyu-vpn-macos-output.XXXXXX)"
OUTPUT_ROOT="${OUTPUT_ROOT:-$ROOT/dist/macos}"
cleanup() { /bin/rm -rf -- "$BUILD_ROOT" "$RELEASE_OUTPUT_ROOT"; }
trap cleanup EXIT HUP INT TERM

if [[ "$(uname -s)" != Darwin || "$(uname -m)" != arm64 ]]; then
  echo "package-macos: an arm64 macOS host is required" >&2
  exit 2
fi
if [[ ! "$VERSION" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  echo "package-macos: VERSION must be semantic x.y.z" >&2
  exit 2
fi
if [[ "$VERSION" != "$WORKSPACE_VERSION" ]]; then
  echo "package-macos: VERSION must match Cargo workspace version $WORKSPACE_VERSION" >&2
  exit 2
fi
if [[ -z "$SOURCE_COMPLIANCE_BUNDLE" || ! -f "$SOURCE_COMPLIANCE_BUNDLE" || -L "$SOURCE_COMPLIANCE_BUNDLE" ]]; then
  echo "package-macos: SOURCE_COMPLIANCE_BUNDLE must name a regular file" >&2
  exit 2
fi

case "$OUTPUT_ROOT" in
  "$ROOT"/dist/*) ;;
  *) echo "package-macos: OUTPUT_ROOT must be inside $ROOT/dist" >&2; exit 2 ;;
esac

BREW_CANDIDATE="${BREW:-}"
if [[ -z "$BREW_CANDIDATE" ]]; then
  for candidate in /opt/homebrew/bin/brew /usr/local/bin/brew; do
    if [[ -x "$candidate" && ! -L "$candidate" ]]; then
      BREW_CANDIDATE="$candidate"
      break
    fi
  done
fi
case "$BREW_CANDIDATE" in
  /opt/homebrew/bin/brew|/usr/local/bin/brew) ;;
  *) echo "package-macos: Homebrew must use a standard absolute path" >&2; exit 2 ;;
esac
if [[ ! -x "$BREW_CANDIDATE" || -L "$BREW_CANDIDATE" ]]; then
  echo "package-macos: Homebrew is required" >&2
  exit 2
fi
BREW="$BREW_CANDIDATE"
BREW_PREFIX="$($BREW --prefix)"
OPENCONNECT="${OPENCONNECT:-$BREW_PREFIX/opt/openconnect/bin/openconnect}"
OATHTOOL="${OATHTOOL:-$BREW_PREFIX/opt/oath-toolkit/bin/oathtool}"
VPNC_SCRIPT="${VPNC_SCRIPT:-$BREW_PREFIX/etc/vpnc/vpnc-script}"
for required in "$OPENCONNECT" "$OATHTOOL" "$VPNC_SCRIPT"; do
  if [[ ! -f "$required" || ! -x "$required" || -L "$required" ]]; then
    echo "package-macos: missing regular executable $required" >&2
    exit 2
  fi
done

/bin/rm -rf -- "$OUTPUT_ROOT"
mkdir -p "$BUILD_ROOT/menu" "$BUILD_ROOT/installer" "$OUTPUT_ROOT"

swift build --package-path "$ROOT/macos" --configuration release --arch arm64
RELEASE_BIN="$ROOT/macos/.build/arm64-apple-macosx/release"
for executable in \
  HYUVPNMenuApp HYUVPNInstallerApp hyu-vpn-credential-reader \
  hyu-vpn-privileged-helper hyu-vpnc-wrapperd; do
  if [[ ! -x "$RELEASE_BIN/$executable" ]]; then
    echo "package-macos: missing Swift release executable $executable" >&2
    exit 2
  fi
done

cargo build --release --package hyu-vpn-macos-service --package hyu-vpn-hip
SERVICE_BIN="$ROOT/target/release/hyu-vpn-macos-service"
HIP_BIN="$ROOT/target/release/hyu-vpn-hip"
if [[ ! -f "$SERVICE_BIN" || ! -x "$SERVICE_BIN" ]]; then
  echo "package-macos: missing Rust service binary $SERVICE_BIN" >&2
  exit 2
fi
if [[ ! -f "$HIP_BIN" || ! -x "$HIP_BIN" ]]; then
  echo "package-macos: missing Rust HIP binary $HIP_BIN" >&2
  exit 2
fi
if [[ "$(lipo -archs "$SERVICE_BIN")" != "arm64" ]]; then
  echo "package-macos: service binary must be arm64" >&2
  exit 2
fi
if [[ "$(lipo -archs "$HIP_BIN")" != "arm64" ]]; then
  echo "package-macos: HIP binary must be arm64" >&2
  exit 2
fi

"$ROOT/macos/Scripts/assemble-menu-app.sh" \
  "$RELEASE_BIN/HYUVPNMenuApp" "$BUILD_ROOT/menu" "$VERSION" >/dev/null
"$ROOT/macos/Scripts/assemble-installer-app.sh" \
  "$RELEASE_BIN/HYUVPNInstallerApp" "$BUILD_ROOT/installer" "$VERSION" >/dev/null

python3 "$ROOT/scripts/package-release.py" \
  --assemble-from-repo \
  --repo-root "$ROOT" \
  --openconnect "$OPENCONNECT" \
  --oathtool "$OATHTOOL" \
  --vpnc-script "$VPNC_SCRIPT" \
  --service-executable "$SERVICE_BIN" \
  --hip-executable "$HIP_BIN" \
  --helper-executable "$RELEASE_BIN/hyu-vpn-privileged-helper" \
  --wrapperd-executable "$RELEASE_BIN/hyu-vpnc-wrapperd" \
  --menu-app "$BUILD_ROOT/menu/HYU VPN.app" \
  --installer-app "$BUILD_ROOT/installer/Install HYU VPN.app" \
  --source-compliance-bundle "$SOURCE_COMPLIANCE_BUNDLE" \
  --rebind-source-compliance-bundle \
  --build-root "$BUILD_ROOT/release" \
  --output-root "$RELEASE_OUTPUT_ROOT" \
  --version "$VERSION" \
  --arch arm64

generated="$RELEASE_OUTPUT_ROOT/HYU-VPN-$VERSION-arm64.dmg"
stable="$OUTPUT_ROOT/EZ-HYU-VPN-arm64.dmg"
[[ -f "$generated" ]] || { echo "package-macos: expected DMG is missing" >&2; exit 2; }
mv "$generated" "$stable"
rm -f "$generated.sha256"
(
  cd "$OUTPUT_ROOT"
  shasum -a 256 "$(basename "$stable")" > "$(basename "$stable").sha256"
)
printf '%s\n' "$stable"
