#!/bin/zsh
set -euo pipefail
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
PAYLOAD_DIR="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)"
MODE="--package-audit"
if [[ $# -gt 0 ]]; then
  case "$1" in
    --package-audit) MODE="--package-audit"; shift ;;
    --live-install) MODE="--live-install"; shift ;;
    *) print -u2 "unexpected uninstaller option: $1"; exit 64 ;;
  esac
fi
[[ $# -eq 0 ]] || { print -u2 "unexpected uninstaller argument"; exit 64; }
if [[ ! -f "$PAYLOAD_DIR/manifest.json" ]]; then
  print -u2 "HYU VPN installer manifest is missing next to the payload."
  exit 66
fi
/usr/bin/python3 "$SCRIPT_DIR/manifest.py" --payload "$PAYLOAD_DIR" --manifest "$PAYLOAD_DIR/manifest.json" --verify-manifest
if [[ "$MODE" == "--package-audit" ]]; then
  print "Package uninstall audit complete. No files were removed."
  exit 0
fi
run_root_admin_live() {
  /usr/bin/sudo -v || return $?
  local LIVE_NONCE="hyu-install-mutation-$(/bin/date +%s)"
  /usr/bin/sudo -n /bin/zsh "$SCRIPT_DIR/root-admin.sh" "$@" --live-install "$LIVE_NONCE"
}
printf "Remove HYU VPN Keychain credentials? Type REMOVE to delete, anything else to retain: "
IFS= read -r KEYCHAIN_CHOICE
set +e
run_root_admin_live --payload "$PAYLOAD_DIR" --manifest "$PAYLOAD_DIR/manifest.json" --administrator-phase uninstall
STATUS=$?
set -e
if [[ $STATUS -eq 0 && "$KEYCHAIN_CHOICE" == "REMOVE" ]]; then
  /usr/bin/security delete-generic-password -s gp-vpn-username -a hyu-vpn >/dev/null 2>&1 || true
  /usr/bin/security delete-generic-password -s gp-vpn-password -a hyu-vpn >/dev/null 2>&1 || true
  /usr/bin/security delete-generic-password -s gp-vpn-totp -a hyu-vpn >/dev/null 2>&1 || true
fi
exit $STATUS
