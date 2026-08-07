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
USER_UID="$(/usr/bin/id -u)"
menubar_process_count() { /usr/bin/pgrep -u "$USER_UID" -x HYUVPNMenuApp 2>/dev/null | /usr/bin/wc -l | /usr/bin/tr -d ' '; }
wait_for_menubar_exit() {
  local attempt=0
  while [[ "$(menubar_process_count)" != "0" && $attempt -lt 50 ]]; do
    /bin/sleep 0.1
    attempt=$((attempt + 1))
  done
  [[ "$(menubar_process_count)" == "0" ]]
}
terminate_menubar() {
  /usr/bin/pkill -TERM -u "$USER_UID" -x HYUVPNMenuApp >/dev/null 2>&1 || true
  wait_for_menubar_exit && return 0
  /usr/bin/pkill -KILL -u "$USER_UID" -x HYUVPNMenuApp >/dev/null 2>&1 || true
  wait_for_menubar_exit || { print -u2 "could not stop existing HYU VPN menu process"; return 1; }
}
unregister_login_item() {
  local app_exec="${HYU_VPN_TEST_APP_EXEC:-/Applications/HYU VPN.app/Contents/MacOS/HYUVPNMenuApp}"
  if [[ -n "${HYU_VPN_TEST_APP_EXEC:-}" ]]; then
    case "$app_exec" in /tmp/*|/private/tmp/*|/var/folders/*|/private/var/folders/*) ;; *) print -u2 "unsafe test app exec override"; return 65 ;; esac
  fi
  [[ -x "$app_exec" ]] || return 0
  local output unregister_status
  set +e
  output="$("$app_exec" --unregister-login-item 2>&1)"
  unregister_status=$?
  set -e
  if [[ $unregister_status -eq 0 ]]; then return 0; fi
  [[ "$output" == *LOGIN_ITEM_NOT_REGISTERED* || "$output" == *LOGIN_ITEM_NOT_FOUND* ]] && return 0
  print -u2 "HYU VPN login item unregister failed: $output"
  return $unregister_status
}
unregister_login_item
terminate_menubar
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
