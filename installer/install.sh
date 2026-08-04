#!/bin/zsh
set -euo pipefail
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
PAYLOAD_DIR="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)"
MODE="--package-audit"
if [[ $# -gt 0 ]]; then
  case "$1" in
    --package-audit) MODE="--package-audit"; shift ;;
    --live-install) MODE="--live-install"; shift ;;
    *) print -u2 "unexpected installer option: $1"; exit 64 ;;
  esac
fi
[[ $# -eq 0 ]] || { print -u2 "unexpected installer argument"; exit 64; }
if [[ ! -f "$PAYLOAD_DIR/manifest.json" ]]; then
  print -u2 "HYU VPN installer manifest is missing next to the payload."
  exit 66
fi
/usr/bin/python3 "$SCRIPT_DIR/manifest.py" --payload "$PAYLOAD_DIR" --manifest "$PAYLOAD_DIR/manifest.json" --verify-manifest
if [[ "$MODE" == "--package-audit" ]]; then
  /usr/bin/python3 "$SCRIPT_DIR/manifest.py" --payload "$PAYLOAD_DIR" --manifest "$PAYLOAD_DIR/manifest.json" --package-audit
  print "Package audit complete. No files were installed. Re-run with --live-install for a real install."
  exit 0
fi
LIVE_NONCE="hyu-install-mutation-$(/bin/date +%s)"
STAGE_DIR="$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/hyu-vpn-stage.XXXXXX")"
KEYCHAIN_CREATED_FILE="$(/usr/bin/mktemp "${TMPDIR:-/tmp}/hyu-vpn-keychain.XXXXXX")"
KEYCHAIN_TMP_SUFFIX="$(/usr/bin/uuidgen | /usr/bin/tr 'A-Z' 'a-z')"
TMP_USER_SERVICE="hyu-vpn-install-username-$KEYCHAIN_TMP_SUFFIX"
TMP_PASS_SERVICE="hyu-vpn-install-password-$KEYCHAIN_TMP_SUFFIX"
TMP_TOTP_SERVICE="hyu-vpn-install-totp-$KEYCHAIN_TMP_SUFFIX"
cleanup() { /usr/bin/security delete-generic-password -s "$TMP_USER_SERVICE" -a hyu-vpn >/dev/null 2>&1 || true; /usr/bin/security delete-generic-password -s "$TMP_PASS_SERVICE" -a hyu-vpn >/dev/null 2>&1 || true; /usr/bin/security delete-generic-password -s "$TMP_TOTP_SERVICE" -a hyu-vpn >/dev/null 2>&1 || true; /bin/rm -rf "$STAGE_DIR" "$KEYCHAIN_CREATED_FILE"; }
keychain_exists() { /usr/bin/security find-generic-password -s "$1" -a hyu-vpn >/dev/null 2>&1; }
record_keychain_created() { print -r -- "$1" >> "$KEYCHAIN_CREATED_FILE"; }
rollback_keychain() {
  [[ -f "$KEYCHAIN_CREATED_FILE" ]] || return 0
  while IFS= read -r item; do
    [[ -n "$item" ]] && /usr/bin/security delete-generic-password -s "$item" -a hyu-vpn >/dev/null 2>&1 || true
  done < "$KEYCHAIN_CREATED_FILE"
}
trap cleanup EXIT
trap 'rollback_keychain; cleanup; exit 130' INT TERM
/usr/bin/python3 "$SCRIPT_DIR/manifest.py" --payload "$PAYLOAD_DIR" --manifest "$PAYLOAD_DIR/manifest.json" --stage-user-payload --stage-dir "$STAGE_DIR"
PACKAGE_MANIFEST_SHA256="$(/usr/bin/shasum -a 256 "$PAYLOAD_DIR/manifest.json" | /usr/bin/awk '{print $1}')"
STAGE_MANIFEST_SHA256="$(/usr/bin/shasum -a 256 "$STAGE_DIR/manifest.json" | /usr/bin/awk '{print $1}')"
[[ "$PACKAGE_MANIFEST_SHA256" == [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f] ]] || { print -u2 "invalid package manifest digest"; exit 65; }
[[ "$STAGE_MANIFEST_SHA256" == [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f] ]] || { print -u2 "invalid staged manifest digest"; exit 65; }
printf "HYU VPN username: "
IFS= read -r HYU_VPN_USERNAME
[[ -n "$HYU_VPN_USERNAME" && "$HYU_VPN_USERNAME" != *[$'\001'-$'\037'$'\177']* && ${#HYU_VPN_USERNAME} -le 128 ]] || { print -u2 "invalid HYU VPN username"; exit 65; }
# Store credentials only in random temporary Keychain services until root install succeeds.
# Existing final credentials are never overwritten by this installer; missing finals are created only after root install succeeds.
: > "$KEYCHAIN_CREATED_FILE"
FINAL_USER_EXISTS=0; keychain_exists gp-vpn-username && FINAL_USER_EXISTS=1 || true
FINAL_PASS_EXISTS=0; keychain_exists gp-vpn-password && FINAL_PASS_EXISTS=1 || true
FINAL_TOTP_EXISTS=0; keychain_exists gp-vpn-totp && FINAL_TOTP_EXISTS=1 || true
if [[ $FINAL_USER_EXISTS -eq 0 ]]; then /usr/bin/security add-generic-password -s "$TMP_USER_SERVICE" -a hyu-vpn -w "$HYU_VPN_USERNAME" || { cleanup; exit 1; }; fi
if [[ $FINAL_PASS_EXISTS -eq 0 ]]; then
  print "HYU VPN password (not the Mac administrator password): enter it twice at the next prompts."
  /usr/bin/security add-generic-password -s "$TMP_PASS_SERVICE" -a hyu-vpn -w || { cleanup; exit 1; }
fi
if [[ $FINAL_TOTP_EXISTS -eq 0 ]]; then
  print "TOTP secret seed (not the current 6-digit OTP code): enter the authenticator setup secret twice at the next prompts."
  /usr/bin/security add-generic-password -s "$TMP_TOTP_SERVICE" -a hyu-vpn -w || { cleanup; exit 1; }
fi
# Exactly one administrator-authentication phase begins after manifest verification, staging, and credentials.
print "Mac administrator authorization: the next Password prompt is your Mac login password."
set +e
/usr/bin/sudo /bin/zsh "$SCRIPT_DIR/root-admin.sh" --payload "$PAYLOAD_DIR" --manifest "$PAYLOAD_DIR/manifest.json" --stage "$STAGE_DIR" --administrator-phase install --stage-manifest-sha256 "$STAGE_MANIFEST_SHA256" --package-manifest-sha256 "$PACKAGE_MANIFEST_SHA256" --live-install "$LIVE_NONCE"
STATUS=$?
set -e
if [[ $STATUS -ne 0 ]]; then cleanup; exit $STATUS; fi
promote_failed=0
if [[ $FINAL_USER_EXISTS -eq 0 ]]; then
  if /usr/bin/security add-generic-password -s gp-vpn-username -a hyu-vpn -w "$HYU_VPN_USERNAME"; then record_keychain_created gp-vpn-username; else promote_failed=1; fi
fi
if [[ $promote_failed -eq 0 && $FINAL_PASS_EXISTS -eq 0 ]]; then
  if /usr/bin/security find-generic-password -w -s "$TMP_PASS_SERVICE" -a hyu-vpn | /usr/bin/security add-generic-password -s gp-vpn-password -a hyu-vpn -w; then record_keychain_created gp-vpn-password; else promote_failed=1; fi
fi
if [[ $promote_failed -eq 0 && $FINAL_TOTP_EXISTS -eq 0 ]]; then
  if /usr/bin/security find-generic-password -w -s "$TMP_TOTP_SERVICE" -a hyu-vpn | /usr/bin/security add-generic-password -s gp-vpn-totp -a hyu-vpn -w; then record_keychain_created gp-vpn-totp; else promote_failed=1; fi
fi
if [[ $promote_failed -ne 0 ]]; then
  rollback_keychain
  set +e
  /usr/bin/sudo /bin/zsh "$SCRIPT_DIR/root-admin.sh" --payload "$PAYLOAD_DIR" --manifest "$PAYLOAD_DIR/manifest.json" --administrator-phase uninstall --live-install "hyu-install-mutation-$(/bin/date +%s)"
  CLEANUP_STATUS=$?
  set -e
  if [[ $CLEANUP_STATUS -ne 0 ]]; then
    print -u2 "HYU VPN root rollback incomplete after keychain promotion failure: root-admin uninstall exited $CLEANUP_STATUS"
    cleanup
    exit 70
  fi
  cleanup
  exit 1
fi
USER_UID="$(/usr/bin/id -u)"
SERVICE_PLIST="$HOME/Library/LaunchAgents/com.hyu.vpn.service.plist"
MENUBAR_PLIST="$HOME/Library/LaunchAgents/com.hyu.vpn.menubar.plist"
# Safe post-install activation: forces automatic reconnect false before loading service/menu, so login/activation does not start OpenConnect until the user chooses Connect.
PREF_PATH="$HOME/Library/Application Support/hyu-openconnect/auto-reconnect.json"
/usr/bin/python3 -I -c 'import sys; sys.path.insert(0,"/Library/Application Support/HYU VPN/src"); from hyu_vpn.control import AutoReconnectPreference; AutoReconnectPreference(sys.argv[1], owner_uid=int(sys.argv[2])).write(False)' "$PREF_PATH" "$USER_UID"
[[ -f "$SERVICE_PLIST" ]] || { print -u2 "missing installed service LaunchAgent"; exit 1; }
[[ -f "$MENUBAR_PLIST" ]] || { print -u2 "missing installed menu LaunchAgent"; exit 1; }
/bin/launchctl bootstrap "gui/$USER_UID" "$SERVICE_PLIST" >/dev/null 2>&1 || /bin/launchctl print "gui/$USER_UID/com.hyu.vpn.service" >/dev/null
/bin/launchctl bootstrap "gui/$USER_UID" "$MENUBAR_PLIST" >/dev/null 2>&1 || /bin/launchctl print "gui/$USER_UID/com.hyu.vpn.menubar" >/dev/null
/bin/launchctl kickstart -k "gui/$USER_UID/com.hyu.vpn.service" >/dev/null
/bin/launchctl kickstart -k "gui/$USER_UID/com.hyu.vpn.menubar" >/dev/null
/bin/launchctl print "gui/$USER_UID/com.hyu.vpn.service" >/dev/null
/bin/launchctl print "gui/$USER_UID/com.hyu.vpn.menubar" >/dev/null
[[ -d "/Applications/HYU VPN.app" ]] && /usr/bin/open -a "/Applications/HYU VPN.app" >/dev/null 2>&1 || true
exit 0
