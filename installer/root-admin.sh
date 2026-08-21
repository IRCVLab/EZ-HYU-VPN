#!/bin/zsh
set -euo pipefail
SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"

ACTION=""; PAYLOAD=""; MANIFEST=""; STAGE=""; STAGE_MANIFEST_SHA256=""; PACKAGE_MANIFEST_SHA256=""; DRY_RUN_ROOT=""; ADMIN_USER_ARG=""; ADMIN_UID_ARG=""; RECOVER=0; TOOLS_ROOT=""; LIVE_NONCE=""
typeset -A SEEN_OPT
seen_once(){ local opt="$1"; [[ -z "${SEEN_OPT[$opt]:-}" ]] || { print -u2 "duplicate option: $opt"; exit 64; }; SEEN_OPT[$opt]=1; }
need_value(){ [[ $# -ge 2 && "$2" != --* ]] || { print -u2 "missing value for $1"; exit 64; }; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --administrator-phase) seen_once "$1"; need_value "$@"; ACTION="$2"; shift 2 ;;
    --payload) seen_once "$1"; need_value "$@"; PAYLOAD="$2"; shift 2 ;;
    --manifest) seen_once "$1"; need_value "$@"; MANIFEST="$2"; shift 2 ;;
    --stage) seen_once "$1"; need_value "$@"; STAGE="$2"; shift 2 ;;
    --stage-manifest-sha256) seen_once "$1"; need_value "$@"; STAGE_MANIFEST_SHA256="$2"; shift 2 ;;
    --package-manifest-sha256) seen_once "$1"; need_value "$@"; PACKAGE_MANIFEST_SHA256="$2"; shift 2 ;;
    --dry-run-root) seen_once "$1"; need_value "$@"; DRY_RUN_ROOT="$2"; shift 2 ;;
    --admin-user) seen_once "$1"; need_value "$@"; ADMIN_USER_ARG="$2"; shift 2 ;;
    --admin-uid) seen_once "$1"; need_value "$@"; ADMIN_UID_ARG="$2"; shift 2 ;;
    --tools-root) seen_once "$1"; need_value "$@"; TOOLS_ROOT="$2"; shift 2 ;;
    --recover) seen_once "$1"; RECOVER=1; shift ;;
    --live-install) seen_once "$1"; need_value "$@"; LIVE_NONCE="$2"; shift 2 ;;
    *) print -u2 "unexpected argument: $1"; exit 64 ;;
  esac
done
[[ -n "$ACTION" && -n "$PAYLOAD" && -n "$MANIFEST" ]] || { print -u2 "usage: root-admin.sh --payload PATH --manifest PATH --administrator-phase install|uninstall"; exit 64; }
case "$ACTION" in install|uninstall) ;; *) print -u2 "unknown administrator phase"; exit 64;; esac

validate_temp_root(){
  local root="$1" real parent entry
  [[ -n "$root" && "$root" != "/" && ! -L "$root" ]] || { print -u2 "fresh temporary dry-run root required"; exit 65; }
  if [[ -e "$root" ]]; then real="$(CDPATH='' cd -- "$root" && pwd -P)"; else real="$root"; fi
  case "$real" in /tmp/*|/private/tmp/*|/var/folders/*|/private/var/folders/*) ;; *) print -u2 "fresh temporary dry-run root required"; exit 65;; esac
  if [[ -e "$real" ]]; then
    [[ -d "$real" ]] || { print -u2 "fresh temporary dry-run root required"; exit 65; }
    for entry in "$real"/*(N) "$real"/.[!.]*(N); do
      [[ "${entry:t}" == ".hyu-vpn-dry-run-root" || "${entry:t}" == "Users" || "${entry:t}" == "private" || "${entry:t}" == "Library" || "${entry:t}" == "Applications" || "${entry:t}" == "etc" ]] || { print -u2 "fresh empty dry-run root required"; exit 65; }
    done
  else
    parent="$(/usr/bin/dirname "$real")"; [[ -d "$parent" ]] || { print -u2 "fresh temporary dry-run root required"; exit 65; }
  fi
}
validate_live_nonce(){
  local nonce="$1" epoch now delta
  [[ "$nonce" == hyu-install-mutation-<-> ]] || { print -u2 "fresh live mutation nonce required"; exit 65; }
  epoch="${nonce#hyu-install-mutation-}"; now="$(/bin/date +%s)"; delta=$(( now - epoch ))
  [[ $delta -ge 0 && $delta -le 300 ]] || { print -u2 "fresh live mutation nonce required"; exit 65; }
}
validate_tools_root(){
  local tools="$1" dry="$2" real_tools real_dry tool
  [[ -z "$tools" ]] && return 0
  [[ -n "$dry" && -d "$tools" && ! -L "$tools" ]] || { print -u2 "invalid tools root"; exit 65; }
  real_tools="$(CDPATH='' cd -- "$tools" && pwd -P)"; real_dry="$(CDPATH='' cd -- "$dry" && pwd -P)"
  case "$real_tools" in "$real_dry"/*) ;; *) print -u2 "tools root must be inside dry-run root"; exit 65;; esac
  for tool in /usr/sbin/visudo /usr/sbin/chown /usr/bin/pgrep /usr/sbin/netstat /usr/sbin/scutil /usr/bin/env /usr/bin/sudo /bin/launchctl /bin/mv; do
    [[ -x "$real_tools$tool" ]] || { print -u2 "tools root missing allowlisted tool: $tool"; exit 65; }
  done
}

ROOT_PREFIX="${DRY_RUN_ROOT:-}"
rel_path() {
  local p="$1"
  if [[ -n "$ROOT_PREFIX" && "$p" == "$ROOT_PREFIX"/* ]]; then
    print -- "${p#$ROOT_PREFIX/}"
  elif [[ "$p" == /* ]]; then
    print -- "${p#/}"
  else
    print -- "$p"
  fi
}
_chain_root_for_target(){
  local target="$1"
  if [[ -n "$ROOT_PREFIX" ]]; then
    print -- "$ROOT_PREFIX"
    return 0
  fi
  if [[ -n "${HYU_VPN_CHAIN_GUARD_SELFTEST_PATH:-}" ]]; then
    case "$target" in
      */Library/*) print -- "${target%%/Library/*}"; return 0 ;;
      */Applications/*) print -- "${target%%/Applications/*}"; return 0 ;;
      */etc/*) print -- "${target%%/etc/*}"; return 0 ;;
      */var/*) print -- "${target%%/var/*}"; return 0 ;;
    esac
  fi
  print -- "/"
}
_allowed_system_alias(){
  local path="$1" target="" link=""
  case "$path" in
    /etc) target="/private/etc" ;;
    /var) target="/private/var" ;;
    /tmp) target="/private/tmp" ;;
    *) return 1 ;;
  esac
  link="$(/usr/bin/readlink "$path" 2>/dev/null || true)"
  [[ "$link" == "$target" || "$link" == "${target#/}" ]]
}
_allowed_standard_applications_anchor(){
  local path="$1" mode="$2" uid gid
  [[ -z "$DRY_RUN_ROOT" && "$path" == "/Applications" && "$mode" == "0775" ]] || return 1
  uid="$(/usr/bin/stat -f %u "$path")" || return 1
  gid="$(/usr/bin/stat -f %g "$path")" || return 1
  [[ "$uid" == 0 && "$gid" == 80 ]]
}
_allowed_destination_owner(){
  local target="$1" current="$2" uid="$3"
  [[ "$uid" == 0 ]] && return 0
  if [[ -n "${USER_HOME:-}" && -n "${ADMIN_UID:-}" && "$target" == "$USER_HOME/Library/LaunchAgents"* ]]; then
    case "$current" in "$USER_HOME"|"$USER_HOME"/*) [[ "$uid" == "$ADMIN_UID" ]] && return 0;; esac
  fi
  return 1
}
validate_privileged_destination_chain(){
  local target="$1" root current mode uid remain next
  [[ "$target" == /* ]] || { print -u2 "privileged destination must be absolute"; return 1; }
  root="$(_chain_root_for_target "$target")"
  [[ -n "$root" ]] || root="/"
  [[ "$root" == "/" || "$target" == "$root" || "$target" == "$root"/* ]] || { print -u2 "privileged destination outside root"; return 1; }
  current="$root"
  while true; do
    if [[ -L "$current" ]]; then
      _allowed_system_alias "$current" || { print -u2 "privileged destination contains symlink: $(rel_path "$current")"; return 1; }
    elif [[ -e "$current" ]]; then
      mode="$(/usr/bin/stat -f %Lp "$current")" || return 1
      while [[ ${#mode} -lt 4 ]]; do mode="0$mode"; done
      if [[ $(( 8#$mode & 18 )) -ne 0 ]]; then
        _allowed_standard_applications_anchor "$current" "$mode" || { print -u2 "privileged destination ancestor is writable: $(rel_path "$current")"; return 1; }
      fi
      if [[ -z "$DRY_RUN_ROOT" && -z "${HYU_VPN_CHAIN_GUARD_SELFTEST_PATH:-}" ]]; then
        uid="$(/usr/bin/stat -f %u "$current")" || return 1
        _allowed_destination_owner "$target" "$current" "$uid" || { print -u2 "privileged destination ancestor has unsafe owner: $(rel_path "$current")"; return 1; }
      fi
    fi
    [[ "$current" == "$target" ]] && break
    if [[ "$current" == "/" ]]; then
      remain="${target#/}"
      next="${remain%%/*}"
      current="/$next"
    elif [[ "$target" == "$current"/* ]]; then
      remain="${target#$current/}"
      next="${remain%%/*}"
      current="$current/$next"
    else
      print -u2 "privileged destination traversal failed"
      return 1
    fi
  done
}

if [[ -n "${HYU_VPN_CHAIN_GUARD_SELFTEST_PATH:-}" ]]; then
  validate_privileged_destination_chain "$HYU_VPN_CHAIN_GUARD_SELFTEST_PATH"
  exit $?
fi

if [[ -n "$DRY_RUN_ROOT" ]]; then
  [[ -z "$LIVE_NONCE" ]] || { print -u2 "live root phase rejects test-only option"; exit 65; }
  if [[ "$ACTION" == install && "$RECOVER" -eq 0 ]]; then
    validate_temp_root "$DRY_RUN_ROOT"
  else
    [[ "$DRY_RUN_ROOT" != "/" && -d "$DRY_RUN_ROOT" && ! -L "$DRY_RUN_ROOT" ]] || { print -u2 "temporary dry-run root required"; exit 65; }
  fi
  [[ -f "$DRY_RUN_ROOT/.hyu-vpn-dry-run-root" && ! -L "$DRY_RUN_ROOT/.hyu-vpn-dry-run-root" ]] || { print -u2 "dry-run marker required"; exit 65; }
  validate_tools_root "$TOOLS_ROOT" "$DRY_RUN_ROOT"
  ADMIN_USER="${ADMIN_USER_ARG:-tester}"; ADMIN_UID="${ADMIN_UID_ARG:-501}"; ADMIN_HOME="/Users/$ADMIN_USER"
else
  [[ -z "$DRY_RUN_ROOT" && -z "$TOOLS_ROOT" && -z "$ADMIN_USER_ARG" && -z "$ADMIN_UID_ARG" ]] || { print -u2 "live root phase rejects test-only option"; exit 65; }
  [[ -n "$LIVE_NONCE" ]] || { print -u2 "live install requires --live-install nonce"; exit 65; }
  validate_live_nonce "$LIVE_NONCE"
  ADMIN_USER="${SUDO_USER:-}"; ADMIN_UID="${SUDO_UID:-}"
  [[ -n "$ADMIN_USER" && -n "$ADMIN_UID" && "$ADMIN_USER" != "root" ]] || { print -u2 "invalid sudo identity"; exit 65; }
  ACTUAL_UID="$(/usr/bin/id -u "$ADMIN_USER")"; [[ "$ACTUAL_UID" == "$ADMIN_UID" ]] || { print -u2 "SUDO_UID mismatch"; exit 65; }
  ADMIN_HOME="$(/usr/bin/dscl . -read /Users/${ADMIN_USER} NFSHomeDirectory | /usr/bin/awk '{print $2}')"
  [[ "$ADMIN_HOME" == /Users/* && "$ADMIN_HOME" != *..* ]] || { print -u2 "unsafe user home"; exit 65; }
fi
case "$ADMIN_USER" in (*[!A-Za-z0-9_.-]*|'') print -u2 "unsafe sudoers user"; exit 65;; esac
[[ "$ACTION" != install || -n "$STAGE" || "$RECOVER" -eq 1 ]] || { print -u2 "missing stage"; exit 64; }
[[ "$ACTION" != install || "$RECOVER" -eq 1 || "$STAGE_MANIFEST_SHA256" == [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f] ]] || { print -u2 "missing or invalid staged manifest digest"; exit 65; }
[[ "$ACTION" != install || "$RECOVER" -eq 1 || "$PACKAGE_MANIFEST_SHA256" == [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f] ]] || { print -u2 "missing or invalid package manifest digest"; exit 65; }

ROOT_PREFIX="${DRY_RUN_ROOT:-}"
map_path() {
  local p="$1"
  if [[ -n "$ROOT_PREFIX" && "$p" == /* ]]; then
    print -- "$ROOT_PREFIX${p}"
  else
    print -- "$p"
  fi
}
rel_path() {
  local p="$1"
  if [[ -n "$ROOT_PREFIX" && "$p" == "$ROOT_PREFIX"/* ]]; then
    print -- "${p#$ROOT_PREFIX/}"
  elif [[ "$p" == /* ]]; then
    print -- "${p#/}"
  else
    print -- "$p"
  fi
}
tool_path() {
  local p="$1"
  if [[ -n "$TOOLS_ROOT" && -x "$TOOLS_ROOT$p" ]]; then
    print -- "$TOOLS_ROOT$p"
  else
    print -- "$p"
  fi
}
STATE_DIR="$(map_path /private/var/db/hyu-vpn)"; TX_STATE="$STATE_DIR/transaction-state"; JOURNAL="$STATE_DIR/install-transaction.log"; TXN_PATHS="$STATE_DIR/txn-paths"; INSTALLED_MANIFEST="$STATE_DIR/installed-manifest.json"; INSTALLED_PATHS="$STATE_DIR/installed-paths.tsv"; COMMAND_LOG="$STATE_DIR/command-log.jsonl"; ROOT_SERVICE_BOOTSTRAPPED=0; CURRENT_USER_SERVICE_STOPPED=0
SUDOERS_TMP="$STATE_DIR/sudoers-candidate.$$"
APP_SUPPORT="$(map_path '/Library/Application Support/HYU VPN')"; HELPER_DST="$(map_path /Library/PrivilegedHelperTools/com.hyu.vpn.helper)"; VPNC_WRAPPER_DST="$(map_path /Library/PrivilegedHelperTools/com.hyu.vpn.vpnc-wrapper)"; SUDOERS_DST="$(map_path /etc/sudoers.d/hyu-vpn)"; APP_DST="$(map_path '/Applications/HYU VPN.app')"
LEGACY_SUDOERS_DST="$(map_path /etc/sudoers.d/com.hyu.vpn)"
USER_HOME="$(map_path "$ADMIN_HOME")"; SERVICE_PLIST="$USER_HOME/Library/LaunchAgents/com.hyu.vpn.service.plist"; LEGACY_MENUBAR_PLIST="$USER_HOME/Library/LaunchAgents/com.hyu.vpn.menubar.plist"; MENU_LABEL="com.hyu.vpn.menubar"
PACKAGE_SNAPSHOT="$STATE_DIR/package-snapshot"; TXN_SNAPSHOT="$STATE_DIR/root-snapshot"; ROOT_NATIVE_TOOL_DIR="$STATE_DIR/native-tool"; ROOT_NATIVE_TOOL="$ROOT_NATIVE_TOOL_DIR/hyu-vpn-macos-service"; LEGACY_LABEL="local.hyu-openconnect"

trusted_native_tool(){
  local tool="$1" mode uid
  [[ -n "$tool" && -x "$tool" && ! -L "$tool" ]] || return 1
  case "$tool" in
    "$ROOT_NATIVE_TOOL") ;;
    "$APP_SUPPORT/bin/hyu-vpn-macos-service") ;;
    *) return 1 ;;
  esac
  mode="$(/usr/bin/stat -f %Lp "$tool")" || return 1
  while [[ ${#mode} -lt 4 ]]; do mode="0$mode"; done
  [[ $(( 8#$mode & 18 )) -eq 0 ]] || return 1
  if [[ -z "$DRY_RUN_ROOT" ]]; then
    uid="$(/usr/bin/stat -f %u "$tool")" || return 1
    [[ "$uid" == 0 ]] || return 1
  fi
}
native_service_tools(){
  local candidate
  if [[ "$ACTION" == install ]]; then
    trusted_native_tool "$ROOT_NATIVE_TOOL" && print -- "$ROOT_NATIVE_TOOL"
    return 0
  fi
  for candidate in "$ROOT_NATIVE_TOOL" "$APP_SUPPORT/bin/hyu-vpn-macos-service"; do
    trusted_native_tool "$candidate" && print -- "$candidate"
  done
}
native_service_tool(){ native_service_tools | /usr/bin/head -n 1; }
durable_flush(){
  local target="$1" tool ok=0
  [[ -e "$target" ]] || return 0
  if [[ -z "$(native_service_tool)" ]]; then return 0; fi
  while IFS= read -r tool; do
    [[ -z "$tool" ]] && continue
    if "$tool" root-util fsync "$target" >/dev/null 2>&1; then ok=1; break; fi
  done < <(native_service_tools)
  [[ "$ok" -eq 1 ]] || { print -u2 "native fsync utility unavailable"; return 1; }
  if [[ -f "$target" ]]; then
    local parent="$(/usr/bin/dirname "$target")"
    if [[ -d "$parent" ]]; then
      while IFS= read -r tool; do
        [[ -z "$tool" ]] && continue
        "$tool" root-util fsync "$parent" >/dev/null 2>&1 && return 0
      done < <(native_service_tools)
      print -u2 "native fsync utility unavailable"; return 1
    fi
  fi
}
if [[ -e "$STATE_DIR" || -L "$STATE_DIR" ]]; then [[ ! -L "$STATE_DIR" ]] || { print -u2 "privileged destination contains symlink: $(rel_path "$STATE_DIR")"; exit 65; }; _state_mode="$(/usr/bin/stat -f %Lp "$STATE_DIR")"; while [[ ${#_state_mode} -lt 4 ]]; do _state_mode="0$_state_mode"; done; [[ $(( 8#$_state_mode & 18 )) -eq 0 ]] || { print -u2 "privileged destination ancestor is writable: $(rel_path "$STATE_DIR")"; exit 65; }; fi
NEED_PREINSTALL_RECOVERY=0; /bin/mkdir -p "$STATE_DIR"; /bin/chmod 700 "$STATE_DIR"; /bin/rm -f "$STATE_DIR"/sudoers-candidate.*(N); [[ -f "$JOURNAL" ]] || : >| "$JOURNAL"; [[ -f "$TXN_PATHS" ]] || : >| "$TXN_PATHS"; if [[ "$RECOVER" -eq 1 ]]; then :; elif [[ -z "$DRY_RUN_ROOT" && -s "$TXN_PATHS" && ("$(/bin/cat "$TX_STATE" 2>/dev/null || true)" == "install-pending" || "$(/bin/cat "$TX_STATE" 2>/dev/null || true)" == "commit" || "$(/bin/cat "$TX_STATE" 2>/dev/null || true)" == "in_progress") ]]; then NEED_PREINSTALL_RECOVERY=1; else : >| "$JOURNAL"; : >| "$TXN_PATHS"; /bin/rm -rf "$STATE_DIR/backups" "$STATE_DIR/backups.tsv" "$PACKAGE_SNAPSHOT" "$TXN_SNAPSHOT" "$ROOT_NATIVE_TOOL_DIR"; print complete >| "$TX_STATE"; durable_flush "$TX_STATE"; fi
log(){ print -- "$1" >> "$JOURNAL"; durable_flush "$JOURNAL"; }
record_cmd(){ print -- "$*" >> "$COMMAND_LOG"; durable_flush "$COMMAND_LOG"; }
run_cmd(){ local exe="$(tool_path "$1")"; shift; record_cmd "$exe $*"; if [[ -z "$DRY_RUN_ROOT" || -n "$TOOLS_ROOT" ]]; then "$exe" "$@"; fi; }
run_optional_cmd(){ local exe="$(tool_path "$1")"; shift; record_cmd "$exe $*"; if [[ -z "$DRY_RUN_ROOT" || -n "$TOOLS_ROOT" ]]; then "$exe" "$@" || true; fi; }
record_path(){ rel_path "$1" >> "$TXN_PATHS"; durable_flush "$TXN_PATHS"; }

capture_cmd(){ local exe="$(tool_path "$1")"; shift; record_cmd "$exe $*"; [[ -n "$DRY_RUN_ROOT" && -z "$TOOLS_ROOT" ]] && return 0; "$exe" "$@" 2>/dev/null || true; }
helper_state(){
  local raw tool
  raw="$(capture_cmd "$HELPER_DST" status)"
  tool="$(native_service_tool)" || return 1
  print -r -- "$raw" | "$tool" root-util helper-state
}
drain_existing_helper(){
  [[ -x "$HELPER_DST" ]] || return 0
  [[ -n "$DRY_RUN_ROOT" && -z "$TOOLS_ROOT" ]] && return 0
  local state after
  state="$(helper_state)" || { print -u2 "existing HYU VPN helper status is invalid"; return 1; }
  case "$state" in
    stopped)
      log "old-helper-stopped"
      ;;
    running)
      if run_cmd "$HELPER_DST" stop; then
        [[ "$(helper_state)" == stopped ]] || { print -u2 "existing HYU VPN helper did not stop"; return 1; }
        log "old-helper-drained"
      else
        after="$(helper_state)" || { print -u2 "existing HYU VPN helper state became unreadable after stop"; return 1; }
        case "$after" in
          stopped) log "old-helper-drained-after-nonzero" ;;
          repair-required) log "old-helper-stop-repair-deferred" ;;
          *) print -u2 "existing HYU VPN session could not be stopped safely"; return 1 ;;
        esac
      fi
      ;;
    repair-required)
      # A repair-required helper may be an older build with the bug being
      # upgraded. Never execute its recovery path. Preserve its ledger until
      # the package helper has replaced it, then let the new fail-closed
      # implementation decide whether recovery is safe.
      log "old-helper-repair-deferred"
      ;;
  esac
}
stop_current_user_service(){
  log "current-service-stop-start"
  run_optional_cmd /bin/launchctl bootout "gui/$ADMIN_UID/com.hyu.vpn.service"
  CURRENT_USER_SERVICE_STOPPED=1
  log "current-service-stopped"
}
verify_installed_helper_stopped(){
  [[ -n "$DRY_RUN_ROOT" && -z "$TOOLS_ROOT" ]] && return 0
  local state
  state="$(helper_state)" || { print -u2 "installed HYU VPN helper status is invalid"; return 1; }
  if [[ "$state" == repair-required ]]; then
    [[ -f "$PAYLOAD/com.hyu.vpn.helper" && "$(sha256 "$HELPER_DST")" == "$(sha256 "$PAYLOAD/com.hyu.vpn.helper")" ]] || {
      print -u2 "refusing repair through an unverified HYU VPN helper"
      return 1
    }
    run_cmd "$HELPER_DST" repair || { print -u2 "installed HYU VPN helper could not repair retained state"; return 1; }
    state="$(helper_state)" || { print -u2 "installed HYU VPN helper status is invalid after repair"; return 1; }
  fi
  [[ "$state" == stopped ]] || { print -u2 "installed HYU VPN helper is not stopped"; return 1; }
  log "installed-helper-stopped"
}
has_legacy_tunnel_route(){
  print -r -- "$1" | /usr/bin/awk '
    $1 ~ /^166[.]104([.]|\/|$)/ {
      for (i = 2; i <= NF; i++) {
        if ($i ~ /^(utun|ppp|ipsec|tap|tun)[0-9]*$/) found = 1
      }
    }
    END { exit found ? 0 : 1 }
  '
}
has_legacy_vpn_resolver(){
  print -r -- "$1" | /usr/bin/awk '
    function finish_resolver() {
      if (has_hanyang && has_tunnel) found = 1
      has_hanyang = 0
      has_tunnel = 0
    }
    /^[[:space:]]*resolver #[0-9]+/ { finish_resolver(); next }
    {
      line = tolower($0)
      if (line ~ /(166[.]104[.]|hanyang)/) has_hanyang = 1
      if (line ~ /\((utun|ppp|ipsec|tap|tun)[0-9]*\)/ || line ~ /(if_index|interface)[^[:alnum:]_]+(utun|ppp|ipsec|tap|tun)[0-9]*/) has_tunnel = 1
    }
    END { finish_resolver(); exit found ? 0 : 1 }
  '
}
quarantine_legacy(){
  local proc_out net_out dns_out disabled_out
  log "legacy-quarantine-start"
  run_optional_cmd /bin/launchctl print "gui/$ADMIN_UID/$LEGACY_LABEL"
  run_optional_cmd /bin/launchctl bootout "gui/$ADMIN_UID/$LEGACY_LABEL"
  run_cmd /bin/launchctl disable "gui/$ADMIN_UID/$LEGACY_LABEL"
  disabled_out="$(capture_cmd /bin/launchctl print-disabled "gui/$ADMIN_UID")"
  [[ "$disabled_out" == *"$LEGACY_LABEL"* || -n "$DRY_RUN_ROOT" ]] || { print -u2 "legacy service disable not verified"; return 1; }
  proc_out="$(capture_cmd /usr/bin/pgrep -fl 'openconnect.*secure\.hanyang\.ac\.kr|local\.hyu-openconnect')"
  [[ -z "$proc_out" ]] || { print -u2 "legacy process remains: $LEGACY_LABEL"; return 1; }
  net_out="$(capture_cmd /usr/sbin/netstat -rn -f inet)"
  ! has_legacy_tunnel_route "$net_out" || { print -u2 "legacy tunnel route remains"; return 1; }
  dns_out="$(capture_cmd /usr/sbin/scutil --dns)"
  ! has_legacy_vpn_resolver "$dns_out" || { print -u2 "legacy VPN resolver remains"; return 1; }
  log "legacy-quarantined-never-restore $LEGACY_LABEL"
}
sha256(){ /usr/bin/shasum -a 256 "$1" | /usr/bin/awk '{print $1}'; }
verify_stage_digest(){ local dir="$1" got; got="$(sha256 "$dir/manifest.json")"; [[ "$got" == "$STAGE_MANIFEST_SHA256" ]] || { print -u2 "staged manifest digest mismatch"; return 1; }; }
verify_package_manifest_digest(){ local got; got="$(sha256 "$1/manifest.json")"; [[ "$got" == "$PACKAGE_MANIFEST_SHA256" ]] || { print -u2 "package manifest digest mismatch"; return 1; }; }
verify_tree_manifest_hashes(){
  local root="$1" manifest_json="$1/manifest.json" path rel escaped_rel hash
  [[ -f "$manifest_json" && ! -L "$manifest_json" ]] || { print -u2 "missing staged manifest"; return 1; }
  if /usr/bin/find "$root" -type l -print -quit | /usr/bin/grep -q .; then print -u2 "symlink in staged payload"; return 1; fi
  while IFS= read -r -d '' path; do
    rel="${path#$root/}"
    [[ "$rel" == "manifest.json" ]] && continue
    hash="$(sha256 "$path")"
    escaped_rel="${rel//\//\\/}"
    { /usr/bin/grep -F -q '"'"$rel"'"' "$manifest_json" || /usr/bin/grep -F -q '"'"$escaped_rel"'"' "$manifest_json"; } || { print -u2 "missing manifest entry: $rel"; return 1; }
    /usr/bin/grep -E -q '"sha256"[[:space:]]*:[[:space:]]*"'"$hash"'"' "$manifest_json" || { print -u2 "hash mismatch: $rel"; return 1; }
  done < <(/usr/bin/find "$root" -type f -print0)
}
verify_package_snapshot_manifest(){ verify_tree_manifest_hashes "$1"; }

verify_stage_matches_package_payload(){
  local pair stage_rel package_rel
  for pair in \
    "runtime/bin/openconnect|runtime/openconnect/bin/openconnect" \
    "runtime/bin/oathtool|runtime/oathtool" \
    "runtime/gp-hip-report|runtime/gp-hip-report" \
    "runtime/vpnc/hyu-vpnc-wrapper|runtime/vpnc/hyu-vpnc-wrapper" \
    "runtime/vpnc/hyu-vpnc-wrapperd|runtime/vpnc/hyu-vpnc-wrapperd" \
    "runtime/vpnc/vpnc-script|runtime/vpnc/vpnc-script" \
    "com.hyu.vpn.helper|com.hyu.vpn.helper" \
    "bin/hyu-vpn-macos-service|hyu-vpn-macos-service" \
    "config/launchd/com.hyu.vpn.service.plist.in|launchd/com.hyu.vpn.service.plist.in"; do
    stage_rel="${pair%%|*}"; package_rel="${pair#*|}"
    [[ -f "$STAGE/$stage_rel" && -f "$PAYLOAD/$package_rel" ]] || { print -u2 "missing staged package file: $stage_rel"; return 1; }
    [[ "$(sha256 "$STAGE/$stage_rel")" == "$(sha256 "$PAYLOAD/$package_rel")" ]] || { print -u2 "hash mismatch: $stage_rel"; return 1; }
  done
}
verify_manifest_arg_relation(){
  local payload_real manifest_dir_real manifest_real
  [[ -d "$PAYLOAD" && -f "$MANIFEST" && ! -L "$MANIFEST" ]] || { print -u2 "missing package payload or manifest"; return 1; }
  payload_real="$(CDPATH='' cd -- "$PAYLOAD" && pwd -P)"
  manifest_dir_real="$(CDPATH='' cd -- "$(/usr/bin/dirname "$MANIFEST")" && pwd -P)"
  manifest_real="$manifest_dir_real/$(/usr/bin/basename "$MANIFEST")"
  [[ "$manifest_real" == "$payload_real/manifest.json" ]] || { print -u2 "manifest must be package top manifest"; return 1; }
}
copy_package_snapshot(){
  verify_manifest_arg_relation
  verify_package_manifest_digest "$PAYLOAD"
  [[ -d "$STAGE" && ! -L "$STAGE" ]] || { print -u2 "missing staged payload"; return 1; }
  /bin/rm -rf "$PACKAGE_SNAPSHOT" "$TXN_SNAPSHOT" "$ROOT_NATIVE_TOOL_DIR"
  /bin/mkdir -p "$PACKAGE_SNAPSHOT" "$TXN_SNAPSHOT"
  /bin/chmod 700 "$PACKAGE_SNAPSHOT" "$TXN_SNAPSHOT"
  /usr/bin/tar -C "$PAYLOAD" -cf - . | /usr/bin/tar -C "$PACKAGE_SNAPSHOT" -xpf -
  verify_package_snapshot_manifest "$PACKAGE_SNAPSHOT"
  /bin/mkdir -p "$ROOT_NATIVE_TOOL_DIR"
  /bin/chmod 700 "$ROOT_NATIVE_TOOL_DIR"
  /bin/cp "$PACKAGE_SNAPSHOT/hyu-vpn-macos-service" "$ROOT_NATIVE_TOOL"
  /bin/chmod 700 "$ROOT_NATIVE_TOOL"
  /bin/mkdir -p "$TXN_SNAPSHOT/runtime/bin" "$TXN_SNAPSHOT/runtime/lib" "$TXN_SNAPSHOT/runtime/vpnc" "$TXN_SNAPSHOT/bin" "$TXN_SNAPSHOT/config/launchd"
  /bin/cp "$PACKAGE_SNAPSHOT/runtime/openconnect/bin/openconnect" "$TXN_SNAPSHOT/runtime/bin/openconnect"
  /bin/cp "$PACKAGE_SNAPSHOT/runtime/oathtool" "$TXN_SNAPSHOT/runtime/bin/oathtool"
  /bin/cp "$PACKAGE_SNAPSHOT/runtime/gp-hip-report" "$TXN_SNAPSHOT/runtime/gp-hip-report"
  /bin/cp "$PACKAGE_SNAPSHOT/runtime/vpnc/hyu-vpnc-wrapper" "$TXN_SNAPSHOT/runtime/vpnc/hyu-vpnc-wrapper"
  /bin/cp "$PACKAGE_SNAPSHOT/runtime/vpnc/hyu-vpnc-wrapperd" "$TXN_SNAPSHOT/runtime/vpnc/hyu-vpnc-wrapperd"
  /bin/cp "$PACKAGE_SNAPSHOT/runtime/vpnc/vpnc-script" "$TXN_SNAPSHOT/runtime/vpnc/vpnc-script"
  /bin/cp "$PACKAGE_SNAPSHOT/com.hyu.vpn.helper" "$TXN_SNAPSHOT/com.hyu.vpn.helper"
  /bin/cp "$PACKAGE_SNAPSHOT/hyu-vpn-macos-service" "$TXN_SNAPSHOT/bin/hyu-vpn-macos-service"
  /bin/cp "$PACKAGE_SNAPSHOT/launchd/com.hyu.vpn.service.plist.in" "$TXN_SNAPSHOT/config/launchd/com.hyu.vpn.service.plist.in"
  [[ -d "$PACKAGE_SNAPSHOT/runtime/openconnect/lib" ]] && /usr/bin/tar -C "$PACKAGE_SNAPSHOT/runtime/openconnect/lib" -cf - . | /usr/bin/tar -C "$TXN_SNAPSHOT/runtime/lib" -xpf -
  /usr/bin/tar -C "$PACKAGE_SNAPSHOT" -cf - "HYU VPN.app" | /usr/bin/tar -C "$TXN_SNAPSHOT" -xpf -
  /bin/chmod -R u+rwX,go-w "$TXN_SNAPSHOT"
  /bin/chmod 755 "$TXN_SNAPSHOT/bin/hyu-vpn-macos-service" "$TXN_SNAPSHOT/runtime/gp-hip-report" "$TXN_SNAPSHOT/runtime/bin/openconnect" "$TXN_SNAPSHOT/runtime/bin/oathtool" "$TXN_SNAPSHOT/runtime/vpnc/"* "$TXN_SNAPSHOT/com.hyu.vpn.helper"
  /bin/chmod 644 "$TXN_SNAPSHOT/config/launchd/com.hyu.vpn.service.plist.in"
  /bin/chmod 700 "$TXN_SNAPSHOT"
  verify_stage_digest "$STAGE"
  verify_stage_manifest "$STAGE"
  verify_stage_matches_package_payload
}
fail_after(){ [[ "${HYU_VPN_FAIL_AFTER:-}" == "$1" ]] && { print -u2 "injected failure after $1"; return 1; } || return 0; }
remove_rel(){ local rel="$1" target; case "$rel" in /*|*..*|Library/Preferences/SystemConfiguration*) print -u2 "unsafe installed path: $rel"; return 1;; esac; case "$rel" in Library/Application\ Support/HYU\ VPN/*|Library/PrivilegedHelperTools/com.hyu.vpn.helper|Library/PrivilegedHelperTools/com.hyu.vpn.vpnc-wrapper|Applications/HYU\ VPN.app|etc/sudoers.d/hyu-vpn|etc/sudoers.d/com.hyu.vpn|Users/*/Library/LaunchAgents/com.hyu.vpn.*.plist|private/var/db/hyu-vpn/*) ;; *) print -u2 "unsafe installed path: $rel"; return 1;; esac; [[ "$rel" == /* ]] && target="$(map_path "$rel")" || target="$ROOT_PREFIX/$rel"; [[ -e "$target" || -L "$target" ]] || return 0; [[ -d "$target" && ! -L "$target" ]] && /bin/rm -rf "$target" || /bin/rm -f "$target"; }
backup_target(){ local target="$1"; local rel hash backup; validate_privileged_destination_chain "$target"; rel="$(rel_path "$target")"; hash="$(print -r -- "$rel" | /usr/bin/shasum -a 256 | /usr/bin/awk '{print $1}')"; backup="$STATE_DIR/backups/$hash"; log "before-backup $rel $backup"; if [[ -e "$target" || -L "$target" ]]; then /bin/mkdir -p "$(/usr/bin/dirname "$backup")"; /bin/mv "$target" "$backup"; print -- "$rel|$backup" >> "$STATE_DIR/backups.tsv"; durable_flush "$STATE_DIR/backups.tsv"; fi; }
rollback_bootstrapped_root_service(){
  [[ "${ROOT_SERVICE_BOOTSTRAPPED:-0}" == 1 ]] || return 0
  log "rollback-service-bootout-start"
  run_cmd /bin/launchctl bootout "gui/$ADMIN_UID/com.hyu.vpn.service" || { log "rollback-service-bootout-failed"; return 1; }
  local remaining
  remaining="$(capture_cmd /usr/bin/pgrep -fl "$APP_SUPPORT/bin/hyu-vpn-macos-service")"
  [[ -z "$remaining" ]] || { print -u2 "root service still running after bootout"; log "rollback-service-running"; return 1; }
  ROOT_SERVICE_BOOTSTRAPPED=0
  log "rollback-service-bootout-complete"
}
rollback(){
  local rel backup rollback_status=0
  log "rollback-start"
  rollback_bootstrapped_root_service || return 1
  /bin/rm -f "$SUDOERS_TMP"
  /bin/rm -rf "$PACKAGE_SNAPSHOT" "$TXN_SNAPSHOT"
  if [[ -f "$TXN_PATHS" ]]; then
    while IFS= read -r rel; do
      [[ -z "$rel" ]] && continue
      remove_rel "$rel" || rollback_status=1
    done < <(/usr/bin/tail -r "$TXN_PATHS" 2>/dev/null)
  fi
  [[ "$rollback_status" -eq 0 ]] || return 1
  if [[ -f "$STATE_DIR/backups.tsv" ]]; then
    while IFS='|' read -r rel backup; do
      [[ -z "$rel" ]] && continue
      if [[ -e "$backup" ]]; then
        /bin/mkdir -p "$(/usr/bin/dirname "$ROOT_PREFIX/$rel")" || rollback_status=1
        [[ "$rollback_status" -eq 0 ]] && /bin/mv "$backup" "$ROOT_PREFIX/$rel" || rollback_status=1
      fi
    done < <(/usr/bin/tail -r "$STATE_DIR/backups.tsv" 2>/dev/null)
  fi
  [[ "$rollback_status" -eq 0 ]] || return 1
  /bin/rm -rf "$STATE_DIR/backups" "$STATE_DIR/backups.tsv"
  if [[ "$CURRENT_USER_SERVICE_STOPPED" -eq 1 && -f "$SERVICE_PLIST" && ! -L "$SERVICE_PLIST" ]]; then
    run_cmd /bin/launchctl bootstrap "gui/$ADMIN_UID" "$SERVICE_PLIST" || rollback_status=1
    [[ "$rollback_status" -eq 0 ]] && run_cmd /bin/launchctl kickstart -k "gui/$ADMIN_UID/com.hyu.vpn.service" || rollback_status=1
    [[ "$rollback_status" -eq 0 ]] && log "rollback-existing-service-restarted"
  fi
  [[ "$rollback_status" -eq 0 ]] || return 1
  : >| "$TXN_PATHS"
  print complete >| "$TX_STATE"
  durable_flush "$TX_STATE"
  durable_flush "$TXN_PATHS"
  log "rollback-complete"
}
trap 'rollback' ERR INT TERM
[[ "$NEED_PREINSTALL_RECOVERY" -eq 1 ]] && { log "preinstall-recovery-start"; rollback; : >| "$JOURNAL"; : >| "$TXN_PATHS"; log "preinstall-recovery-complete"; }

ensure_parent_dir(){ local dst="$1" parent; parent="$(/usr/bin/dirname "$dst")"; validate_privileged_destination_chain "$parent"; /bin/mkdir -p "$parent"; validate_privileged_destination_chain "$parent"; }
verify_no_symlinks(){ /usr/bin/find "$1" -type l -print -quit | /usr/bin/grep -q . && { print -u2 "symlink in staged payload"; return 1; } || return 0; }
verify_stage_manifest(){ verify_tree_manifest_hashes "$1"; }
copy_snapshot(){ [[ -d "$STAGE" ]] || { print -u2 "missing user stage"; return 1; }; verify_stage_digest "$STAGE"; copy_package_snapshot; }
copy_file(){ local src="$1" dst="$2" mode="$3"; log "before-mutate $(rel_path "$dst")"; backup_target "$dst"; ensure_parent_dir "$dst"; /bin/cp "$src" "$dst"; /bin/chmod "$mode" "$dst"; record_path "$dst"; durable_flush "$dst"; durable_flush "$TXN_PATHS"; log "complete $(rel_path "$dst")"; }
copy_dir(){ local src="$1" dst="$2" mode="$3"; log "before-mutate-dir $(rel_path "$dst")"; backup_target "$dst"; ensure_parent_dir "$dst"; /bin/mkdir -p "$dst"; /bin/chmod 700 "$dst"; validate_privileged_destination_chain "$dst"; /usr/bin/tar -C "$src" -cf - . | /usr/bin/tar -C "$dst" -xpf -; run_cmd /usr/sbin/chown -R root:wheel "$dst"; /bin/chmod -R u+rwX,go-w "$dst"; /bin/chmod "$mode" "$dst"; record_path "$dst"; durable_flush "$dst"; durable_flush "$TXN_PATHS"; log "complete $(rel_path "$dst")"; }
write_file(){ local dst="$1" mode="$2" content="$3"; log "before-mutate-write $(rel_path "$dst")"; backup_target "$dst"; ensure_parent_dir "$dst"; print -- "$content" > "$dst"; /bin/chmod "$mode" "$dst"; record_path "$dst"; durable_flush "$dst"; durable_flush "$TXN_PATHS"; log "complete $(rel_path "$dst")"; }
render_from_template(){ local template="$1" dst="$2"; validate_privileged_destination_chain "$dst"; /usr/bin/sed -e "s#@USER_HOME@#/Users/$ADMIN_USER#g" -e "s#@APP_PATH@#/Applications/HYU VPN.app#g" -e "s#@SERVICE_PATH@#/Library/Application Support/HYU VPN/bin/hyu-vpn-macos-service#g" "$template" > "$dst"; }
render_plists(){ ensure_parent_dir "$SERVICE_PLIST"; backup_target "$SERVICE_PLIST"; render_from_template "$TXN_SNAPSHOT/config/launchd/com.hyu.vpn.service.plist.in" "$SERVICE_PLIST"; /bin/chmod 644 "$SERVICE_PLIST"; record_path "$SERVICE_PLIST"; }
migrate_legacy_menu_launchagent(){ log "legacy-menu-launchagent-migration-start"; run_optional_cmd /bin/launchctl bootout "gui/$ADMIN_UID/$MENU_LABEL"; if [[ -f "$LEGACY_MENUBAR_PLIST" || -L "$LEGACY_MENUBAR_PLIST" ]]; then backup_target "$LEGACY_MENUBAR_PLIST"; /bin/rm -f "$LEGACY_MENUBAR_PLIST"; log "legacy-menu-launchagent-removed com.hyu.vpn.menubar"; else log "legacy-menu-launchagent-absent com.hyu.vpn.menubar"; fi; }
write_installed_manifest(){ local tmp="$INSTALLED_MANIFEST.tmp" paths_tmp="$INSTALLED_PATHS.tmp" first=1; print '{"schema":1,"paths":[' > "$tmp"; : > "$paths_tmp"; while IFS= read -r rel; do [[ -z "$rel" ]] && continue; [[ "$rel" == private/var/db/hyu-vpn/installed-manifest.json || "$rel" == private/var/db/hyu-vpn/installed-paths.tsv ]] && continue; print -- "$rel" >> "$paths_tmp"; [[ $first -eq 0 ]] && print ',' >> "$tmp"; first=0; printf '"%s"' "$rel" >> "$tmp"; done < "$TXN_PATHS"; print ']}' >> "$tmp"; /bin/mv "$tmp" "$INSTALLED_MANIFEST"; /bin/mv "$paths_tmp" "$INSTALLED_PATHS"; /bin/chmod 600 "$INSTALLED_MANIFEST" "$INSTALLED_PATHS"; durable_flush "$INSTALLED_MANIFEST"; durable_flush "$INSTALLED_PATHS"; }
root_service_health_check(){
  log "root-service-bootstrap-start"
  run_cmd /bin/launchctl bootstrap "gui/$ADMIN_UID" "$SERVICE_PLIST"
  run_cmd /bin/launchctl kickstart -k "gui/$ADMIN_UID/com.hyu.vpn.service"
  ROOT_SERVICE_BOOTSTRAPPED=1
  fail_after health
  run_cmd /usr/bin/sudo -H -u "$ADMIN_USER" -- "$APP_SUPPORT/bin/hyu-vpn-macos-service" health --uid "$ADMIN_UID" --home "$ADMIN_HOME" --timeout-ms 2500 || { print -u2 "root service health check failed"; return 1; }
  log "root-service-health-ok"
}

install_phase(){
  print install-pending >| "$TX_STATE"; durable_flush "$TX_STATE"; log "install-pending"; log "before-snapshot"; copy_snapshot; fail_after snapshot
  stop_current_user_service
  drain_existing_helper
  quarantine_legacy
  migrate_legacy_menu_launchagent
  copy_file "$TXN_SNAPSHOT/com.hyu.vpn.helper" "$HELPER_DST" 755; fail_after helper
  validate_privileged_destination_chain "$APP_SUPPORT"; validate_privileged_destination_chain "$STATE_DIR"
  /bin/mkdir -p "$APP_SUPPORT/bin" "$APP_SUPPORT/runtime/openconnect" "$APP_SUPPORT/runtime/vpnc" "$STATE_DIR/ledger"
  validate_privileged_destination_chain "$APP_SUPPORT"; validate_privileged_destination_chain "$APP_SUPPORT/bin"; validate_privileged_destination_chain "$APP_SUPPORT/runtime"; validate_privileged_destination_chain "$STATE_DIR"; validate_privileged_destination_chain "$STATE_DIR/ledger"
  /bin/chmod 755 "$APP_SUPPORT" "$APP_SUPPORT/bin" "$APP_SUPPORT/runtime" "$APP_SUPPORT/runtime/openconnect" "$APP_SUPPORT/runtime/vpnc"; /bin/chmod 700 "$STATE_DIR" "$STATE_DIR/ledger"
  RUNTIME_DIR="$APP_SUPPORT/runtime/current"
  copy_dir "$TXN_SNAPSHOT/runtime/bin" "$RUNTIME_DIR/bin" 755; [[ -d "$TXN_SNAPSHOT/runtime/lib" ]] && copy_dir "$TXN_SNAPSHOT/runtime/lib" "$RUNTIME_DIR/lib" 755
  copy_file "$TXN_SNAPSHOT/runtime/gp-hip-report" "$APP_SUPPORT/runtime/gp-hip-report" 755; copy_file "$TXN_SNAPSHOT/runtime/vpnc/hyu-vpnc-wrapper" "$APP_SUPPORT/runtime/vpnc/hyu-vpnc-wrapper" 755; copy_file "$TXN_SNAPSHOT/runtime/vpnc/hyu-vpnc-wrapper" "$VPNC_WRAPPER_DST" 755; copy_file "$TXN_SNAPSHOT/runtime/vpnc/hyu-vpnc-wrapperd" "$APP_SUPPORT/runtime/vpnc/hyu-vpnc-wrapperd" 755; copy_file "$TXN_SNAPSHOT/runtime/vpnc/vpnc-script" "$APP_SUPPORT/runtime/vpnc/vpnc-script" 755
  copy_file "$TXN_SNAPSHOT/bin/hyu-vpn-macos-service" "$APP_SUPPORT/bin/hyu-vpn-macos-service" 755; copy_dir "$TXN_SNAPSHOT/HYU VPN.app" "$APP_DST" 755
  run_cmd /usr/sbin/chown -R root:wheel "$APP_SUPPORT" "$HELPER_DST" "$VPNC_WRAPPER_DST" "$APP_DST" "$STATE_DIR"
  WRAPPERD_HASH="$(sha256 "$APP_SUPPORT/runtime/vpnc/hyu-vpnc-wrapperd")"; write_file "$APP_SUPPORT/runtime/vpnc/hyu-vpnc-wrapperd.sha256" 644 "$WRAPPERD_HASH"; OATH_HASH="$(sha256 "$RUNTIME_DIR/bin/oathtool")"; write_file "$APP_SUPPORT/connector-config.json" 644 "{\"schema_version\":1,\"oathtool_path\":\"/Library/Application Support/HYU VPN/runtime/current/bin/oathtool\",\"oathtool_sha256\":\"$OATH_HASH\"}"
  OC_ABS="/Library/Application Support/HYU VPN/runtime/current/bin/openconnect"; VPNC_ABS="/Library/PrivilegedHelperTools/com.hyu.vpn.vpnc-wrapper"; HIP_ABS="/Library/Application Support/HYU VPN/runtime/gp-hip-report"; OC_HASH="$(sha256 "$RUNTIME_DIR/bin/openconnect")"; VPNC_HASH="$(sha256 "$VPNC_WRAPPER_DST")"; HIP_HASH="$(sha256 "$APP_SUPPORT/runtime/gp-hip-report")"; cfg="{\"openConnectExecutable\":\"$OC_ABS\",\"vpncScript\":\"$VPNC_ABS\",\"hipWrapper\":\"$HIP_ABS\",\"stateDirectory\":\"/private/var/db/hyu-vpn\",\"ledgerDirectory\":\"/private/var/db/hyu-vpn/ledger\",\"openConnectExecutableSHA256\":\"$OC_HASH\",\"vpncScriptSHA256\":\"$VPNC_HASH\",\"hipWrapperSHA256\":\"$HIP_HASH\"}"
  write_file "$APP_SUPPORT/helper-config.json" 600 "$cfg"; fail_after app
  verify_installed_helper_stopped
  ensure_parent_dir "$SUDOERS_DST"; print -- "$ADMIN_USER ALL=(root) NOPASSWD: /Library/PrivilegedHelperTools/com.hyu.vpn.helper start, /Library/PrivilegedHelperTools/com.hyu.vpn.helper stop, /Library/PrivilegedHelperTools/com.hyu.vpn.helper status, /Library/PrivilegedHelperTools/com.hyu.vpn.helper repair" > "$SUDOERS_TMP"; /bin/chmod 440 "$SUDOERS_TMP"; run_cmd /usr/sbin/visudo -c -f "$SUDOERS_TMP"; backup_target "$SUDOERS_DST"; record_path "$SUDOERS_DST"; run_cmd /bin/mv "$SUDOERS_TMP" "$SUDOERS_DST"; [[ -e "$SUDOERS_TMP" ]] && /bin/mv "$SUDOERS_TMP" "$SUDOERS_DST"; /bin/chmod 440 "$SUDOERS_DST"; run_cmd /usr/sbin/visudo -c -f "$SUDOERS_DST"; run_cmd /usr/sbin/visudo -c; backup_target "$LEGACY_SUDOERS_DST"; fail_after sudoers
  render_plists; run_cmd /usr/sbin/chown "${ADMIN_USER}:staff" "$SERVICE_PLIST"; fail_after launchagent
  root_service_health_check
  write_file "$STATE_DIR/migration.json" 600 '{"liveHelper":"drained-before-replace-and-verified-stopped","rootServiceHealth":"schema-v1-status-ok"}'; write_installed_manifest; print commit >| "$TX_STATE"; durable_flush "$TX_STATE"; log "install-commit"; /bin/rm -rf "$PACKAGE_SNAPSHOT" "$TXN_SNAPSHOT"; print complete >| "$TX_STATE"; durable_flush "$TX_STATE"; log "install-complete"; durable_flush "$JOURNAL"; /bin/rm -rf "$ROOT_NATIVE_TOOL_DIR"
}
uninstall_phase(){
  if [[ -x "$HELPER_DST" ]]; then
    drain_existing_helper
    verify_installed_helper_stopped
  fi
  [[ -f "$SERVICE_PLIST" ]] && run_optional_cmd /bin/launchctl bootout "gui/$ADMIN_UID" "$SERVICE_PLIST"
  [[ -f "$LEGACY_MENUBAR_PLIST" ]] && run_optional_cmd /bin/launchctl bootout "gui/$ADMIN_UID/$MENU_LABEL"
  if [[ -f "$INSTALLED_PATHS" ]]; then /usr/bin/tail -r "$INSTALLED_PATHS" 2>/dev/null | while IFS= read -r rel; do [[ -n "$rel" ]] && remove_rel "$rel"; done; fi
  /usr/bin/find "$APP_SUPPORT" -depth -type d -empty -delete 2>/dev/null || true
  /usr/bin/find "$STATE_DIR" -depth -type d -empty -delete 2>/dev/null || true
  log "uninstall-complete"
}

[[ "$RECOVER" -eq 1 ]] && { rollback; exit 0; }
case "$ACTION" in install) install_phase;; uninstall) uninstall_phase;; esac
trap - ERR INT TERM
