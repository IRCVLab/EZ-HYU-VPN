#!/bin/zsh
set -euo pipefail
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"

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
  if [[ -e "$root" ]]; then real="$(CDPATH= cd -- "$root" && pwd -P)"; else real="$root"; fi
  case "$real" in /tmp/*|/private/tmp/*|/var/folders/*|/private/var/folders/*) ;; *) print -u2 "fresh temporary dry-run root required"; exit 65;; esac
  if [[ -e "$real" ]]; then
    [[ -d "$real" ]] || { print -u2 "fresh temporary dry-run root required"; exit 65; }
    for entry in "$real"/*(N) "$real"/.[!.]*(N); do
      [[ "${entry:t}" == ".hyu-vpn-dry-run-root" || "${entry:t}" == "Users" || "${entry:t}" == "private" ]] || { print -u2 "fresh empty dry-run root required"; exit 65; }
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
  real_tools="$(CDPATH= cd -- "$tools" && pwd -P)"; real_dry="$(CDPATH= cd -- "$dry" && pwd -P)"
  case "$real_tools" in "$real_dry"/*) ;; *) print -u2 "tools root must be inside dry-run root"; exit 65;; esac
  for tool in /usr/sbin/visudo /usr/sbin/chown /usr/bin/pgrep /usr/sbin/netstat /usr/sbin/scutil /usr/bin/env /bin/launchctl /bin/mv; do
    [[ -x "$real_tools$tool" ]] || { print -u2 "tools root missing allowlisted tool: $tool"; exit 65; }
  done
}

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
  ADMIN_HOME="$(/usr/bin/dscl . -read "/Users/$ADMIN_USER" NFSHomeDirectory | /usr/bin/awk '{print $2}')"
  [[ "$ADMIN_HOME" == /Users/* && "$ADMIN_HOME" != *..* ]] || { print -u2 "unsafe user home"; exit 65; }
fi
case "$ADMIN_USER" in (*[!A-Za-z0-9_.-]*|'') print -u2 "unsafe sudoers user"; exit 65;; esac
[[ "$ACTION" != install || -n "$STAGE" || "$RECOVER" -eq 1 ]] || { print -u2 "missing stage"; exit 64; }
[[ "$ACTION" != install || "$RECOVER" -eq 1 || "$STAGE_MANIFEST_SHA256" == [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f] ]] || { print -u2 "missing or invalid staged manifest digest"; exit 65; }
[[ "$ACTION" != install || "$RECOVER" -eq 1 || "$PACKAGE_MANIFEST_SHA256" == [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f] ]] || { print -u2 "missing or invalid package manifest digest"; exit 65; }

ROOT_PREFIX="${DRY_RUN_ROOT:-}"
map_path() { local p="$1"; [[ -n "$ROOT_PREFIX" && "$p" == /* ]] && print -- "$ROOT_PREFIX${p}" || print -- "$p"; }
rel_path() { local p="$1"; [[ -n "$ROOT_PREFIX" && "$p" == "$ROOT_PREFIX"/* ]] && print -- "${p#$ROOT_PREFIX/}" || { [[ "$p" == /* ]] && print -- "${p#/}" || print -- "$p"; }; }
tool_path() { local p="$1"; [[ -n "$TOOLS_ROOT" && -x "$TOOLS_ROOT$p" ]] && print -- "$TOOLS_ROOT$p" || print -- "$p"; }
STATE_DIR="$(map_path /private/var/db/hyu-vpn)"; TX_STATE="$STATE_DIR/transaction-state"; JOURNAL="$STATE_DIR/install-transaction.log"; TXN_PATHS="$STATE_DIR/txn-paths"; INSTALLED_MANIFEST="$STATE_DIR/installed-manifest.json"; INSTALLED_PATHS="$STATE_DIR/installed-paths.tsv"; COMMAND_LOG="$STATE_DIR/command-log.jsonl"
SUDOERS_TMP="$STATE_DIR/sudoers-candidate.$$"
APP_SUPPORT="$(map_path '/Library/Application Support/HYU VPN')"; HELPER_DST="$(map_path /Library/PrivilegedHelperTools/com.hyu.vpn.helper)"; VPNC_WRAPPER_DST="$(map_path /Library/PrivilegedHelperTools/com.hyu.vpn.vpnc-wrapper)"; SUDOERS_DST="$(map_path /etc/sudoers.d/hyu-vpn)"; APP_DST="$(map_path '/Applications/HYU VPN.app')"
LEGACY_SUDOERS_DST="$(map_path /etc/sudoers.d/com.hyu.vpn)"
USER_HOME="$(map_path "$ADMIN_HOME")"; SERVICE_PLIST="$USER_HOME/Library/LaunchAgents/com.hyu.vpn.service.plist"; LEGACY_MENUBAR_PLIST="$USER_HOME/Library/LaunchAgents/com.hyu.vpn.menubar.plist"; MENU_LABEL="com.hyu.vpn.menubar"
PACKAGE_SNAPSHOT="$STATE_DIR/package-snapshot"; TXN_SNAPSHOT="$STATE_DIR/root-snapshot"; LEGACY_LABEL="local.hyu-openconnect"

durable_flush(){
  local target="$1" dir
  [[ -e "$target" ]] || return 0
  /usr/bin/python3 -I -c 'import os,sys; p=sys.argv[1]; fd=os.open(p, os.O_RDONLY); os.fsync(fd); os.close(fd); d=os.path.dirname(p) or "."; dfd=os.open(d, os.O_RDONLY); os.fsync(dfd); os.close(dfd)' "$target"
}

NEED_PREINSTALL_RECOVERY=0; /bin/mkdir -p "$STATE_DIR"; /bin/chmod 700 "$STATE_DIR"; /bin/rm -f "$STATE_DIR"/sudoers-candidate.*(N); [[ -f "$JOURNAL" ]] || : >| "$JOURNAL"; [[ -f "$TXN_PATHS" ]] || : >| "$TXN_PATHS"; if [[ "$RECOVER" -eq 1 ]]; then :; elif [[ -z "$DRY_RUN_ROOT" && -s "$TXN_PATHS" && "$(/bin/cat "$TX_STATE" 2>/dev/null || true)" == "in_progress" ]]; then NEED_PREINSTALL_RECOVERY=1; else : >| "$JOURNAL"; : >| "$TXN_PATHS"; /bin/rm -rf "$STATE_DIR/backups" "$STATE_DIR/backups.tsv" "$STATE_DIR/native-suppression-transaction" "$PACKAGE_SNAPSHOT" "$TXN_SNAPSHOT"; print complete >| "$TX_STATE"; durable_flush "$TX_STATE"; fi
log(){ print -- "$1" >> "$JOURNAL"; durable_flush "$JOURNAL"; }
record_cmd(){ print -- "$*" >> "$COMMAND_LOG"; durable_flush "$COMMAND_LOG"; }
run_cmd(){ local exe="$(tool_path "$1")"; shift; record_cmd "$exe $*"; if [[ -z "$DRY_RUN_ROOT" || -n "$TOOLS_ROOT" ]]; then "$exe" "$@"; fi; }
run_optional_cmd(){ local exe="$(tool_path "$1")"; shift; record_cmd "$exe $*"; if [[ -z "$DRY_RUN_ROOT" || -n "$TOOLS_ROOT" ]]; then "$exe" "$@" || true; fi; }
record_path(){ rel_path "$1" >> "$TXN_PATHS"; durable_flush "$TXN_PATHS"; }

capture_cmd(){ local exe="$(tool_path "$1")"; shift; record_cmd "$exe $*"; [[ -n "$DRY_RUN_ROOT" && -z "$TOOLS_ROOT" ]] && return 0; "$exe" "$@" 2>/dev/null || true; }
helper_state(){
  local raw
  raw="$(capture_cmd "$HELPER_DST" status)"
  print -r -- "$raw" | /usr/bin/python3 -I -c 'import json,sys
try: data=json.load(sys.stdin)
except Exception: raise SystemExit(1)
if not isinstance(data,dict) or data.get("schema_version") != 1: raise SystemExit(1)
state=data.get("state")
if state not in {"stopped","running","repair-required"}: raise SystemExit(1)
print(state)
' 2>/dev/null
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
      run_cmd "$HELPER_DST" stop || { print -u2 "existing HYU VPN session could not be stopped safely"; return 1; }
      [[ "$(helper_state)" == stopped ]] || { print -u2 "existing HYU VPN helper did not stop"; return 1; }
      log "old-helper-drained"
      ;;
    repair-required)
      if run_cmd "$HELPER_DST" repair; then
        [[ "$(helper_state)" == stopped ]] || { print -u2 "existing HYU VPN helper repair did not reach stopped"; return 1; }
        log "old-helper-repaired"
      else
        after="$(helper_state)" || { print -u2 "existing HYU VPN helper state became unreadable"; return 1; }
        case "$after" in
          stopped) log "old-helper-repaired-after-nonzero" ;;
          repair-required) log "old-helper-repair-deferred" ;;
          *) print -u2 "existing HYU VPN helper changed state during failed repair"; return 1 ;;
        esac
      fi
      ;;
  esac
}
stop_current_user_service(){
  log "current-service-stop-start"
  run_optional_cmd /bin/launchctl bootout "gui/$ADMIN_UID/com.hyu.vpn.service"
  log "current-service-stopped"
}
verify_installed_helper_stopped(){
  [[ -n "$DRY_RUN_ROOT" && -z "$TOOLS_ROOT" ]] && return 0
  local state
  state="$(helper_state)" || { print -u2 "installed HYU VPN helper status is invalid"; return 1; }
  if [[ "$state" == repair-required ]]; then
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
validate_native_snapshot(){
  [[ -n "$DRY_RUN_ROOT" && -z "$TOOLS_ROOT" ]] && return 0
  local snapshot="$STATE_DIR/native-suppression.json"
  local mode owner
  [[ -f "$snapshot" && ! -L "$snapshot" ]] || { print -u2 "native suppression snapshot missing"; return 1; }
  mode="$(/usr/bin/stat -f %Lp "$snapshot")"; while [[ ${#mode} -lt 4 ]]; do mode="0$mode"; done
  [[ "$mode" == "0600" ]] || { print -u2 "native suppression snapshot must be 0600"; return 1; }
  if [[ -z "$DRY_RUN_ROOT" ]]; then owner="$(/usr/bin/stat -f %Su "$snapshot")"; [[ "$owner" == root ]] || { print -u2 "native suppression snapshot must be root-owned"; return 1; }; fi
  /usr/bin/python3 -I -c 'import json,sys
allowed={
("com.paloaltonetworks.gp.pangpsd","launchd-system","/Library/LaunchDaemons/com.paloaltonetworks.gp.pangpsd.plist"),
("com.paloaltonetworks.gp.pangpa","launchd-gui","/Library/LaunchAgents/com.paloaltonetworks.gp.pangpa.plist"),
("com.paloaltonetworks.gp.pangps","launchd-gui","/Library/LaunchAgents/com.paloaltonetworks.gp.pangps.plist"),
}
def pairs(xs):
    seen=set(); out={}
    for k,v in xs:
        if k in seen: raise ValueError("duplicate key")
        seen.add(k); out[k]=v
    return out
data=json.load(open(sys.argv[1]), object_pairs_hook=pairs)
if set(data)!={"schema_version","console_uid","mechanisms"}: raise SystemExit("schema")
if data.get("schema_version") != 1: raise SystemExit("schema")
uid=data.get("console_uid")
if uid is not None and (type(uid) is not int or uid < 0): raise SystemExit("uid")
mechs=data.get("mechanisms")
if not isinstance(mechs,list): raise SystemExit("mechanisms")
seen=set()
for item in mechs:
    if not isinstance(item,dict) or set(item)!={"identifier","kind","enabled","exact_target","running"}: raise SystemExit("mechanism")
    tup=(item["identifier"], item["kind"], item["exact_target"])
    if tup not in allowed or type(item["enabled"]) is not bool or type(item["running"]) is not bool: raise SystemExit("target")
    if item["identifier"] in seen: raise SystemExit("duplicate")
    seen.add(item["identifier"])
' "$snapshot" 2>/dev/null || { print -u2 "native suppression snapshot schema invalid"; return 1; }
}
quarantine_legacy(){
  local proc_out net_out dns_out disabled_out
  log "legacy-quarantine-start"
  run_optional_cmd /bin/launchctl print "gui/$ADMIN_UID/$LEGACY_LABEL"
  run_optional_cmd /bin/launchctl bootout "gui/$ADMIN_UID/$LEGACY_LABEL"
  run_cmd /bin/launchctl disable "gui/$ADMIN_UID/$LEGACY_LABEL"
  disabled_out="$(capture_cmd /bin/launchctl print-disabled "gui/$ADMIN_UID")"
  [[ "$disabled_out" == *"$LEGACY_LABEL"* || -n "$DRY_RUN_ROOT" ]] || { print -u2 "legacy service disable not verified"; return 1; }
  proc_out="$(capture_cmd /usr/bin/pgrep -fl 'openconnect.*secure\.hanyang\.ac\.kr|local\.hyu-openconnect|hyu-vpn-connect')"
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
verify_package_snapshot_manifest(){
  local snapshot="$1" manifest_json="$1/manifest.json"
  [[ -f "$manifest_json" && ! -L "$manifest_json" ]] || { print -u2 "missing package snapshot manifest"; return 1; }
  /usr/bin/python3 -I -c 'import hashlib,json,os,stat,sys
MAX=2*1024*1024
def pairs(xs):
    seen=set(); out={}
    for k,v in xs:
        if k in seen: raise SystemExit("duplicate JSON key")
        seen.add(k); out[k]=v
    return out
root=sys.argv[1]
manifest=os.path.join(root,"manifest.json")
st=os.lstat(manifest)
if os.path.islink(manifest) or not stat.S_ISREG(st.st_mode) or st.st_size > MAX: raise SystemExit("manifest must be bounded regular file")
fd=os.open(manifest, os.O_RDONLY | getattr(os,"O_NOFOLLOW",0)); raw=os.read(fd, MAX+1); os.close(fd)
if len(raw) > MAX: raise SystemExit("manifest too large")
data=json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
if data.get("schema") != 1 or not isinstance(data.get("files"), dict): raise SystemExit("package manifest schema mismatch")
expected=data["files"]
script=expected.get("installer/manifest.py")
if not isinstance(script,dict) or sorted(script) != ["mode","sha256","size"]: raise SystemExit("package verifier script missing")
actual={}
for walk_root, dirs, files in os.walk(root):
    for name in files:
        path=os.path.join(walk_root,name)
        rel=os.path.relpath(path, root)
        st=os.lstat(path)
        if rel == "manifest.json":
            if not stat.S_ISREG(st.st_mode): raise SystemExit("manifest must be regular")
            continue
        if os.path.islink(path): raise SystemExit(f"symlink in package snapshot: {rel}")
        if not stat.S_ISREG(st.st_mode): raise SystemExit(f"special package snapshot entry rejected: {rel}")
        h=hashlib.sha256()
        with open(path,"rb") as f:
            for chunk in iter(lambda:f.read(1024*1024), b""): h.update(chunk)
        actual[rel]={"sha256":h.hexdigest(),"mode":format(stat.S_IMODE(st.st_mode),"04o"),"size":st.st_size}
if set(actual) != set(expected): raise SystemExit("package snapshot extras/missing mismatch")
for rel, info in expected.items():
    if sorted(info) != ["mode","sha256","size"]: raise SystemExit("package manifest schema mismatch")
    if actual[rel]["sha256"] != info["sha256"]: raise SystemExit(f"hash mismatch: {rel}")
    if actual[rel]["mode"] != info["mode"]: raise SystemExit(f"mode mismatch: {rel}")
    if actual[rel]["size"] != info["size"]: raise SystemExit(f"size mismatch: {rel}")
' "$snapshot" 2>"$STATE_DIR/package-verify.err" || { /bin/cat "$STATE_DIR/package-verify.err" >&2; return 1; }
}
verify_manifest_arg_relation(){
  local payload_real manifest_dir_real manifest_real
  [[ -d "$PAYLOAD" && -f "$MANIFEST" && ! -L "$MANIFEST" ]] || { print -u2 "missing package payload or manifest"; return 1; }
  payload_real="$(CDPATH= cd -- "$PAYLOAD" && pwd -P)"
  manifest_dir_real="$(CDPATH= cd -- "$(/usr/bin/dirname "$MANIFEST")" && pwd -P)"
  manifest_real="$manifest_dir_real/$(/usr/bin/basename "$MANIFEST")"
  [[ "$manifest_real" == "$payload_real/manifest.json" ]] || { print -u2 "manifest must be package top manifest"; return 1; }
}
copy_package_snapshot(){
  verify_manifest_arg_relation
  /bin/rm -rf "$PACKAGE_SNAPSHOT" "$TXN_SNAPSHOT"
  /bin/mkdir -p "$PACKAGE_SNAPSHOT"
  /bin/chmod 700 "$PACKAGE_SNAPSHOT"
  /usr/bin/tar -C "$PAYLOAD" -cf - . | /usr/bin/tar -C "$PACKAGE_SNAPSHOT" -xpf -
  /bin/chmod 700 "$PACKAGE_SNAPSHOT"
  verify_package_manifest_digest "$PACKAGE_SNAPSHOT"
  verify_package_snapshot_manifest "$PACKAGE_SNAPSHOT" || { print -u2 "package snapshot manifest verification failed"; return 1; }
  [[ -f "$PACKAGE_SNAPSHOT/installer/manifest.py" && ! -L "$PACKAGE_SNAPSHOT/installer/manifest.py" ]] || { print -u2 "package verifier script must be regular"; return 1; }
  /usr/bin/python3 -I "$PACKAGE_SNAPSHOT/installer/manifest.py" --payload "$PACKAGE_SNAPSHOT" --manifest "$PACKAGE_SNAPSHOT/manifest.json" --verify-manifest || { print -u2 "package snapshot manifest.py verification failed"; return 1; }
  /usr/bin/python3 -I "$PACKAGE_SNAPSHOT/installer/manifest.py" --payload "$PACKAGE_SNAPSHOT" --manifest "$PACKAGE_SNAPSHOT/manifest.json" --stage-user-payload --stage-dir "$TXN_SNAPSHOT" || { print -u2 "root package staging failed"; return 1; }
  verify_stage_digest "$TXN_SNAPSHOT"
  verify_stage_manifest "$TXN_SNAPSHOT"
}
fail_after(){ [[ "${HYU_VPN_FAIL_AFTER:-}" == "$1" ]] && { print -u2 "injected failure after $1"; return 1; } || return 0; }
remove_rel(){ local rel="$1" target; case "$rel" in /*|*..*|Library/Preferences/SystemConfiguration*) print -u2 "unsafe installed path: $rel"; return 1;; esac; case "$rel" in Library/Application\ Support/HYU\ VPN/*|Library/PrivilegedHelperTools/com.hyu.vpn.helper|Library/PrivilegedHelperTools/com.hyu.vpn.vpnc-wrapper|Applications/HYU\ VPN.app|etc/sudoers.d/hyu-vpn|etc/sudoers.d/com.hyu.vpn|Users/*/Library/LaunchAgents/com.hyu.vpn.*.plist|private/var/db/hyu-vpn/*) ;; *) print -u2 "unsafe installed path: $rel"; return 1;; esac; [[ "$rel" == /* ]] && target="$(map_path "$rel")" || target="$ROOT_PREFIX/$rel"; [[ -e "$target" || -L "$target" ]] || return 0; [[ -d "$target" && ! -L "$target" ]] && /bin/rm -rf "$target" || /bin/rm -f "$target"; }
backup_target(){ local target="$1"; local rel hash backup; rel="$(rel_path "$target")"; hash="$(print -r -- "$rel" | /usr/bin/shasum -a 256 | /usr/bin/awk '{print $1}')"; backup="$STATE_DIR/backups/$hash"; log "before-backup $rel $backup"; if [[ -e "$target" || -L "$target" ]]; then /bin/mkdir -p "$(/usr/bin/dirname "$backup")"; /bin/mv "$target" "$backup"; print -- "$rel|$backup" >> "$STATE_DIR/backups.tsv"; durable_flush "$STATE_DIR/backups.tsv"; fi; }
rollback(){
  local rel backup rollback_status=0
  log "rollback-start"
  /bin/rm -f "$SUDOERS_TMP"
  /bin/rm -rf "$PACKAGE_SNAPSHOT" "$TXN_SNAPSHOT"
  if [[ -f "$STATE_DIR/native-suppression-transaction" ]]; then
    if [[ -x "$APP_SUPPORT/bin/hyu-vpn-native-client" && -f "$STATE_DIR/native-suppression.json" ]]; then
      run_cmd /usr/bin/env -i PATH=/usr/bin:/bin SUDO_UID="$ADMIN_UID" /usr/bin/python3 "$APP_SUPPORT/bin/hyu-vpn-native-client" restore-auto-launch || { print -u2 "native restore failed during rollback"; log "rollback-preserved-native-assets"; return 1; }
      /bin/rm -f "$STATE_DIR/native-suppression-transaction"
      log "rollback-native-restored"
    else
      /bin/rm -f "$STATE_DIR/native-suppression-transaction"
      log "rollback-stale-native-marker-cleared"
    fi
  fi
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
  : >| "$TXN_PATHS"
  print complete >| "$TX_STATE"
  durable_flush "$TX_STATE"
  durable_flush "$TXN_PATHS"
  log "rollback-complete"
}
trap 'rollback' ERR INT TERM
[[ "$NEED_PREINSTALL_RECOVERY" -eq 1 ]] && { log "preinstall-recovery-start"; rollback; : >| "$JOURNAL"; : >| "$TXN_PATHS"; log "preinstall-recovery-complete"; }

verify_no_symlinks(){ /usr/bin/find "$1" -type l -print -quit | /usr/bin/grep -q . && { print -u2 "symlink in staged payload"; return 1; } || return 0; }
verify_stage_manifest(){
  local stage="$1"
  local manifest_json="$stage/manifest.json"
  [[ -f "$manifest_json" && ! -L "$manifest_json" ]] || { print -u2 "missing staged manifest"; return 1; }
  verify_no_symlinks "$stage"
  /usr/bin/python3 -I -c 'import hashlib,json,os,stat,sys
def pairs(xs):
    seen=set(); out={}
    for k,v in xs:
        if k in seen: raise SystemExit("duplicate JSON key")
        seen.add(k); out[k]=v
    return out
stage=sys.argv[1]
manifest=os.path.join(stage,"manifest.json")
st=os.lstat(manifest)
if os.path.islink(manifest) or not stat.S_ISREG(st.st_mode) or st.st_size > 2097152: raise SystemExit("manifest must be bounded regular file")
fd=os.open(manifest, os.O_RDONLY | getattr(os,"O_NOFOLLOW",0)); raw=os.read(fd, 2097153); os.close(fd)
if len(raw) > 2097152: raise SystemExit("manifest too large")
data=json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
if data.get("schema") != 1 or not isinstance(data.get("files"), dict): raise SystemExit("staged manifest schema mismatch")
actual={}
for root, dirs, files in os.walk(stage):
    for name in files:
        path=os.path.join(root,name)
        rel=os.path.relpath(path, stage)
        st=os.lstat(path)
        if rel == "manifest.json":
            if not stat.S_ISREG(st.st_mode): raise SystemExit("manifest must be regular")
            continue
        if os.path.islink(path): raise SystemExit("symlink in staged payload")
        if not stat.S_ISREG(st.st_mode): raise SystemExit(f"special staged entry rejected: {rel}")
        h=hashlib.sha256()
        with open(path,"rb") as f:
            for chunk in iter(lambda:f.read(1024*1024), b""): h.update(chunk)
        actual[rel]={"sha256":h.hexdigest(),"mode":format(stat.S_IMODE(st.st_mode),"04o"),"size":st.st_size}
expected=data["files"]
if set(actual) != set(expected): raise SystemExit("staged manifest extras/missing mismatch")
for rel, info in expected.items():
    if sorted(info) != ["mode","sha256","size"]: raise SystemExit("staged manifest schema mismatch")
    if actual[rel]["sha256"] != info["sha256"]: raise SystemExit(f"hash mismatch: {rel}")
    if actual[rel]["mode"] != info["mode"]: raise SystemExit(f"mode mismatch: {rel}")
    if actual[rel]["size"] != info["size"]: raise SystemExit(f"size mismatch: {rel}")
' "$stage" 2>"$STATE_DIR/stage-verify.err" || { /bin/cat "$STATE_DIR/stage-verify.err" >&2; return 1; }
}
copy_snapshot(){ [[ -d "$STAGE" ]] || { print -u2 "missing user stage"; return 1; }; verify_stage_digest "$STAGE"; copy_package_snapshot; }
copy_file(){ local src="$1" dst="$2" mode="$3"; log "before-mutate $(rel_path "$dst")"; backup_target "$dst"; /bin/mkdir -p "$(/usr/bin/dirname "$dst")"; /bin/cp "$src" "$dst"; /bin/chmod "$mode" "$dst"; record_path "$dst"; durable_flush "$dst"; durable_flush "$TXN_PATHS"; log "complete $(rel_path "$dst")"; }
copy_dir(){ local src="$1" dst="$2" mode="$3"; log "before-mutate-dir $(rel_path "$dst")"; backup_target "$dst"; /bin/mkdir -p "$(/usr/bin/dirname "$dst")"; /bin/mkdir -p "$dst"; /bin/chmod 700 "$dst"; /usr/bin/tar -C "$src" -cf - . | /usr/bin/tar -C "$dst" -xpf -; run_cmd /usr/sbin/chown -R root:wheel "$dst"; /bin/chmod -R u+rwX,go-w "$dst"; /bin/chmod "$mode" "$dst"; record_path "$dst"; durable_flush "$dst"; durable_flush "$TXN_PATHS"; log "complete $(rel_path "$dst")"; }
write_file(){ local dst="$1" mode="$2" content="$3"; log "before-mutate-write $(rel_path "$dst")"; backup_target "$dst"; /bin/mkdir -p "$(/usr/bin/dirname "$dst")"; print -- "$content" > "$dst"; /bin/chmod "$mode" "$dst"; record_path "$dst"; durable_flush "$dst"; durable_flush "$TXN_PATHS"; log "complete $(rel_path "$dst")"; }
render_from_template(){ local template="$1" dst="$2"; /usr/bin/sed -e "s#@USER_HOME@#/Users/$ADMIN_USER#g" -e "s#@APP_PATH@#/Applications/HYU VPN.app#g" -e "s#@SERVICE_PATH@#/Library/Application Support/HYU VPN/bin/hyu-vpn-service#g" -e "s#@CONTROL_PATH@#/Library/Application Support/HYU VPN/bin/hyu-vpn-control#g" "$template" > "$dst"; }
render_plists(){ /bin/mkdir -p "$(/usr/bin/dirname "$SERVICE_PLIST")"; backup_target "$SERVICE_PLIST"; render_from_template "$TXN_SNAPSHOT/config/launchd/com.hyu.vpn.service.plist.in" "$SERVICE_PLIST"; /bin/chmod 644 "$SERVICE_PLIST"; record_path "$SERVICE_PLIST"; }
migrate_legacy_menu_launchagent(){ log "legacy-menu-launchagent-migration-start"; run_optional_cmd /bin/launchctl bootout "gui/$ADMIN_UID/$MENU_LABEL"; if [[ -f "$LEGACY_MENUBAR_PLIST" || -L "$LEGACY_MENUBAR_PLIST" ]]; then backup_target "$LEGACY_MENUBAR_PLIST"; /bin/rm -f "$LEGACY_MENUBAR_PLIST"; log "legacy-menu-launchagent-removed com.hyu.vpn.menubar"; else log "legacy-menu-launchagent-absent com.hyu.vpn.menubar"; fi; }
write_installed_manifest(){ local tmp="$INSTALLED_MANIFEST.tmp" paths_tmp="$INSTALLED_PATHS.tmp" first=1; print '{"schema":1,"paths":[' > "$tmp"; : > "$paths_tmp"; while IFS= read -r rel; do [[ -z "$rel" ]] && continue; [[ "$rel" == private/var/db/hyu-vpn/installed-manifest.json || "$rel" == private/var/db/hyu-vpn/installed-paths.tsv ]] && continue; print -- "$rel" >> "$paths_tmp"; [[ $first -eq 0 ]] && print ',' >> "$tmp"; first=0; printf '"%s"' "$rel" >> "$tmp"; done < "$TXN_PATHS"; print ']}' >> "$tmp"; /bin/mv "$tmp" "$INSTALLED_MANIFEST"; /bin/mv "$paths_tmp" "$INSTALLED_PATHS"; /bin/chmod 600 "$INSTALLED_MANIFEST" "$INSTALLED_PATHS"; durable_flush "$INSTALLED_MANIFEST"; durable_flush "$INSTALLED_PATHS"; }

install_phase(){
  print in_progress >| "$TX_STATE"; durable_flush "$TX_STATE"; log "before-snapshot"; copy_snapshot; fail_after snapshot
  stop_current_user_service
  drain_existing_helper
  quarantine_legacy
  migrate_legacy_menu_launchagent
  copy_file "$TXN_SNAPSHOT/com.hyu.vpn.helper" "$HELPER_DST" 755; fail_after helper
  /bin/mkdir -p "$APP_SUPPORT/bin" "$APP_SUPPORT/runtime/openconnect" "$APP_SUPPORT/runtime/vpnc" "$STATE_DIR/ledger"
  /bin/chmod 755 "$APP_SUPPORT" "$APP_SUPPORT/bin" "$APP_SUPPORT/runtime" "$APP_SUPPORT/runtime/openconnect" "$APP_SUPPORT/runtime/vpnc"; /bin/chmod 700 "$STATE_DIR" "$STATE_DIR/ledger"
  RUNTIME_DIR="$APP_SUPPORT/runtime/current"
  copy_dir "$TXN_SNAPSHOT/runtime/bin" "$RUNTIME_DIR/bin" 755; [[ -d "$TXN_SNAPSHOT/runtime/lib" ]] && copy_dir "$TXN_SNAPSHOT/runtime/lib" "$RUNTIME_DIR/lib" 755
  copy_file "$TXN_SNAPSHOT/runtime/gp-hip-report" "$APP_SUPPORT/runtime/gp-hip-report" 755; copy_file "$TXN_SNAPSHOT/runtime/vpnc/hyu-vpnc-wrapper" "$APP_SUPPORT/runtime/vpnc/hyu-vpnc-wrapper" 755; copy_file "$TXN_SNAPSHOT/runtime/vpnc/hyu-vpnc-wrapper" "$VPNC_WRAPPER_DST" 755; copy_file "$TXN_SNAPSHOT/runtime/vpnc/hyu-vpnc-wrapperd" "$APP_SUPPORT/runtime/vpnc/hyu-vpnc-wrapperd" 755; copy_file "$TXN_SNAPSHOT/runtime/vpnc/vpnc-script" "$APP_SUPPORT/runtime/vpnc/vpnc-script" 755
  copy_file "$TXN_SNAPSHOT/backend/hyu-vpn-control" "$APP_SUPPORT/bin/hyu-vpn-control" 755; copy_file "$TXN_SNAPSHOT/backend/hyu-vpn-service" "$APP_SUPPORT/bin/hyu-vpn-service" 755; copy_file "$TXN_SNAPSHOT/backend/hyu-vpn-connect" "$APP_SUPPORT/bin/hyu-vpn-connect" 755; copy_file "$TXN_SNAPSHOT/bin/hyu-vpn-native-client" "$APP_SUPPORT/bin/hyu-vpn-native-client" 755; copy_dir "$TXN_SNAPSHOT/src/hyu_vpn" "$APP_SUPPORT/src/hyu_vpn" 755; copy_dir "$TXN_SNAPSHOT/HYU VPN.app" "$APP_DST" 755
  run_cmd /usr/sbin/chown -R root:wheel "$APP_SUPPORT" "$HELPER_DST" "$VPNC_WRAPPER_DST" "$APP_DST" "$STATE_DIR"
  WRAPPERD_HASH="$(sha256 "$APP_SUPPORT/runtime/vpnc/hyu-vpnc-wrapperd")"; write_file "$APP_SUPPORT/runtime/vpnc/hyu-vpnc-wrapperd.sha256" 644 "$WRAPPERD_HASH"; OATH_HASH="$(sha256 "$RUNTIME_DIR/bin/oathtool")"; write_file "$APP_SUPPORT/connector-config.json" 644 "{\"schema_version\":1,\"oathtool_path\":\"/Library/Application Support/HYU VPN/runtime/current/bin/oathtool\",\"oathtool_sha256\":\"$OATH_HASH\"}"
  OC_ABS="/Library/Application Support/HYU VPN/runtime/current/bin/openconnect"; VPNC_ABS="/Library/PrivilegedHelperTools/com.hyu.vpn.vpnc-wrapper"; HIP_ABS="/Library/Application Support/HYU VPN/runtime/gp-hip-report"; OC_HASH="$(sha256 "$RUNTIME_DIR/bin/openconnect")"; VPNC_HASH="$(sha256 "$VPNC_WRAPPER_DST")"; HIP_HASH="$(sha256 "$APP_SUPPORT/runtime/gp-hip-report")"; cfg="{\"openConnectExecutable\":\"$OC_ABS\",\"vpncScript\":\"$VPNC_ABS\",\"hipWrapper\":\"$HIP_ABS\",\"stateDirectory\":\"/private/var/db/hyu-vpn\",\"ledgerDirectory\":\"/private/var/db/hyu-vpn/ledger\",\"openConnectExecutableSHA256\":\"$OC_HASH\",\"vpncScriptSHA256\":\"$VPNC_HASH\",\"hipWrapperSHA256\":\"$HIP_HASH\"}"
  write_file "$APP_SUPPORT/helper-config.json" 600 "$cfg"; fail_after app
  verify_installed_helper_stopped
  /bin/mkdir -p "$(/usr/bin/dirname "$SUDOERS_DST")"; print -- "$ADMIN_USER ALL=(root) NOPASSWD: /Library/PrivilegedHelperTools/com.hyu.vpn.helper start, /Library/PrivilegedHelperTools/com.hyu.vpn.helper stop, /Library/PrivilegedHelperTools/com.hyu.vpn.helper status, /Library/PrivilegedHelperTools/com.hyu.vpn.helper repair" > "$SUDOERS_TMP"; /bin/chmod 440 "$SUDOERS_TMP"; run_cmd /usr/sbin/visudo -c -f "$SUDOERS_TMP"; backup_target "$SUDOERS_DST"; record_path "$SUDOERS_DST"; run_cmd /bin/mv "$SUDOERS_TMP" "$SUDOERS_DST"; [[ -e "$SUDOERS_TMP" ]] && /bin/mv "$SUDOERS_TMP" "$SUDOERS_DST"; /bin/chmod 440 "$SUDOERS_DST"; run_cmd /usr/sbin/visudo -c -f "$SUDOERS_DST"; run_cmd /usr/sbin/visudo -c; backup_target "$LEGACY_SUDOERS_DST"; fail_after sudoers
  if [[ -f "$STATE_DIR/native-suppression.json" ]]; then
    validate_native_snapshot
    run_cmd /usr/bin/env -i PATH=/usr/bin:/bin SUDO_UID="$ADMIN_UID" /usr/bin/python3 "$APP_SUPPORT/bin/hyu-vpn-native-client" verify-suppressed
    log "native-suppression-preserved"
  else
    print native_suppression_started >| "$STATE_DIR/native-suppression-transaction"; durable_flush "$STATE_DIR/native-suppression-transaction"
    run_cmd /usr/bin/env -i PATH=/usr/bin:/bin SUDO_UID="$ADMIN_UID" /usr/bin/python3 "$APP_SUPPORT/bin/hyu-vpn-native-client" suppress-auto-launch
    validate_native_snapshot; print native_suppressed >| "$STATE_DIR/native-suppression-transaction"; durable_flush "$STATE_DIR/native-suppression-transaction"
  fi
  fail_after native-suppression
  render_plists; run_cmd /usr/sbin/chown "${ADMIN_USER}:staff" "$SERVICE_PLIST"; fail_after launchagent
  write_file "$STATE_DIR/migration.json" 600 '{"liveHelper":"drained-before-replace-and-verified-stopped"}'; write_installed_manifest; /bin/rm -rf "$PACKAGE_SNAPSHOT" "$TXN_SNAPSHOT"; /bin/rm -f "$STATE_DIR/native-suppression-transaction"; print complete >| "$TX_STATE"; durable_flush "$TX_STATE"; log "install-complete"
}
uninstall_phase(){
  [[ -x "$HELPER_DST" ]] && { run_optional_cmd /Library/PrivilegedHelperTools/com.hyu.vpn.helper status; run_optional_cmd /Library/PrivilegedHelperTools/com.hyu.vpn.helper stop; run_optional_cmd /Library/PrivilegedHelperTools/com.hyu.vpn.helper repair; }
  [[ -f "$SERVICE_PLIST" ]] && run_optional_cmd /bin/launchctl bootout "gui/$ADMIN_UID" "$SERVICE_PLIST"
  [[ -f "$LEGACY_MENUBAR_PLIST" ]] && run_optional_cmd /bin/launchctl bootout "gui/$ADMIN_UID/$MENU_LABEL"
  [[ -x "$APP_SUPPORT/bin/hyu-vpn-native-client" && -f "$STATE_DIR/native-suppression.json" ]] && run_optional_cmd /usr/bin/env -i PATH=/usr/bin:/bin SUDO_UID="$ADMIN_UID" /usr/bin/python3 "$APP_SUPPORT/bin/hyu-vpn-native-client" restore-auto-launch
  if [[ -f "$INSTALLED_PATHS" ]]; then /usr/bin/tail -r "$INSTALLED_PATHS" 2>/dev/null | while IFS= read -r rel; do [[ -n "$rel" ]] && remove_rel "$rel"; done; fi
  /usr/bin/find "$APP_SUPPORT" -depth -type d -empty -delete 2>/dev/null || true
  /usr/bin/find "$STATE_DIR" -depth -type d -empty -delete 2>/dev/null || true
  log "native-restore-fixed-cli-boundary"; log "uninstall-complete"
}

[[ "$RECOVER" -eq 1 ]] && { rollback; exit 0; }
case "$ACTION" in install) install_phase;; uninstall) uninstall_phase;; esac
trap - ERR INT TERM
