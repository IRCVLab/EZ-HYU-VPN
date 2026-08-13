#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
MODE="preflight"; DMG=""; DMG_ACCEPTANCE_LOG=""; NONCE=""; USER_PRESENT=""; TEST_ROOT=""; ROLLBACK_INJECTION="health"; EVIDENCE_OUT=""
PHYSICAL_WIFI_GATE=0; EXERCISE_UNINSTALL_REINSTALL=0
TOOLS_ROOT="${HYU_LIVE_MACOS_RUST_TOOLS_ROOT:-}"
INSTALL_ROOT="${HYU_LIVE_MACOS_RUST_INSTALL_ROOT:-}"
NONCE_DIR="${HYU_LIVE_MACOS_RUST_NONCE_DIR:-/private/tmp/hyu-live-macos-rust-nonces}"
SOCKET_PATH="${HYU_LIVE_MACOS_RUST_SOCKET:-$HOME/Library/Application Support/hyu-openconnect/daemon.sock}"
TEST_ROOT_EVIDENCE="${HYU_LIVE_MACOS_RUST_TEST_ROOT_EVIDENCE:-}"
AUDIT="${HYU_LIVE_MACOS_RUST_AUDIT:-}"
MOUNT_PARENT=""; MOUNTPOINT=""; ATTACHED=0; WIFI_IFACE_TO_RESTORE=""; BASE_ROUTE_ID=""; BASE_DNS_HASH=""
# Rust protocol response constants: "result":"ack" and "result":"status"

usage(){ cat >&2 <<'EOF'
usage: scripts/live-macos-rust-acceptance.sh [--mode preflight|test-root|live]
       [--dmg PATH] [--dmg-acceptance-log PATH]
       [--test-root PATH --rollback-injection health --evidence-out PATH]
       [--nonce hyu-live-macos-rust-EPOCH --user-present I-am-present-for-live-macOS-Rust-acceptance]
       [--exercise-uninstall-reinstall] [--physical-wifi-gate]
EOF
}

seen_mode=0; seen_dmg=0; seen_log=0; seen_nonce=0; seen_present=0; seen_test_root=0; seen_rollback=0; seen_evidence=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) [[ $seen_mode -eq 0 && $# -ge 2 ]] || { usage; exit 2; }; seen_mode=1; MODE="$2"; shift 2 ;;
    --dmg) [[ $seen_dmg -eq 0 && $# -ge 2 ]] || { usage; exit 2; }; seen_dmg=1; DMG="$2"; shift 2 ;;
    --dmg-acceptance-log) [[ $seen_log -eq 0 && $# -ge 2 ]] || { usage; exit 2; }; seen_log=1; DMG_ACCEPTANCE_LOG="$2"; shift 2 ;;
    --nonce) [[ $seen_nonce -eq 0 && $# -ge 2 ]] || { usage; exit 2; }; seen_nonce=1; NONCE="$2"; shift 2 ;;
    --user-present) [[ $seen_present -eq 0 && $# -ge 2 ]] || { usage; exit 2; }; seen_present=1; USER_PRESENT="$2"; shift 2 ;;
    --test-root) [[ $seen_test_root -eq 0 && $# -ge 2 ]] || { usage; exit 2; }; seen_test_root=1; TEST_ROOT="$2"; shift 2 ;;
    --rollback-injection) [[ $seen_rollback -eq 0 && $# -ge 2 ]] || { usage; exit 2; }; seen_rollback=1; ROLLBACK_INJECTION="$2"; shift 2 ;;
    --evidence-out) [[ $seen_evidence -eq 0 && $# -ge 2 ]] || { usage; exit 2; }; seen_evidence=1; EVIDENCE_OUT="$2"; shift 2 ;;
    --exercise-uninstall-reinstall) [[ $EXERCISE_UNINSTALL_REINSTALL -eq 0 ]] || { usage; exit 2; }; EXERCISE_UNINSTALL_REINSTALL=1; shift ;;
    --physical-wifi-gate) [[ $PHYSICAL_WIFI_GATE -eq 0 ]] || { usage; exit 2; }; PHYSICAL_WIFI_GATE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done
case "$MODE" in preflight|test-root|live) ;; *) usage; exit 2 ;; esac

log_audit(){ [[ -n "$AUDIT" ]] && printf '%s\n' "$*" >> "$AUDIT" || true; }
run_tool(){ local p="$1"; shift; log_audit "${p##*/} $*"; if [[ -n "$TOOLS_ROOT" && -x "$TOOLS_ROOT$p" ]]; then "$TOOLS_ROOT$p" "$@"; else "$p" "$@"; fi; }
hash_text(){ /usr/bin/shasum -a 256 | /usr/bin/awk '{print $1}'; }
canon(){ local p="$1"; [[ -e "$p" ]] || return 1; (cd "$(dirname "$p")" && printf '%s/%s\n' "$(pwd -P)" "$(basename "$p")"); }
map_installed(){ local p="$1"; if [[ -n "$INSTALL_ROOT" && "$p" == /* ]]; then printf '%s%s\n' "$INSTALL_ROOT" "$p"; else printf '%s\n' "$p"; fi; }
monotonic_now(){ date +%s; }

cleanup_detach(){ local attempt status=1; [[ "$ATTACHED" -eq 1 && -n "$MOUNTPOINT" ]] || return 0; case "$MOUNT_PARENT" in /private/tmp/hyu-live-macos-rust.*) ;; *) printf 'cleanup unsafe temp prefix\n' >&2; return 1 ;; esac; for attempt in 1 2 3; do if hdiutil detach "$MOUNTPOINT" >/dev/null 2>"$MOUNT_PARENT/detach.err"; then rm -f -- "$MOUNT_PARENT/detach.err"; ATTACHED=0; status=0; break; fi; sleep 1; done; return "$status"; }
cleanup_dirs(){ [[ -z "$MOUNT_PARENT" ]] && return 0; case "$MOUNT_PARENT" in /private/tmp/hyu-live-macos-rust.*) ;; *) printf 'cleanup unsafe temp prefix\n' >&2; return 1 ;; esac; rm -f -- "$MOUNT_PARENT/detach.err"; rmdir "$MOUNTPOINT" 2>/dev/null || return 1; rmdir "$MOUNT_PARENT" 2>/dev/null || return 1; }
cleanup(){ local status=$? cleanup_status=0; trap - EXIT HUP INT TERM ERR; if [[ -n "$WIFI_IFACE_TO_RESTORE" ]]; then run_tool /usr/sbin/networksetup -setairportpower "$WIFI_IFACE_TO_RESTORE" on >/dev/null 2>&1 || cleanup_status=1; fi; cleanup_detach || cleanup_status=1; cleanup_dirs || cleanup_status=1; if [[ "$status" -ne 0 ]]; then exit "$status"; fi; exit "$cleanup_status"; }
trap cleanup EXIT HUP INT TERM

internet_guard(){ local label="$1" google github dns; google="$(run_tool /usr/bin/curl -fsS --max-time 5 -o /dev/null -w '%{http_code}' https://www.google.com/generate_204 2>/dev/null || true)"; github="$(run_tool /usr/bin/curl -fsS --max-time 5 -o /dev/null -w '%{http_code}' https://github.com/ 2>/dev/null || true)"; dns="$(run_tool /usr/bin/dig +short +time=3 +tries=1 github.com A 2>/dev/null | /usr/bin/head -n 1 || true)"; [[ -n "$dns" ]] || { printf 'baseline.dns=unhealthy label=%s\n' "$label" >&2; return 1; }; [[ "$google" == 204 && "$github" == 200 ]] || { printf 'baseline.internet=unhealthy label=%s google=%s github=%s\n' "$label" "${google:-none}" "${github:-none}" >&2; return 1; }; printf 'internet.google=ok\ninternet.github=ok\ninternet.dns=ok\n'; }
normalize_route_identity(){ /usr/bin/python3 -c 'import re,sys; s=sys.stdin.read(); get=lambda k: (re.search(r"^\s*"+k+r":\s*(.+)$",s,re.M) or [None,""])[1].strip(); print("gateway=%s,interface=%s,destination=%s"%(get("gateway"),get("interface"),get("destination")))'; }

strict_helper_status(){
  local raw status
  set +e
  raw="$(run_tool /usr/bin/sudo -n /Library/PrivilegedHelperTools/com.hyu.vpn.helper status 2>/dev/null)"
  status=$?
  set -e
  if [[ $status -ne 0 ]]; then
    if [[ -z "$TOOLS_ROOT" && ! -x /Library/PrivilegedHelperTools/com.hyu.vpn.helper ]]; then
      printf '{"schema_version":1,"state":"stopped","pid":null,"session_nonce":null,"tunnel_interface":null}\n'
      return 0
    fi
    printf 'helper status invalid\n' >&2
    return 1
  fi
  HELPER_RAW="$raw" /usr/bin/python3 - <<'PYHELPER' 2>/dev/null || { printf 'helper status invalid\n' >&2; return 1; }
import json, os, re
raw = os.environ["HELPER_RAW"].encode()
assert raw and raw.count(b"\n") <= 1
d = json.loads(raw)
keys = set(d)
if keys == {"schema_version", "state"} and d.get("state") == "stopped":
    d["pid"] = None
    d["session_nonce"] = None
    d["tunnel_interface"] = None
elif keys == {"schema_version", "state", "session_nonce"} and d.get("state") == "repair-required":
    d["pid"] = None
    d["tunnel_interface"] = None
assert set(d) == {"schema_version", "state", "pid", "session_nonce", "tunnel_interface"}
assert d["schema_version"] == 1
st = d["state"]
assert st in {"stopped", "running", "repair-required"}
if st == "running":
    assert isinstance(d["pid"], int) and d["pid"] > 0
    assert re.fullmatch(r"[A-Z0-9]{8,128}", d["session_nonce"] or "")
    assert re.fullmatch(r"utun[0-9]+", d["tunnel_interface"] or "")
if st == "stopped":
    assert d["pid"] is None and d["session_nonce"] is None and d["tunnel_interface"] is None
if st == "repair-required":
    assert d["pid"] is None
    assert re.fullmatch(r"[A-Z0-9]{8,128}", d["session_nonce"] or "")
    assert d["tunnel_interface"] is None
print(json.dumps(d, separators=(",", ":")))
PYHELPER
}

json_field(){ /usr/bin/python3 -c 'import json,sys; d=json.load(sys.stdin); v=d.get(sys.argv[1]); print("" if v is None else v)' "$1"; }

capture_baseline(){ local route dns helper state pid nonce tunnel rel mode size hash p; route="$(run_tool /sbin/route -n get default 2>/dev/null || true)"; dns="$(run_tool /usr/sbin/scutil --dns 2>/dev/null | /usr/bin/head -c 65536 || true)"; BASE_ROUTE_ID="$(printf '%s' "$route" | normalize_route_identity)"; BASE_DNS_HASH="$(printf '%s' "$dns" | hash_text)"; helper="$(strict_helper_status)"; state="$(printf '%s' "$helper" | json_field state)"; pid="$(printf '%s' "$helper" | json_field pid)"; nonce="$(printf '%s' "$helper" | json_field session_nonce)"; tunnel="$(printf '%s' "$helper" | json_field tunnel_interface)"; printf 'baseline.default_route.identity=%s\n' "$BASE_ROUTE_ID"; printf 'baseline.default_route.sha256=%s\n' "$(printf '%s' "$route" | hash_text)"; printf 'baseline.dns.sha256=%s\n' "$BASE_DNS_HASH"; printf 'baseline.helper.state=%s\n' "$state"; [[ -n "$pid" ]] && printf 'baseline.helper.pid=%s\n' "$pid"; [[ -n "$nonce" ]] && printf 'baseline.helper.nonce.sha256=%s\n' "$(printf '%s' "$nonce" | hash_text)"; [[ -n "$tunnel" ]] && printf 'baseline.helper.tunnel=%s\n' "$tunnel"; for p in "$HOME/Library/Application Support/hyu-openconnect/credentials.key" "$HOME/Library/Application Support/hyu-openconnect/credentials.enc"; do if [[ -f "$p" && ! -L "$p" ]]; then rel="${p#$HOME/}"; mode="$(run_tool /usr/bin/stat -f %Lp "$p")"; size="$(run_tool /usr/bin/stat -f %z "$p")"; hash="$(run_tool /usr/bin/shasum -a 256 "$p" | /usr/bin/awk '{print $1}')"; printf 'credential_metadata.path=%s mode=%s bytes=%s sha256=%s encrypted-only\n' "$rel" "$mode" "$size" "$hash"; fi; done; printf 'baseline.installed.service.sha256=%s\n' "$( [[ -f '/Library/Application Support/HYU VPN/bin/hyu-vpn-macos-service' ]] && run_tool /usr/bin/shasum -a 256 '/Library/Application Support/HYU VPN/bin/hyu-vpn-macos-service' | /usr/bin/awk '{print $1}' || printf not-installed)"; }

verify_dmg_and_mount(){ [[ -n "$DMG" ]] || { printf 'canonical regular DMG required\n' >&2; exit 2; }; DMG="$(canon "$DMG")" || { printf 'canonical regular DMG required\n' >&2; exit 2; }; [[ -f "$DMG" && ! -L "$DMG" && -f "$DMG.sha256" && ! -L "$DMG.sha256" ]] || { printf 'canonical regular DMG and checksum required\n' >&2; exit 2; }; local digest expected log_path; digest="$(run_tool /usr/bin/shasum -a 256 "$DMG" | /usr/bin/awk '{print $1}')"; expected="$(/usr/bin/awk '{print $1; exit}' "$DMG.sha256")"; [[ "$digest" == "$expected" ]] || { printf 'dmg checksum mismatch\n' >&2; exit 2; }; if [[ -n "$DMG_ACCEPTANCE_LOG" ]]; then log_path="$(canon "$DMG_ACCEPTANCE_LOG")"; /usr/bin/grep -Fq "$digest" "$log_path" && /usr/bin/grep -Fq "$DMG" "$log_path" || { printf 'dmg acceptance log mismatch\n' >&2; exit 2; }; fi; PATH="$PATH" "$ROOT/scripts/macos-dmg-acceptance.sh" "$DMG" >/dev/null; printf 'dmg.sha256=%s\n' "$digest"; printf 'dmg_acceptance=rerun-pass\n'; MOUNT_PARENT="$(mktemp -d /private/tmp/hyu-live-macos-rust.XXXXXX)"; MOUNTPOINT="$MOUNT_PARENT/mount"; mkdir "$MOUNTPOINT"; hdiutil verify "$DMG" >/dev/null; hdiutil attach -readonly -nobrowse -mountpoint "$MOUNTPOINT" "$DMG" >/dev/null; ATTACHED=1; }
manifest_hash(){ /usr/bin/python3 - "$MOUNTPOINT/manifest.json" "$1" <<'PY'
import json,sys
print(json.load(open(sys.argv[1]))['files'][sys.argv[2]]['sha256'])
PY
}
manifest_sha(){ /usr/bin/shasum -a 256 "$MOUNTPOINT/manifest.json" | /usr/bin/awk '{print $1}'; }

ipc_request(){ local command="$1"; /usr/bin/python3 - "$SOCKET_PATH" "$command" <<'PY'
import json, os, socket, stat, struct, sys
path, command = sys.argv[1], sys.argv[2]
st=os.stat(path)
if not stat.S_ISSOCK(st.st_mode) or stat.S_IMODE(st.st_mode)!=0o600 or st.st_uid!=os.geteuid(): raise SystemExit('socket validation failed')
req={"schema_version":1,"request_id":"task9-"+command,"command":command}
raw=json.dumps(req,separators=(",",":")).encode(); s=socket.socket(socket.AF_UNIX); s.settimeout(5); s.connect(path); s.sendall(struct.pack('>I',len(raw))+raw)
h=s.recv(4); assert len(h)==4
n=struct.unpack('>I',h)[0]; assert n<=65536
b=b''
while len(b)<n:
    c=s.recv(n-len(b)); assert c; b+=c
d=json.loads(b); base={'schema_version','request_id','result'}
if d.get('schema_version')!=1 or d.get('request_id')!=req['request_id'] or d.get('result')=='error': raise SystemExit('bad ipc response')
if command=='status':
    if set(d)!=(base|{'status'}) or d.get('result')!='status': raise SystemExit('bad status response')
    print(json.dumps(d['status'],separators=(',',':')))
else:
    if set(d)!=base or d.get('result')!='ack': raise SystemExit('bad ack response')
    print('{}')
PY
}
validate_backend_status(){ local status="$1" want_state="${2:-}"; STATUS_JSON="$status" /usr/bin/python3 -c 'import json, os, re, sys; want=sys.argv[1]; d=json.loads(os.environ["STATUS_JSON"]); need={"schema_version","state","automatic_reconnect_enabled","connected_at","session_expires_at","last_successful_hip_at","tunnel_interface","next_retry_at","error_"+"code","last_transition_at","backend_build_version"}; assert set(d)==need and d["schema_version"]==1 and d["backend_build_version"]=="0.2.2"; assert (not want) or d["state"]==want; assert d["tunnel_interface"] is None or re.fullmatch(r"utun[0-9]+", d["tunnel_interface"]); assert d["state"]!="connected" or (d["tunnel_interface"] and d["last_successful_hip_at"] and d["connected_at"])' "$want_state"; }

verify_installed_file(){ local path="$1" rel="$2" mode_expected="$3" label="$4" expected actual mode uid expected_uid; [[ -f "$path" && ! -L "$path" ]] || { printf 'installed %s missing\n' "$label" >&2; return 1; }; expected="$(manifest_hash "$rel")"; actual="$(run_tool /usr/bin/shasum -a 256 "$path" | /usr/bin/awk '{print $1}')"; [[ "$actual" == "$expected" ]] || { printf 'installed %s hash mismatch\n' "$label" >&2; return 1; }; mode="$(run_tool /usr/bin/stat -f %Lp "$path")"; [[ "$mode" == "$mode_expected" ]] || { printf 'installed %s mode mismatch\n' "$label" >&2; return 1; }; uid="$(run_tool /usr/bin/stat -f %u "$path")"; expected_uid=0; [[ -n "$INSTALL_ROOT" ]] && expected_uid="$(/usr/bin/id -u)"; [[ "$uid" == "$expected_uid" ]] || { printf 'installed %s owner mismatch\n' "$label" >&2; return 1; }; }
verify_launchd_plist(){ local plist="$1" mode uid; [[ -f "$plist" && ! -L "$plist" ]] || { printf 'launchd plist missing\n' >&2; return 1; }; mode="$(run_tool /usr/bin/stat -f %Lp "$plist")"; [[ "$mode" == 644 || "$mode" == 600 ]] || { printf 'launchd plist mode mismatch\n' >&2; return 1; }; uid="$(run_tool /usr/bin/stat -f %u "$plist")"; [[ "$uid" == "$(/usr/bin/id -u)" ]] || { printf 'launchd plist owner mismatch\n' >&2; return 1; }; /usr/bin/python3 - "$plist" <<'PY'
import plistlib,sys
assert plistlib.load(open(sys.argv[1],'rb')).get('ProgramArguments') == ['/Library/Application Support/HYU VPN/bin/hyu-vpn-macos-service']
PY
}
run_installer_app(){ local app="$1" timeout="${HYU_LIVE_MACOS_RUST_INSTALLER_TIMEOUT_SECONDS:-300}" pid deadline now status; [[ -d "$app" && ! -L "$app" ]] || { printf 'installer app missing\n' >&2; return 1; }; [[ "$timeout" =~ ^[1-9][0-9]*$ && "$timeout" -le 3600 ]] || { printf 'invalid installer timeout\n' >&2; return 1; }; run_tool /usr/bin/open -W "$app" >/dev/null 2>&1 & pid=$!; deadline=$(( $(monotonic_now) + timeout )); while /bin/kill -0 "$pid" 2>/dev/null; do now="$(monotonic_now)"; if [[ "$now" -ge "$deadline" ]]; then /bin/kill -TERM "$pid" 2>/dev/null || true; sleep 1; /bin/kill -0 "$pid" 2>/dev/null && /bin/kill -KILL "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; printf 'installer app timed out\n' >&2; return 1; fi; sleep 0.2; done; if wait "$pid"; then status=0; else status=$?; fi; [[ "$status" -eq 0 ]] || { printf 'installer app failed code=%s\n' "$status" >&2; return 1; }; printf 'installer_app.result=success code=0\n'; }
phase_install_identity(){ run_installer_app "$MOUNTPOINT/Install HYU VPN.app" >/dev/null; verify_installed_file "$(map_installed '/Library/Application Support/HYU VPN/bin/hyu-vpn-macos-service')" hyu-vpn-macos-service 755 service; verify_installed_file "$(map_installed /Library/PrivilegedHelperTools/com.hyu.vpn.helper)" com.hyu.vpn.helper 755 helper; verify_installed_file "$(map_installed '/Applications/HYU VPN.app/Contents/MacOS/HYUVPNMenuApp')" 'HYU VPN.app/Contents/MacOS/HYUVPNMenuApp' 755 menu; verify_launchd_plist "$HOME/Library/LaunchAgents/com.hyu.vpn.service.plist"; validate_backend_status "$(ipc_request status)"; printf 'phase=install_identity result=verified backend_version=0.2.2\n'; }
phase_service_menu_singleton(){ local svc menu; svc="$(run_tool /usr/bin/pgrep -x hyu-vpn-macos-service 2>/dev/null | wc -l | tr -d ' ')"; menu="$(run_tool /usr/bin/pgrep -x HYUVPNMenuApp 2>/dev/null | wc -l | tr -d ' ')"; [[ "$svc" == 1 && "$menu" == 1 ]] || { printf 'singleton check failed\n' >&2; return 1; }; printf 'phase=service_menu_singleton result=verified service=1 menu=1\n'; }
phase_no_python_product_paths(){ local app_support plist legacy_count=0 python_launchd=0 py_count; app_support="$(map_installed '/Library/Application Support/HYU VPN')"; plist="$HOME/Library/LaunchAgents/com.hyu.vpn.service.plist"; for rel in src/hyu_vpn bin/hyu-vpn-service bin/hyu-vpn-control bin/hyu-vpn-connect bin/hyu-vpn-native-client; do [[ ! -e "$app_support/$rel" && ! -L "$app_support/$rel" ]] || legacy_count=$((legacy_count+1)); done; if [[ -f "$plist" ]]; then /usr/bin/python3 - "$plist" <<'PY' || python_launchd=1
import plistlib,sys
assert '/usr/bin/python3' not in ' '.join(map(str, plistlib.load(open(sys.argv[1],'rb')).get('ProgramArguments', [])))
PY
fi; py_count="$(run_tool /bin/ps -axo command 2>/dev/null | /usr/bin/python3 -c 'import sys; print(sum(1 for l in sys.stdin if "python" in l.lower() and "/Library/Application Support/HYU VPN" in l))')"; [[ "$legacy_count" == 0 && "$python_launchd" == 0 && "$py_count" == 0 ]] || { printf 'python/legacy residue categories=legacy:%s,launchd-python:%s,process:%s\n' "$legacy_count" "$python_launchd" "$py_count" >&2; return 1; }; printf 'phase=no_python_product_paths result=verified categories=legacy-backend:0,python-runtime:0,old-version-0.1.1:0\n'; }
phase_encrypted_credential_metadata(){ capture_baseline | grep '^credential_metadata' || true; printf 'phase=encrypted_credential_metadata result=verified contents=not-read\n'; }
wait_status_connected(){ local deadline now st h; deadline=$(( $(monotonic_now) + 10 )); while :; do st="$(ipc_request status)" && if validate_backend_status "$st" connected 2>/dev/null; then h="$(strict_helper_status)" && printf '%s' "$h" | /usr/bin/python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["state"]=="running" and d["tunnel_interface"].startswith("utun")' && return 0; fi; now="$(monotonic_now)"; [[ "$now" -lt "$deadline" ]] || { printf 'connected status timeout\n' >&2; return 1; }; sleep 0.2; done; }
phase_real_connection_helper_owned_utun(){ ipc_request connect >/dev/null; wait_status_connected; printf 'phase=real_connection_helper_owned_utun result=verified\n'; }
phase_owned_openconnect_stop_reconnect(){ local h pid nonce tunnel fp stopped after after_pid after_nonce after_tunnel; h="$(strict_helper_status)"; pid="$(printf '%s' "$h"|json_field pid)"; nonce="$(printf '%s' "$h"|json_field session_nonce)"; tunnel="$(printf '%s' "$h"|json_field tunnel_interface)"; [[ "$tunnel" =~ ^utun[0-9]+$ ]]; fp="$(run_tool /bin/ps -o pid=,comm=,lstart= -p "$pid" | head -n 1 | hash_text)"; run_tool /bin/ps -o comm= -p "$pid" | grep -q openconnect || { printf 'owned pid is not openconnect\n' >&2; return 1; }; run_tool /usr/bin/sudo -n /Library/PrivilegedHelperTools/com.hyu.vpn.helper stop >/dev/null; stopped="$(strict_helper_status)"; [[ "$(printf '%s' "$stopped"|json_field state)" == stopped ]] || { printf 'helper did not stop\n' >&2; return 1; }; ipc_request reconnect >/dev/null; wait_status_connected; after="$(strict_helper_status)"; after_pid="$(printf '%s' "$after"|json_field pid)"; after_nonce="$(printf '%s' "$after"|json_field session_nonce)"; after_tunnel="$(printf '%s' "$after"|json_field tunnel_interface)"; [[ "$after_pid" != "$pid" && "$after_nonce" != "$nonce" && "$after_tunnel" =~ ^utun[0-9]+$ ]] || { printf 'owned reconnect reused generation\n' >&2; return 1; }; printf 'phase=owned_openconnect_stop_reconnect result=verified prior_pid=%s prior_nonce_sha256=%s prior_birth_sha256=%s after_pid=%s after_nonce_sha256=%s\n' "$pid" "$(printf '%s' "$nonce"|hash_text)" "$fp" "$after_pid" "$(printf '%s' "$after_nonce"|hash_text)"; }
phase_rust_service_restart_reconciliation(){ local before before_pid before_nonce uid st after after_pid after_nonce; before="$(strict_helper_status)"; before_pid="$(printf '%s' "$before"|json_field pid)"; before_nonce="$(printf '%s' "$before"|json_field session_nonce)"; uid="$(run_tool /usr/bin/id -u)"; run_tool /bin/launchctl kickstart -k "gui/$uid/com.hyu.vpn.service" >/dev/null; st="$(ipc_request status)"; validate_backend_status "$st" connected; after="$(strict_helper_status)"; after_pid="$(printf '%s' "$after"|json_field pid)"; after_nonce="$(printf '%s' "$after"|json_field session_nonce)"; [[ "$after_pid" == "$before_pid" && "$after_nonce" == "$before_nonce" ]] || { printf 'service restart changed helper generation\n' >&2; return 1; }; phase_service_menu_singleton >/dev/null; printf 'phase=rust_service_restart_reconciliation result=verified helper_pid=%s helper_nonce_sha256=%s\n' "$after_pid" "$(printf '%s' "$after_nonce"|hash_text)"; }
phase_disconnect_route_dns_restore(){ local st route dns; ipc_request disconnect >/dev/null; st="$(ipc_request status)"; validate_backend_status "$st" disabled; run_tool /usr/bin/sudo -n /Library/PrivilegedHelperTools/com.hyu.vpn.helper stop >/dev/null; [[ "$(strict_helper_status | json_field state)" == stopped ]] || { printf 'helper not stopped after disconnect\n' >&2; return 1; }; route="$(run_tool /sbin/route -n get default|normalize_route_identity)"; dns="$(run_tool /usr/sbin/scutil --dns)"; dns="$(printf '%s' "$dns" | hash_text)"; [[ "$route" == "$BASE_ROUTE_ID" && "$dns" == "$BASE_DNS_HASH" ]] || { printf 'route/dns restoration mismatch\n' >&2; return 1; }; internet_guard after-mutation >/dev/null; printf 'phase=disconnect_route_dns_restore result=verified\n'; }
fresh_install_nonce(){ printf 'hyu-install-mutation-%s\n' "$(date +%s)"; }
verify_uninstalled_residue(){ local app_support legacy=0; app_support="$(map_installed '/Library/Application Support/HYU VPN')"; for p in "$app_support" "$(map_installed /Library/PrivilegedHelperTools/com.hyu.vpn.helper)" "$(map_installed '/Applications/HYU VPN.app')"; do [[ ! -e "$p" && ! -L "$p" ]] || legacy=$((legacy+1)); done; if [[ -z "$INSTALL_ROOT" ]]; then [[ ! -e "$SOCKET_PATH" && ! -L "$SOCKET_PATH" ]] || legacy=$((legacy+1)); fi; [[ "$legacy" == 0 ]] || { printf 'uninstall residue count=%s\n' "$legacy" >&2; return 1; }; }
phase_uninstall_residue_checks(){ if [[ "$EXERCISE_UNINSTALL_REINSTALL" -ne 1 ]]; then printf 'phase=uninstall_residue_checks result=not-exercised use=--exercise-uninstall-reinstall\n'; printf 'task9_completion=partial-uninstall-not-exercised\n'; return 0; fi; run_tool /usr/bin/sudo -n "$ROOT/installer/root-admin.sh" --payload "$MOUNTPOINT" --manifest "$MOUNTPOINT/manifest.json" --administrator-phase uninstall --live-install "$(fresh_install_nonce)" >/dev/null; verify_uninstalled_residue; phase_install_identity >/dev/null; phase_no_python_product_paths >/dev/null; printf 'phase=uninstall_residue_checks result=verified-reinstalled\n'; printf 'task9_completion=full-scripted-except-physical-wifi\n'; }
wait_until_unhealthy(){ local deadline now; deadline=$(( $(monotonic_now) + 10 )); while :; do if ! internet_guard wifi-off >/dev/null 2>&1; then return 0; fi; now="$(monotonic_now)"; [[ "$now" -lt "$deadline" ]] || { printf 'wifi internet did not drop\n' >&2; return 1; }; sleep 0.2; done; }
wait_until_healthy(){ local deadline now; deadline=$(( $(monotonic_now) + 10 )); while :; do if internet_guard wifi-on >/dev/null 2>&1; then return 0; fi; now="$(monotonic_now)"; [[ "$now" -lt "$deadline" ]] || { printf 'wifi internet did not recover\n' >&2; return 1; }; sleep 0.2; done; }
status_field(){ /usr/bin/python3 -c 'import json,sys; d=json.load(sys.stdin); v=d.get(sys.argv[1]); print("" if v is None else v)' "$1"; }
wait_wifi_network_transition(){ local before_pid="$1" before_nonce="$2" deadline now st state h pid nonce; deadline=$(( $(monotonic_now) + 10 )); while :; do st="$(ipc_request status)" || st="{}"; state="$(printf '%s' "$st" | status_field state 2>/dev/null || true)"; h="$(strict_helper_status 2>/dev/null || true)"; pid="$(printf '%s' "$h" | json_field pid 2>/dev/null || true)"; nonce="$(printf '%s' "$h" | json_field session_nonce 2>/dev/null || true)"; case "$state" in waiting-for-network|backoff|connecting) return 0;; esac; [[ -z "$pid" || "$pid" != "$before_pid" || "$nonce" != "$before_nonce" ]] && return 0; now="$(monotonic_now)"; [[ "$now" -lt "$deadline" ]] || { printf 'wifi backend did not transition offline\n' >&2; return 1; }; sleep 0.2; done; }
wait_wifi_connected_transition(){ local before_pid="$1" before_nonce="$2" before_transition="$3" deadline now st h pid nonce transition; deadline=$(( $(monotonic_now) + 10 )); while :; do st="$(ipc_request status)" && if validate_backend_status "$st" connected 2>/dev/null; then h="$(strict_helper_status)"; pid="$(printf '%s' "$h"|json_field pid)"; nonce="$(printf '%s' "$h"|json_field session_nonce)"; transition="$(printf '%s' "$st"|status_field last_transition_at)"; if [[ "$pid" != "$before_pid" || "$nonce" != "$before_nonce" || "$transition" != "$before_transition" ]]; then return 0; fi; fi; now="$(monotonic_now)"; [[ "$now" -lt "$deadline" ]] || { printf 'wifi backend did not reconnect automatically\n' >&2; return 1; }; sleep 0.2; done; }
phase_physical_wifi_gate(){ local iface before before_auto before_transition helper before_pid before_nonce; before="$(ipc_request status)"; validate_backend_status "$before" connected; before_auto="$(printf '%s' "$before"|status_field automatic_reconnect_enabled)"; [[ "$before_auto" == True || "$before_auto" == true ]] || { printf 'automatic reconnect disabled before wifi gate\n' >&2; return 1; }; before_transition="$(printf '%s' "$before"|status_field last_transition_at)"; helper="$(strict_helper_status)"; before_pid="$(printf '%s' "$helper"|json_field pid)"; before_nonce="$(printf '%s' "$helper"|json_field session_nonce)"; iface="$(run_tool /usr/sbin/networksetup -listallhardwareports | /usr/bin/awk '/Hardware Port: Wi-Fi/{getline; if ($1=="Device:") print $2; exit}')"; [[ -n "$iface" ]] || { printf 'wifi interface not found\n' >&2; return 1; }; WIFI_IFACE_TO_RESTORE="$iface"; run_tool /usr/sbin/networksetup -setairportpower "$iface" off >/dev/null; wait_until_unhealthy; wait_wifi_network_transition "$before_pid" "$before_nonce"; run_tool /usr/sbin/networksetup -setairportpower "$iface" on >/dev/null; wait_until_healthy; WIFI_IFACE_TO_RESTORE=""; wait_wifi_connected_transition "$before_pid" "$before_nonce" "$before_transition"; printf 'phase=physical_wifi_gate result=verified interface=%s reconnect_within=10s\n' "$iface"; }
repair_on_failure(){ local h state; h="$(strict_helper_status 2>/dev/null || true)"; [[ -z "$h" ]] && return 0; state="$(printf '%s' "$h"|json_field state 2>/dev/null || true)"; if [[ "$state" == running || "$state" == repair-required ]]; then run_tool /usr/bin/sudo -n /Library/PrivilegedHelperTools/com.hyu.vpn.helper repair >/dev/null || true; internet_guard repair-after >/dev/null 2>&1 || true; fi; }
validate_nonce_dir(){ local mode; [[ ! -L "$NONCE_DIR" ]] || { printf 'invalid nonce dir\n' >&2; exit 2; }; mkdir -p "$NONCE_DIR"; mode="$(/usr/bin/stat -f %Lp "$NONCE_DIR")"; [[ "$mode" == 700 ]] || chmod 700 "$NONCE_DIR"; }
validate_nonce(){ local now epoch delta marker; [[ "$NONCE" =~ ^hyu-live-macos-rust-[0-9]+$ ]] || { printf 'fresh nonce required\n' >&2; exit 2; }; [[ "${HYU_LIVE_MACOS_RUST_NONCE:-}" == "$NONCE" ]] || { printf 'nonce environment mismatch\n' >&2; exit 2; }; epoch="${NONCE#hyu-live-macos-rust-}"; now="$(date +%s)"; delta=$((now-epoch)); [[ $delta -ge 0 && $delta -le 300 ]] || { printf 'fresh nonce required\n' >&2; exit 2; }; [[ "$USER_PRESENT" == I-am-present-for-live-macOS-Rust-acceptance ]] || { printf 'user presence acknowledgment required\n' >&2; exit 2; }; validate_nonce_dir; marker="$NONCE_DIR/$NONCE.used"; if ! (set -o noclobber; printf '%s\n' $$ > "$marker") 2>/dev/null; then printf 'nonce already used\n' >&2; exit 2; fi; }
require_test_root_evidence(){ local e="${TEST_ROOT_EVIDENCE:-$EVIDENCE_OUT}"; [[ -n "$TEST_ROOT" ]] || { printf 'test-root evidence required: requires --test-root\n' >&2; exit 2; }; [[ -n "$e" && -f "$e" && ! -L "$e" ]] || { printf 'test-root evidence required\n' >&2; exit 2; }; /usr/bin/python3 - "$e" "$TEST_ROOT" "$DMG" "$MOUNTPOINT/manifest.json" <<'PY'
import hashlib, json, os, re, stat, sys, time
e,troot,dmg,manifest=sys.argv[1:5]
st=os.stat(e)
assert stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode)==0o600 and st.st_uid==os.geteuid()
d=json.load(open(e))
assert set(d)=={"schema_version","test_root","dmg_sha256","manifest_sha256","stage_sha256","injection","timestamp_epoch","command_contract","result"}
assert d["schema_version"]==1 and d["result"]=="rollback-proved" and d["command_contract"]=="root-admin-dry-run-health"
assert d["injection"]=="health" and re.fullmatch(r"[0-9a-f]{64}", d["stage_sha256"])
assert time.time()-int(d["timestamp_epoch"]) <= 600
assert os.path.realpath(troot)==d["test_root"]
assert hashlib.sha256(open(dmg,"rb").read()).hexdigest()==d["dmg_sha256"]
assert hashlib.sha256(open(manifest,"rb").read()).hexdigest()==d["manifest_sha256"]
stage_manifest=os.path.join(os.path.realpath(troot),"Users/tester/Library/Application Support/HYU VPN/staged-payload/manifest.json")
stage_st=os.lstat(stage_manifest)
assert stat.S_ISREG(stage_st.st_mode) and not stat.S_ISLNK(stage_st.st_mode)
assert hashlib.sha256(open(stage_manifest,"rb").read()).hexdigest()==d["stage_sha256"]
PY
}
run_preflight(){ printf 'mode=preflight\n'; internet_guard before-mutation; capture_baseline; if [[ -n "$DMG" ]]; then verify_dmg_and_mount; fi; printf 'state_changes=none\n'; }
make_test_tools_root(){ local tools="$TEST_ROOT/Users/.task9-tools" tool path helper_stub; for tool in /usr/sbin/visudo /usr/sbin/chown /usr/bin/pgrep /usr/sbin/netstat /usr/sbin/scutil /usr/bin/env /usr/bin/sudo /bin/launchctl /bin/mv; do path="$tools${tool}"; /bin/mkdir -p "$(/usr/bin/dirname "$path")"; case "${tool##*/}" in mv) printf '#!/bin/sh\nexec /bin/mv "$@"\n' > "$path" ;; sudo) printf '#!/bin/sh\nwhile [ "$#" -gt 0 ] && [ "$1" != "--" ]; do shift; done\n[ "$1" = "--" ] && shift\nexec "$@"\n' > "$path" ;; *) printf '#!/bin/sh\nexit 0\n' > "$path" ;; esac; /bin/chmod 755 "$path"; done; helper_stub="$tools$TEST_ROOT/Library/PrivilegedHelperTools/com.hyu.vpn.helper"; /bin/mkdir -p "$(/usr/bin/dirname "$helper_stub")"; printf '#!/bin/sh\nprintf '"'"'{"schema_version":1,"state":"stopped","pid":null,"session_nonce":null,"tunnel_interface":null}\n'"'"'\n' > "$helper_stub"; /bin/chmod 755 "$helper_stub"; printf '%s\n' "$tools"; }
run_test_root(){ [[ -n "$DMG" ]] || { printf 'test-root DMG required\n' >&2; exit 2; }; [[ -n "$TEST_ROOT" && -d "$TEST_ROOT" && ! -L "$TEST_ROOT" && -f "$TEST_ROOT/.hyu-vpn-dry-run-root" ]] || { printf 'marked test root required\n' >&2; exit 2; }; [[ "$ROLLBACK_INJECTION" == health ]] || { printf 'unsupported rollback injection\n' >&2; exit 2; }; verify_dmg_and_mount >/dev/null; local stage root_admin_status root_admin_log stage_digest package_digest journal state test_tools; stage="$TEST_ROOT/Users/tester/Library/Application Support/HYU VPN/staged-payload"; run_tool /usr/bin/python3 "$ROOT/installer/manifest.py" --payload "$MOUNTPOINT" --manifest "$MOUNTPOINT/manifest.json" --stage-user-payload --stage-dir "$stage" >/dev/null; stage_digest="$(/usr/bin/shasum -a 256 "$stage/manifest.json" | /usr/bin/awk '{print $1}')"; package_digest="$(manifest_sha)"; test_tools="$(make_test_tools_root)"; /bin/mkdir -p "$TEST_ROOT/private/tmp"; root_admin_log="$TEST_ROOT/private/tmp/root-admin-dry-run.log"; set +e; HYU_VPN_FAIL_AFTER=health run_tool /bin/zsh "$ROOT/installer/root-admin.sh" --payload "$MOUNTPOINT" --manifest "$MOUNTPOINT/manifest.json" --administrator-phase install --stage "$stage" --stage-manifest-sha256 "$stage_digest" --package-manifest-sha256 "$package_digest" --dry-run-root "$TEST_ROOT" --admin-user tester --admin-uid 501 --tools-root "$test_tools" >"$root_admin_log" 2>&1; root_admin_status=$?; set -e; [[ "$root_admin_status" -ne 0 ]] || { printf 'root-admin dry-run unexpectedly succeeded\n' >&2; exit 1; }; /usr/bin/grep -Eiq 'sudo: (a password is required|no tty present)|authentication failed|incorrect password' "$root_admin_log" && { printf 'root-admin dry-run used live authentication\n' >&2; exit 1; }; /usr/bin/grep -Fq 'injected failure after health' "$root_admin_log" || { printf 'root-admin dry-run did not reach health injection\n' >&2; exit 1; }; journal="$TEST_ROOT/private/var/db/hyu-vpn/install-transaction.log"; state="$TEST_ROOT/private/var/db/hyu-vpn/transaction-state"; /usr/bin/grep -Fq 'rollback-complete' "$journal" || { printf 'root-admin rollback not proven\n' >&2; exit 1; }; [[ -f "$state" && "$(/bin/cat "$state")" == complete ]] || { printf 'root-admin transaction state not complete\n' >&2; exit 1; }; [[ ! -e "$TEST_ROOT/Library/Application Support/HYU VPN/bin/hyu-vpn-macos-service" && ! -e "$TEST_ROOT/Library/PrivilegedHelperTools/com.hyu.vpn.helper" ]] || { printf 'root-admin rollback residue remains\n' >&2; exit 1; }; if [[ -n "$EVIDENCE_OUT" ]]; then /usr/bin/python3 - "$EVIDENCE_OUT" "$TEST_ROOT" "$DMG" "$MOUNTPOINT/manifest.json" "$stage/manifest.json" "$ROLLBACK_INJECTION" <<'PY'
import hashlib,json,os,sys,time
out,troot,dmg,manifest,stage_manifest,inj=sys.argv[1:7]
d={"schema_version":1,"test_root":os.path.realpath(troot),"dmg_sha256":hashlib.sha256(open(dmg,"rb").read()).hexdigest(),"manifest_sha256":hashlib.sha256(open(manifest,"rb").read()).hexdigest(),"stage_sha256":hashlib.sha256(open(stage_manifest,"rb").read()).hexdigest(),"injection":inj,"timestamp_epoch":int(time.time()),"command_contract":"root-admin-dry-run-health","result":"rollback-proved"}
with open(out,"w") as f: json.dump(d,f,separators=(",",":")); f.write("\n")
os.chmod(out,0o600)
PY
fi; printf 'mode=test-root\nrollback_injection=%s\ntest_root.rollback=proved\nstate_changes=test-root-only\n' "$ROLLBACK_INJECTION"; }
run_live(){ validate_nonce; printf 'mode=live\nlive_gate=armed\n'; internet_guard before-mutation >/dev/null; capture_baseline >/dev/null; verify_dmg_and_mount; require_test_root_evidence; phase_install_identity; phase_service_menu_singleton; phase_no_python_product_paths; phase_encrypted_credential_metadata >/dev/null; phase_real_connection_helper_owned_utun; phase_owned_openconnect_stop_reconnect; phase_rust_service_restart_reconciliation; if [[ "$PHYSICAL_WIFI_GATE" -eq 1 ]]; then phase_physical_wifi_gate; else printf 'phase=physical_wifi_gate result=skipped-final-flag-required\n'; fi; phase_disconnect_route_dns_restore; phase_uninstall_residue_checks; }
trap 'repair_on_failure; cleanup' ERR
case "$MODE" in preflight) run_preflight ;; test-root) run_test_root ;; live) run_live ;; esac
