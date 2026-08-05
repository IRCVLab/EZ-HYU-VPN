#!/bin/bash
# Reversible foreground acceptance test for the HYU OpenConnect replacement.

set -u

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CONNECTOR=${HYU_ACCEPTANCE_CONNECTOR:-"$ROOT/bin/hyu-vpn-connect"}
PROTECTED_ENDPOINT=166.104.100.100
PROTECTED_PORT=53
LAUNCH_LABEL=local.hyu-openconnect
MUTATION_AUDIT=${HYU_ACCEPTANCE_MUTATION_AUDIT:-}
# shellcheck source=tests/live_acceptance_gate.sh
source "$ROOT/tests/live_acceptance_gate.sh"

MODE=dry-run
STATE_DIR=
CONNECT_PID=
OWNED_OPENCONNECT_PID=
OWNED_OPENCONNECT_PGID=
NATIVE_WAS_CONNECTED=0
NATIVE_STOPPED=0
CLEANUP_RUNNING=0

record_mutation() {
    action=$1
    if [ -n "$MUTATION_AUDIT" ]; then
        /usr/bin/printf '%s\n' "$action" >> "$MUTATION_AUDIT"
    fi
}

native_process_present() {
    /bin/ps -axo comm= 2>/dev/null \
        | /usr/bin/awk -F/ '$NF == "GlobalProtect" || $NF == "PanGPS" {found=1} END {exit !found}'
}

protected_route_interface() {
    /sbin/route -n get "$PROTECTED_ENDPOINT" 2>/dev/null \
        | /usr/bin/awk '/^[[:space:]]*interface:/ {print $2; exit}'
}

native_connection_active() {
    native_process_present || return 1
    route_interface=$(protected_route_interface)
    case "$route_interface" in
        utun*) return 0 ;;
        *) return 1 ;;
    esac
}

native_ui_connected() {
    record_mutation native-status-read
    status=$(/usr/bin/osascript <<'APPLESCRIPT'
tell application "System Events"
    if not (exists process "GlobalProtect") then return "unavailable"
    tell process "GlobalProtect"
        if (count of windows) is 0 then click menu bar item 1 of menu bar 2
        repeat 40 times
            if (count of windows) > 0 then exit repeat
            delay 0.1
        end repeat
        if (count of windows) is 0 then return "unavailable"
        if (exists button "Disconnect" of window 1) then return "connected"
        return "disconnected"
    end tell
end tell
APPLESCRIPT
    ) || return 1
    [ "$status" = connected ]
}

native_connection_confirmed() {
    native_process_present || return 1
    native_ui_connected || return 1
    route_interface=$(protected_route_interface)
    case "$route_interface" in
        utun*) return 0 ;;
        *) return 1 ;;
    esac
}

launch_agent_state() {
    if /bin/launchctl print "gui/$(/usr/bin/id -u)/$LAUNCH_LABEL" >/dev/null 2>&1; then
        echo loaded
    else
        echo disabled
    fi
}

print_preconditions() {
    echo "mode=dry-run"
    echo "state_changes=none"
    echo "connector=not-read-dry-run"
    echo "dependencies=not-read-dry-run"
    echo "launch_agent=not-read-dry-run"
    echo "native_connection=not-read-dry-run"
    echo "execute_hint=run-with---execute---acknowledge-live-mutation-after-offline-suite"
}

snapshot_state() {
    label=$1
    destination="$STATE_DIR/$label"
    /bin/mkdir -m 700 "$destination" || return 1
    /bin/ps -axo pid=,comm= > "$destination/processes.txt" 2>/dev/null || return 1
    /sbin/route -n get "$PROTECTED_ENDPOINT" > "$destination/protected-route.txt" 2>&1 || true
    /usr/sbin/scutil --dns > "$destination/dns.txt" 2>&1 || return 1
    /bin/launchctl print "gui/$(/usr/bin/id -u)/$LAUNCH_LABEL" > "$destination/launch-agent.txt" 2>&1 || true
    /bin/chmod -R go-rwx "$destination"
}

click_native_button() {
    button_name=$1
    record_mutation "native-$button_name"
    /usr/bin/osascript - "$button_name" <<'APPLESCRIPT'
on run argv
    set requestedButton to item 1 of argv
    tell application "System Events"
        if not (exists process "GlobalProtect") then error "GlobalProtect UI process is unavailable"
        tell process "GlobalProtect"
            if (count of windows) is 0 then click menu bar item 1 of menu bar 2
            repeat 40 times
                if (count of windows) > 0 then exit repeat
                delay 0.1
            end repeat
            if (count of windows) is 0 then error "GlobalProtect status window did not open"
            if not (exists button requestedButton of window 1) then error "requested GlobalProtect action is unavailable"
            click button requestedButton of window 1
        end tell
    end tell
end run
APPLESCRIPT
}

wait_for_native_state() {
    expected=$1
    timeout=$2
    elapsed=0
    while [ "$elapsed" -lt "$timeout" ]; do
        if native_connection_confirmed; then
            actual=connected
        else
            actual=disconnected
        fi
        if [ "$actual" = "$expected" ]; then
            return 0
        fi
        /bin/sleep 1
        elapsed=$((elapsed + 1))
    done
    return 1
}

disconnect_native_gracefully() {
    click_native_button Disconnect || return 1
    # A successful click followed by a verification timeout must still restore.
    NATIVE_STOPPED=1
    wait_for_native_state disconnected 45 || return 1
}

restore_native_if_needed() {
    if [ "$NATIVE_WAS_CONNECTED" -ne 1 ]; then
        return 0
    fi
    if native_connection_confirmed; then
        NATIVE_STOPPED=0
        return 0
    fi
    click_native_button Connect || return 1
    wait_for_native_state connected 120 || return 1
    NATIVE_STOPPED=0
}

start_connector() {
    log_file="$STATE_DIR/openconnect.log"
    : > "$log_file"
    /bin/chmod 600 "$log_file"
    record_mutation connector-start
    "$CONNECTOR" > "$log_file" 2>&1 &
    CONNECT_PID=$!
    capture_owned_openconnect_group 10 || {
        echo "connector_start=child-not-traceable" >&2
        return 1
    }
}

capture_owned_openconnect_group() {
    timeout=$1
    elapsed=0
    process_file="$STATE_DIR/connector-processes.txt"
    while [ "$elapsed" -lt "$timeout" ]; do
        /bin/ps -axo pid=,ppid=,pgid=,comm= > "$process_file" 2>/dev/null || return 1
        child_group=$(/usr/bin/awk -v parent="$CONNECT_PID" '
            $2 == parent {
                comm=$4; sub(/^.*\//, "", comm)
                if (comm == "sudo" || comm == "openconnect") {print $3; exit}
            }
        ' "$process_file")
        if [ -n "$child_group" ]; then
            child_pid=$(/usr/bin/awk -v group="$child_group" '
                $3 == group {
                    comm=$4; sub(/^.*\//, "", comm)
                    if (comm == "openconnect") {print $1; exit}
                }
            ' "$process_file")
            if [ -n "$child_pid" ]; then
                OWNED_OPENCONNECT_PGID=$child_group
                OWNED_OPENCONNECT_PID=$child_pid
                return 0
            fi
        fi
        connector_alive || return 1
        /bin/sleep 1
        elapsed=$((elapsed + 1))
    done
    return 1
}

owned_openconnect_group_present() {
    [ -n "$OWNED_OPENCONNECT_PID" ] || return 1
    [ -n "$OWNED_OPENCONNECT_PGID" ] || return 1
    process_line=$(/bin/ps -p "$OWNED_OPENCONNECT_PID" -o pgid=,comm= 2>/dev/null) || return 1
    process_group=$(/usr/bin/awk '{print $1}' <<EOF
$process_line
EOF
    )
    process_command=$(/usr/bin/awk '{print $2}' <<EOF
$process_line
EOF
    )
    process_command=${process_command##*/}
    [ "$process_group" = "$OWNED_OPENCONNECT_PGID" ] && [ "$process_command" = openconnect ]
}

signal_owned_openconnect_group() {
    signal_name=$1
    owned_openconnect_group_present || return 0
    record_mutation "openconnect-group-$signal_name"
    /bin/kill -"$signal_name" -- "-$OWNED_OPENCONNECT_PGID" 2>/dev/null || return 1
}

wait_for_owned_openconnect_exit() {
    timeout=$1
    elapsed=0
    while owned_openconnect_group_present && [ "$elapsed" -lt "$timeout" ]; do
        /bin/sleep 1
        elapsed=$((elapsed + 1))
    done
    ! owned_openconnect_group_present
}

stop_connector() {
    if [ -z "$CONNECT_PID" ]; then
        return 0
    fi
    if /bin/kill -0 "$CONNECT_PID" 2>/dev/null; then
        record_mutation connector-stop
        /bin/kill -TERM "$CONNECT_PID" 2>/dev/null || true
        waited=0
        while /bin/kill -0 "$CONNECT_PID" 2>/dev/null && [ "$waited" -lt 20 ]; do
            /bin/sleep 1
            waited=$((waited + 1))
        done
        if /bin/kill -0 "$CONNECT_PID" 2>/dev/null; then
            signal_owned_openconnect_group TERM || true
            wait_for_owned_openconnect_exit 10 || true
            waited=0
            while /bin/kill -0 "$CONNECT_PID" 2>/dev/null && [ "$waited" -lt 10 ]; do
                /bin/sleep 1
                waited=$((waited + 1))
            done
        fi
    fi
    if owned_openconnect_group_present; then
        signal_owned_openconnect_group TERM || true
        wait_for_owned_openconnect_exit 10 || true
    fi
    if owned_openconnect_group_present; then
        signal_owned_openconnect_group HUP || true
        wait_for_owned_openconnect_exit 10 || true
    fi
    if /bin/kill -0 "$CONNECT_PID" 2>/dev/null || owned_openconnect_group_present; then
        echo "connector_stop=timed-out" >&2
        return 1
    fi
    wait "$CONNECT_PID" 2>/dev/null || true
    CONNECT_PID=
    OWNED_OPENCONNECT_PID=
    OWNED_OPENCONNECT_PGID=
}

no_new_openconnect_process() {
    baseline="$STATE_DIR/before/openconnect-pids.txt"
    current="$STATE_DIR/current-openconnect-pids.txt"
    /usr/bin/awk '{comm=$2; sub(/^.*\//, "", comm); if (comm == "openconnect") print $1}' \
        "$STATE_DIR/before/processes.txt" > "$baseline"
    /bin/ps -axo pid=,comm= 2>/dev/null \
        | /usr/bin/awk '{comm=$2; sub(/^.*\//, "", comm); if (comm == "openconnect") print $1}' \
        > "$current"
    while IFS= read -r pid; do
        [ -z "$pid" ] && continue
        /usr/bin/grep -Fxq "$pid" "$baseline" || return 1
    done < "$current"
    return 0
}

connector_alive() {
    [ -n "$CONNECT_PID" ] && /bin/kill -0 "$CONNECT_PID" 2>/dev/null
}

tunnel_interface() {
    interface=$(protected_route_interface)
    case "$interface" in
        utun*) echo "$interface" ;;
        *) return 1 ;;
    esac
}

tunnel_address_present() {
    interface=$(tunnel_interface) || return 1
    /sbin/ifconfig "$interface" 2>/dev/null \
        | /usr/bin/awk '/^[[:space:]]*inet 10\.200\.200\./ {found=1} END {exit !found}'
}

protected_endpoint_reachable() {
    /usr/bin/nc -z -G 3 "$PROTECTED_ENDPOINT" "$PROTECTED_PORT" >/dev/null 2>&1
}

dns_usable() {
    /usr/bin/dscacheutil -q host -a name secure.hanyang.ac.kr 2>/dev/null \
        | /usr/bin/grep -q '^ip_address:'
}

log_is_secret_safe() {
    inspected_log=${1:-"$STATE_DIR/openconnect.log"}
    # Prompt labels such as "Password:" are expected and contain no secret.
    # The server also reports explicit `*-authcookie=empty` status fields.
    # Reject only non-empty assignments and never print their values.
    /usr/bin/python3 - "$inspected_log" <<'PY'
import re
import sys
from pathlib import Path

try:
    text = Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
except OSError:
    raise SystemExit(1)

assignment = re.compile(
    r"(?i)(?:^|[^A-Za-z0-9_-])"
    r"(?P<key>[A-Za-z0-9_-]*(?:authcookie|cookie)|password|totp|host-id|interface[- ]mac)"
    r"\s*=\s*(?P<value>[^\s&<]*)"
)
empty_values = {"", "empty", "none", "null", "(null)", "<empty>"}
for match in assignment.finditer(text):
    value = match.group("value").strip().lower()
    if value not in empty_values:
        raise SystemExit(1)
raise SystemExit(0)
PY
}

wait_for_live_acceptance() {
    elapsed=0
    while [ "$elapsed" -lt 150 ]; do
        connector_alive || return 1
        if /usr/bin/grep -Fq 'HIP report submitted successfully' "$STATE_DIR/openconnect.log" \
            && tunnel_address_present \
            && protected_endpoint_reachable \
            && dns_usable; then
            return 0
        fi
        /bin/sleep 1
        elapsed=$((elapsed + 1))
    done
    return 1
}

normalized_route_identity() {
    route_file=$1
    /usr/bin/awk -v endpoint="$PROTECTED_ENDPOINT" '
        /^[[:space:]]*destination:/ {destination=$2}
        /^[[:space:]]*gateway:/ {gateway=$2}
        /^[[:space:]]*interface:/ {interface=$2}
        /^[[:space:]]*flags:/ {flags=$0}
        END {
            if (destination == endpoint && flags ~ /WASCLONED/) { destination = "default" }
            printf "%s|%s|%s\n", destination, gateway, interface
        }
    ' "$route_file"
}

route_matches_snapshot() {
    current="$STATE_DIR/current-route.txt"
    /sbin/route -n get "$PROTECTED_ENDPOINT" > "$current" 2>&1 || true
    [ "$(normalized_route_identity "$STATE_DIR/native-disconnected/protected-route.txt")" = "$(normalized_route_identity "$current")" ]
}

dns_matches_snapshot() {
    current="$STATE_DIR/current-dns.txt"
    /usr/sbin/scutil --dns > "$current" 2>&1 || return 1
    /usr/bin/cmp -s "$STATE_DIR/native-disconnected/dns.txt" "$current"
}

cleanup() {
    original_status=${1:-$?}
    if [ "$CLEANUP_RUNNING" -eq 1 ]; then
        return
    fi
    CLEANUP_RUNNING=1
    trap - EXIT
    trap '' INT TERM
    connector_safe=1
    if ! stop_connector; then
        connector_safe=0
        original_status=1
    fi
    if [ -n "$STATE_DIR" ] && [ -d "$STATE_DIR/before" ] && ! no_new_openconnect_process; then
        connector_safe=0
        original_status=1
        echo "cleanup_openconnect=still-running" >&2
    fi
    if [ "$NATIVE_STOPPED" -eq 1 ] && [ "$connector_safe" -eq 1 ]; then
        if restore_native_if_needed; then
            echo "rollback_native=restored" >&2
        else
            echo "rollback_native=failed" >&2
            original_status=1
        fi
    elif [ "$NATIVE_STOPPED" -eq 1 ]; then
        echo "rollback_native=blocked-until-openconnect-stops" >&2
    fi
    if [ -n "$STATE_DIR" ] && [ -d "$STATE_DIR" ]; then
        record_mutation state-snapshot-remove
        /bin/rm -rf "$STATE_DIR"
    fi
    exit "$original_status"
}

run_execute() {
    if [ ! -x "$CONNECTOR" ]; then
        echo "precondition_failed=connector-missing" >&2
        return 1
    fi
    if [ ! -x /opt/homebrew/bin/openconnect ] || [ ! -x /opt/homebrew/bin/oathtool ]; then
        echo "precondition_failed=dependency-missing" >&2
        return 1
    fi
    if [ "$(launch_agent_state)" != disabled ]; then
        echo "precondition_failed=launch-agent-must-be-disabled" >&2
        return 1
    fi
    if ! native_connection_confirmed; then
        echo "precondition_failed=native-rollback-session-required" >&2
        return 1
    fi

    NATIVE_WAS_CONNECTED=1
    STATE_DIR=$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/hyu-live-acceptance.XXXXXX") || return 1
    /bin/chmod 700 "$STATE_DIR"
    record_mutation state-snapshot-create
    trap 'cleanup $?' EXIT
    trap 'cleanup 130' INT
    trap 'cleanup 143' TERM
    snapshot_state before || return 1

    echo "phase=native-disconnect"
    disconnect_native_gracefully || {
        echo "result=failed-native-disconnect" >&2
        return 1
    }
    snapshot_state native-disconnected || return 1

    echo "phase=openconnect-foreground"
    start_connector || return 1
    if ! wait_for_live_acceptance; then
        echo "result=failed-live-acceptance" >&2
        return 1
    fi
    if ! log_is_secret_safe; then
        echo "result=failed-log-privacy" >&2
        return 1
    fi
    echo "hip_submission=accepted"
    echo "tunnel_route=installed"
    echo "protected_endpoint=reachable"
    echo "dns=usable"
    echo "log_privacy=passed"

    echo "phase=openconnect-teardown"
    if ! stop_connector; then
        echo "result=failed-connector-stop" >&2
        return 1
    fi
    if ! no_new_openconnect_process; then
        echo "result=failed-openconnect-orphan" >&2
        return 1
    fi
    /bin/sleep 2
    if ! route_matches_snapshot; then
        echo "result=failed-route-cleanup" >&2
        return 1
    fi
    if ! dns_matches_snapshot; then
        echo "result=failed-dns-cleanup" >&2
        return 1
    fi
    echo "teardown_routes=restored"
    echo "teardown_dns=restored"

    if ! restore_native_if_needed; then
        echo "result=failed-native-restore" >&2
        return 1
    fi
    if ! native_connection_confirmed; then
        echo "result=failed-native-restore-verification" >&2
        return 1
    fi
    echo "rollback_native=restored"
    echo "result=success"

    trap - EXIT
    trap '' INT TERM
    record_mutation state-snapshot-remove
    /bin/rm -rf "$STATE_DIR"
    STATE_DIR=
    return 0
}

parse_live_acceptance_args "$@" || exit $?
MODE=$LIVE_ACCEPTANCE_MODE

if [ "$MODE" = check-log ]; then
    if log_is_secret_safe "$LIVE_ACCEPTANCE_CHECK_LOG"; then
        echo "log_privacy=passed"
        exit 0
    fi
    echo "log_privacy=failed"
    exit 1
fi

if [ "$MODE" = dry-run ]; then
    print_preconditions
    exit 0
fi

require_live_mutation_ack "$(/bin/date +%s)" || exit $?
echo "mode=execute"
run_execute
