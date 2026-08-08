# shellcheck shell=bash
# shellcheck disable=SC2034
# Side-effect-free argument parser and live mutation gate for live_acceptance.sh.

live_acceptance_usage() {
    echo "usage: $0 [--dry-run|--execute --acknowledge-live-mutation NONCE|--check-log FILE]" >&2
}

parse_live_acceptance_args() {
    LIVE_ACCEPTANCE_MODE=dry-run
    LIVE_MUTATION_ACK_NONCE=
    LIVE_ACCEPTANCE_CHECK_LOG=
    mode_seen=0
    ack_seen=0

    while [ "$#" -gt 0 ]; do
        case "$1" in
            --dry-run)
                if [ "$mode_seen" -ne 0 ]; then
                    live_acceptance_usage
                    return 2
                fi
                LIVE_ACCEPTANCE_MODE=dry-run
                mode_seen=1
                shift
                ;;
            --execute)
                if [ "$mode_seen" -ne 0 ]; then
                    live_acceptance_usage
                    return 2
                fi
                LIVE_ACCEPTANCE_MODE=execute
                mode_seen=1
                shift
                ;;
            --acknowledge-live-mutation)
                if [ "$ack_seen" -ne 0 ] || [ "$#" -lt 2 ]; then
                    live_acceptance_usage
                    return 2
                fi
                LIVE_MUTATION_ACK_NONCE=$2
                ack_seen=1
                shift 2
                ;;
            --check-log)
                if [ "$mode_seen" -ne 0 ] || [ "$#" -ne 2 ]; then
                    live_acceptance_usage
                    return 2
                fi
                LIVE_ACCEPTANCE_MODE=check-log
                LIVE_ACCEPTANCE_CHECK_LOG=$2
                mode_seen=1
                shift 2
                ;;
            *)
                live_acceptance_usage
                return 2
                ;;
        esac
    done

    if [ "$LIVE_ACCEPTANCE_MODE" != execute ] && [ -n "$LIVE_MUTATION_ACK_NONCE" ]; then
        live_acceptance_usage
        return 2
    fi
    return 0
}

require_live_mutation_ack() {
    now_epoch=$1
    if [ -z "$LIVE_MUTATION_ACK_NONCE" ]; then
        echo "precondition_failed=live-mutation-ack-required" >&2
        return 2
    fi
    if [ "${HYU_VPN_ALLOW_LIVE_MUTATION:-}" != "$LIVE_MUTATION_ACK_NONCE" ]; then
        echo "precondition_failed=live-mutation-env-nonce-mismatch" >&2
        return 2
    fi
    case "$LIVE_MUTATION_ACK_NONCE" in
        hyu-live-mutation-[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]*) ;;
        *)
            echo "precondition_failed=live-mutation-nonce-format" >&2
            return 2
            ;;
    esac
    nonce_epoch=${LIVE_MUTATION_ACK_NONCE#hyu-live-mutation-}
    case "$nonce_epoch" in
        ""|*[!0-9]*)
            echo "precondition_failed=live-mutation-nonce-format" >&2
            return 2
            ;;
    esac
    case "$now_epoch" in
        ""|*[!0-9]*)
            echo "precondition_failed=live-mutation-now-format" >&2
            return 2
            ;;
    esac
    age=$((now_epoch - nonce_epoch))
    if [ "$age" -lt 0 ] || [ "$age" -gt 300 ]; then
        echo "precondition_failed=live-mutation-nonce-not-fresh" >&2
        return 2
    fi
    return 0
}
