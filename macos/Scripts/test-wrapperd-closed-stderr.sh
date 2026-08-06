#!/bin/sh
set -eu

package_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd -P)
binary=${1:-}
if [ -z "$binary" ]; then
    (cd "$package_root" && swift build --product hyu-vpnc-wrapperd >/dev/null)
    binary=$(cd "$package_root" && swift build --show-bin-path)/hyu-vpnc-wrapperd
fi

if [ ! -x "$binary" ]; then
    printf 'missing wrapperd executable: %s\n' "$binary" >&2
    exit 66
fi

set +e
normal_output=$("$binary" 2>&1 >/dev/null)
normal_status=$?
"$binary" >/dev/null 2>&-
closed_stderr_status=$?
set -e

if [ "$normal_status" -ne 70 ]; then
    printf 'expected normal failure status 70, got %s\n' "$normal_status" >&2
    exit 1
fi
case "$normal_output" in
    hyu-vpnc-wrapperd:*) ;;
    *)
        printf 'missing normal wrapperd diagnostic\n' >&2
        exit 1
        ;;
esac
if [ "$closed_stderr_status" -ne 70 ]; then
    printf 'expected closed-stderr failure status 70, got %s\n' "$closed_stderr_status" >&2
    exit 1
fi

printf 'PASS wrapperd closed stderr exits 70\n'
