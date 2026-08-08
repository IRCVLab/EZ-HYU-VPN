#!/usr/bin/env bash
set -euo pipefail

SOURCE_DIR=${1:?usage: test-openconnect-windows-hip.sh OPENCONNECT_SOURCE_DIR}
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$SOURCE_DIR"
WORK=$(mktemp -d)
SERVER_PID=
cleanup() {
    if [[ -n "$SERVER_PID" ]]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

FAKE_SERVER="$ROOT/scripts/fake-gp-hip-server.py"

cat > "$WORK/hip-wrapper.c" <<'C'
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    int cookie_stdin = 0, md5 = 0, address = 0, client_os = 0;
    char cookie[8194];
    int i;
    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--cookie") || strstr(argv[i], "user="))
            return 25;
        if (!strcmp(argv[i], "--cookie-on-stdin"))
            cookie_stdin = 1;
        else if (i + 1 < argc && !strcmp(argv[i], "--md5") && strlen(argv[i + 1]) == 32)
            md5 = 1;
        else if (i + 1 < argc && (!strcmp(argv[i], "--client-ip") || !strcmp(argv[i], "--client-ipv6")) && argv[i + 1][0])
            address = 1;
        else if (i + 1 < argc && !strcmp(argv[i], "--client-os") && !strcmp(argv[i + 1], "Windows"))
            client_os = 1;
    }
    if (!fgets(cookie, sizeof(cookie), stdin) || !strstr(cookie, "user="))
        return 26;
    if (!(cookie_stdin && md5 && address && client_os))
        return 23;
    fputs("<hip-report><generated-by>hyu-openconnect-win32-e2e</generated-by></hip-report>", stdout);
    return fflush(stdout) == 0 ? 0 : 24;
}
C

mkdir -p "$WORK/HYU VPN HIP"
WRAPPER="$WORK/HYU VPN HIP/hyu hip test.exe"
x86_64-w64-mingw32-gcc -O2 -Wall -Wextra -Werror "$WORK/hip-wrapper.c" -o "$WRAPPER"
WRAPPER_WIN=$(winepath -w "$WRAPPER")
MARKER="$WORK/hip-submitted.xml"
export HYU_HIP_MARKER="$MARKER"
python3 "$FAKE_SERVER" 127.0.0.1 18443 tests/certs/server-cert.pem tests/certs/server-key.pem >"$WORK/server.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 100); do
    if curl --silent --show-error --insecure --fail https://127.0.0.1:18443/CONFIGURE >/dev/null 2>&1; then
        break
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        cat "$WORK/server.log" >&2
        exit 1
    fi
    sleep 0.1
done
curl --silent --show-error --insecure --fail https://127.0.0.1:18443/CONFIGURE >/dev/null

set +e
printf 'test\n' | WINEDEBUG=-all wine64 ./openconnect.exe \
    --verbose --protocol=gp --os=win --no-dtls --user=test \
    --servercert=pin-sha256:xp3scfzy3rO \
    "--csd-wrapper=$WRAPPER_WIN" \
    https://127.0.0.1:18443/gateway >"$WORK/openconnect.log" 2>&1
OPENCONNECT_STATUS=$?
set -e
if [[ ! -s "$MARKER" ]]; then
    cat "$WORK/openconnect.log" >&2
    cat "$WORK/server.log" >&2
    echo "HIP report was not submitted (OpenConnect status $OPENCONNECT_STATUS)" >&2
    exit 1
fi
grep -F 'hyu-openconnect-win32-e2e' "$MARKER" >/dev/null
grep -F 'HIP report submitted successfully' "$WORK/openconnect.log" >/dev/null
printf 'Windows HIP end-to-end test passed (expected tunnel rejection status: %d)\n' "$OPENCONNECT_STATUS"
