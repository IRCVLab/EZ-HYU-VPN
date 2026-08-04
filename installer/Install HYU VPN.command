#!/bin/zsh
set -euo pipefail
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
exec "$SCRIPT_DIR/install.sh" "$@"
