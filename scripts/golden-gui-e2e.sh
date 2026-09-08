#!/usr/bin/env bash
set -Eeuo pipefail

# Thin, synthetic manager-journey proof. The underlying runner starts and
# removes only its own loopback server and browser profile; it never calls AWS.
export SECCOP_GOLDEN_GUI=1
exec "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/browser-e2e.sh"
