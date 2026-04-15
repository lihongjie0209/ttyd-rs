#!/bin/sh
# Parse TTYD_ARGS env var and prepend to CMD args.
set -e

if [ -n "$TTYD_ARGS" ]; then
    eval exec ttyd $TTYD_ARGS '"$@"'
else
    exec ttyd "$@"
fi