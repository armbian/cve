#!/usr/bin/env bash
# Run from anywhere: ./fasttrack.sh <command> [args]
cd "$(dirname "$(readlink -f "$0")")" && exec python3 -m fasttrack.cli "$@"
