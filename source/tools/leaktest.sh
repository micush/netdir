#!/bin/sh
# The leak test: record what every driver returns while its tests run, then check that nothing of it gets through the strict
# privacy level to an MCP caller (addresses, MAC addresses, e-mail addresses, AS numbers, serial numbers, secrets).
# Run it after changing a driver or the masking:   sh tools/leaktest.sh      (from the source directory)
set -e
cd "$(dirname "$0")/.."
f=$(mktemp /tmp/netdir-leak.XXXXXX)
trap 'rm -f "$f"' EXIT
NETDIR_LEAKCAPTURE="$f" go test -count=1 ./device
NETDIR_LEAKFILE="$f" go test -count=1 -v -run 'TestLeakEveryDriver|TestLeakAdversarialForms' . | grep -E '^(---|===|ok|FAIL|PASS|\s+leak_test)' || true
NETDIR_LEAKFILE="$f" go test -count=1 -run 'TestLeakEveryDriver|TestLeakAdversarialForms' .
