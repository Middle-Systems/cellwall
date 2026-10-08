#!/bin/sh
# Offline checks for scripts/install.sh: argument handling and the refusal paths.
set -eu
here=$(dirname "$0")
fail() { echo "FAIL: $*" >&2; exit 1; }

out=$(sh "$here/install.sh" --bogus 2>&1) && fail "unknown option accepted"
echo "$out" | grep -q "unknown option" || fail "no message for unknown option"

out=$(sh "$here/install.sh" --version 1.2.3 2>&1) && fail "version without v accepted"
echo "$out" | grep -q "must look like v1.2.3" || fail "no message for bad version: $out"

echo ok
