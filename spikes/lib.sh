#!/usr/bin/env bash
# Shared helpers for spike scripts. Throwaway code: results are recorded in docs/spikes.md.
set -uo pipefail

IMAGE="${SPIKE_IMAGE:-busybox:1.36}"
RUN_ID="cwspike$$"
PASS=0
FAIL=0

result() { # result <PASS|FAIL|INFO> <message>
  case "$1" in
    PASS) PASS=$((PASS + 1)) ;;
    FAIL) FAIL=$((FAIL + 1)) ;;
  esac
  printf '%-5s %s\n' "$1" "$2"
}

# expect_ok <desc> <cmd...>: passes when the command exits 0.
expect_ok() {
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then result PASS "$desc"; else result FAIL "$desc"; fi
}

# expect_fail <desc> <cmd...>: passes when the command exits non-zero.
expect_fail() {
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then result FAIL "$desc"; else result PASS "$desc"; fi
}

cleanup_list=()
on_exit() {
  # Reverse order: containers must go before the networks they are attached to.
  local i
  for ((i = ${#cleanup_list[@]} - 1; i >= 0; i--)); do
    [ -n "${cleanup_list[$i]}" ] && eval "${cleanup_list[$i]}" >/dev/null 2>&1
  done
}
trap on_exit EXIT
defer() { cleanup_list+=("$1"); }

summary() {
  echo "---- ${PASS} passed, ${FAIL} failed"
  [ "$FAIL" -eq 0 ]
}
