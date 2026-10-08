#!/usr/bin/env bash
# Shared helpers for spike scripts. Throwaway code: results are recorded in docs/spikes.md.
set -uo pipefail

# Git Bash (MSYS) rewrites POSIX-looking arguments (-v /www:/www, /bin/sh) into Windows paths
# before docker sees them. Harmless elsewhere; required for the spikes to mean anything there.
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'

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

# expect_ok <desc> <cmd...>: passes when the command exits 0. On failure the command's
# output is printed so a CI log explains itself.
expect_ok() {
  local desc="$1"; shift
  local out rc
  out="$("$@" 2>&1)"; rc=$?
  if [ "$rc" -eq 0 ]; then
    result PASS "$desc"
  else
    result FAIL "$desc (exit $rc)"
    printf '%s\n' "$out" | head -15 | sed 's/^/        | /'
  fi
}

# expect_fail <desc> <cmd...>: passes when the command exits non-zero.
# Exit 126/127 means the tool itself is missing or not executable, which would make every
# "must fail" check pass vacuously, so that is reported as a test failure, never a pass.
expect_fail() {
  local desc="$1"; shift
  local out rc
  out="$("$@" 2>&1)"; rc=$?
  case "$rc" in
    0)       result FAIL "$desc (command succeeded)" ;;
    126|127) result FAIL "$desc (VACUOUS: command not runnable, exit $rc)"
             printf '%s\n' "$out" | head -5 | sed 's/^/        | /' ;;
    *)       result PASS "$desc" ;;
  esac
}

# retry <attempts> <cmd...>: run until success, 1s apart. For eventually-consistent things only
# (e.g. DNS registration), never for security assertions that must fail.
retry() {
  local n="$1"; shift
  local i
  for ((i = 1; i <= n; i++)); do
    "$@" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
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
