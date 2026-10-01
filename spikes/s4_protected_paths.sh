#!/usr/bin/env bash
# S4 (Linux part): nested read-only bind mounts over a writable workspace bind mount.
# macOS (VirtioFS) and Windows (WSL2) halves must be run on those hosts: see docs/spikes.md.
source "$(dirname "$0")/lib.sh"

WS="$(mktemp -d)"; defer "rm -rf $WS"
reset_fixture() {
  rm -rf "$WS"/.[!.]* "$WS"/* 2>/dev/null
  mkdir -p "$WS/.git/hooks" "$WS/.devcontainer" "$WS/.cellwall" "$WS/src"
  echo '#!/bin/sh' >"$WS/.git/hooks/pre-commit"; echo ref >"$WS/.git/HEAD"
  echo '{}' >"$WS/.mcp.json"; echo ok >"$WS/src/a.txt"
  chmod -R a+rwX "$WS"
}

run_variant() { # run_variant <label> <extra mount args...>
local label="$1"; shift
echo "######## variant: $label"
reset_fixture
C="${RUN_ID}-agent-$label"
docker run -d --name "$C" --user 1000:1000 \
  --mount type=bind,src="$WS",dst=/workspace \
  "$@" \
  --mount type=bind,src="$WS/.git/hooks",dst=/workspace/.git/hooks,readonly \
  --mount type=bind,src="$WS/.devcontainer",dst=/workspace/.devcontainer,readonly \
  --mount type=bind,src="$WS/.cellwall",dst=/workspace/.cellwall,readonly \
  --mount type=bind,src="$WS/.mcp.json",dst=/workspace/.mcp.json,readonly \
  "$IMAGE" sleep 300 >/dev/null && defer "docker rm -f $C"
x() { docker exec "$C" sh -c "$1"; }

expect_ok   "control: agent can write src/"                         x 'echo x >/workspace/src/b.txt'
expect_ok   "control: agent can write .git/config-adjacent files"   x 'echo x >/workspace/.git/HEAD'
expect_fail "ro: cannot create file in .git/hooks"                  x 'echo x >/workspace/.git/hooks/post-commit'
expect_fail "ro: cannot modify existing hook"                       x 'echo x >>/workspace/.git/hooks/pre-commit'
expect_fail "ro: cannot delete existing hook"                       x 'rm /workspace/.git/hooks/pre-commit'
expect_fail "ro: cannot create file in .devcontainer"               x 'echo x >/workspace/.devcontainer/devcontainer.json'
expect_fail "ro: cannot create file in .cellwall"                   x 'echo x >/workspace/.cellwall/policy.yaml'
expect_fail "ro: cannot modify file-level mount .mcp.json"          x 'echo x >/workspace/.mcp.json'
expect_fail "ro: cannot rm .mcp.json"                               x 'rm -f /workspace/.mcp.json'
expect_fail "evasion: cannot rename .git/hooks away (mountpoint busy)" x 'mv /workspace/.git/hooks /workspace/.git/hooks.old'
expect_fail "evasion: cannot rename .devcontainer away"             x 'mv /workspace/.devcontainer /workspace/dc'
expect_fail "evasion: cannot rename .mcp.json over via mv"          x 'echo evil >/workspace/mcp.new && mv /workspace/mcp.new /workspace/.mcp.json'
expect_fail "evasion: cannot remount (no CAP_SYS_ADMIN)"            x 'mount -o remount,rw /workspace/.git/hooks'
expect_fail "evasion: cannot umount"                                x 'umount /workspace/.git/hooks'

if [ "$label" = plain ]; then
  # Documents the hole: a ro submount does NOT stop its parent directory being renamed.
  expect_ok "DEMO (hole): without pinning, .git can be renamed away and replaced" x 'mv /workspace/.git /workspace/.git.old'
else
  expect_fail "evasion: cannot rename .git away when .git is itself a mountpoint" x 'mv /workspace/.git /workspace/.git.old'
fi
}

run_variant plain
run_variant parent-pinned --mount type=bind,src="$WS/.git",dst=/workspace/.git

# Missing protected path: what does docker do when the source doesn't exist yet?
echo "== missing source handling"
if docker run --rm --mount type=bind,src="$WS/.vscode-missing.json",dst=/workspace/x,readonly "$IMAGE" true 2>/tmp/${RUN_ID}.err; then
  result INFO "--mount with missing src: accepted"
else
  result PASS "--mount with missing src is rejected (no host-side creation): $(head -c 120 /tmp/${RUN_ID}.err)"
fi
docker run --rm -v "$WS/.vscode-v-missing:/workspace/y:ro" "$IMAGE" true >/dev/null 2>&1
[ -e "$WS/.vscode-v-missing" ] && result INFO "-v with missing src CREATED '$WS/.vscode-v-missing' on the host (type: $(stat -c %F "$WS/.vscode-v-missing"))" \
                              || result INFO "-v with missing src did not create host path"

# Missing target inside a rw bind: mounting a ro empty file at a path that does not exist in the workspace.
EMPTY="$(mktemp)"; defer "rm -f $EMPTY"
docker run --rm --mount type=bind,src="$WS",dst=/workspace \
  --mount type=bind,src="$EMPTY",dst=/workspace/.claude-settings.json,readonly "$IMAGE" true >/dev/null 2>&1
[ -e "$WS/.claude-settings.json" ] && result INFO "ro mount at non-existent target created an empty mountpoint file in the HOST workspace" \
                                   || result INFO "ro mount at non-existent target left host workspace untouched"
summary
