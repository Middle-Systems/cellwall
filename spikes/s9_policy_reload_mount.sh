#!/usr/bin/env bash
# S9: hot reload depends on the gateway seeing policy updates. Editors and the cellwall CLI replace
# files atomically (write temp + rename), which swaps the inode. A single-file bind mount keeps
# pointing at the OLD inode; a directory bind mount sees the new file. Verify, then design around it.
source "$(dirname "$0")/lib.sh"

D="$(mktemp -d)"; defer "rm -rf $D"
echo v1 >"$D/policy.json"
chmod -R a+rX "$D"

C_FILE="${RUN_ID}-file"; C_DIR="${RUN_ID}-dir"
docker run -d --name "$C_FILE" --mount type=bind,src="$D/policy.json",dst=/etc/policy.json,readonly "$IMAGE" sleep 120 >/dev/null && defer "docker rm -f $C_FILE"
docker run -d --name "$C_DIR"  --mount type=bind,src="$D",dst=/etc/policy,readonly "$IMAGE" sleep 120 >/dev/null && defer "docker rm -f $C_DIR"

atomic_replace() { echo "$1" >"$D/policy.json.tmp" && chmod a+r "$D/policy.json.tmp" && mv "$D/policy.json.tmp" "$D/policy.json"; }
atomic_replace v2
sleep 1
file_view="$(docker exec "$C_FILE" cat /etc/policy.json)"
dir_view="$(docker exec "$C_DIR" cat /etc/policy/policy.json)"
echo "after atomic replace: file-mount sees '$file_view', dir-mount sees '$dir_view'"

[ "$dir_view" = v2 ] && result PASS "directory mount sees atomically replaced file" || result FAIL "directory mount did not see update (got '$dir_view')"
if [ "$file_view" = v1 ]; then
  result PASS "(documents the hazard) single-file mount is STALE after atomic replace"
else
  result INFO "single-file mount saw the update on this engine (got '$file_view'): hazard not reproduced here"
fi

# In-place write (same inode) is seen by both: shows why the hazard is easy to miss in a casual test.
echo v3 >"$D/policy.json"
sleep 1
expect_ok "in-place write is visible through the directory mount" sh -c "[ \"\$(docker exec $C_DIR cat /etc/policy/policy.json)\" = v3 ]"
summary
