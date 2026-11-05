#!/usr/bin/env bash
# S10: behaviours the generated compose file relies on.
#  A. A named cache volume mounted under a bind-mounted workspace (e.g. /workspace/node_modules):
#     is it writable by the non-root user, and what does it take to make it so?
#  B. Does Docker leave a placeholder for that mountpoint in the HOST repository, and who owns it?
#  C. A tmpfs mounted over a directory inside a read-only bind mount (hiding the gateway state).
source "$(dirname "$0")/lib.sh"

WS="$(mktemp -d)"; defer "rm -rf $WS"
chmod 777 "$WS"
mkdir -p "$WS/.kennel/state"; echo "secret-policy" >"$WS/.kennel/state/policy.json"; echo cfg >"$WS/.kennel/config.yaml"
chmod -R a+rX "$WS/.kennel"

# Image with the cache directory pre-created and owned by uid 1000, and one without.
CTX="$(mktemp -d)"; defer "rm -rf $CTX"
cat >"$CTX/Dockerfile" <<'DF'
FROM busybox:1.36
RUN mkdir -p /workspace/node_modules /workspace && chown 1000:1000 /workspace/node_modules
USER 1000:1000
DF
cat >"$CTX/Dockerfile.bare" <<'DF'
FROM busybox:1.36
RUN mkdir -p /workspace
USER 1000:1000
DF
docker build -q -t "${RUN_ID}-pre" -f "$CTX/Dockerfile" "$CTX" >/dev/null && defer "docker rmi -f ${RUN_ID}-pre"
docker build -q -t "${RUN_ID}-bare" -f "$CTX/Dockerfile.bare" "$CTX" >/dev/null && defer "docker rmi -f ${RUN_ID}-bare"

echo "== A. named volume under a bind mount"
V1="${RUN_ID}-v1"; V2="${RUN_ID}-v2"
defer "docker volume rm -f $V1 $V2"
expect_ok   "image dir pre-created + chowned: user can write the fresh volume" \
  docker run --rm --mount type=bind,src="$WS",dst=/workspace --mount type=volume,src="$V1",dst=/workspace/node_modules "${RUN_ID}-pre" sh -c 'echo ok >/workspace/node_modules/f'
expect_fail "image dir NOT pre-created: user cannot write the fresh volume (documents why the Dockerfile must)" \
  docker run --rm --mount type=bind,src="$WS",dst=/workspace --mount type=volume,src="$V2",dst=/workspace/cachedir "${RUN_ID}-bare" sh -c 'echo no >/workspace/cachedir/f'
expect_ok   "volume content persists across containers" \
  docker run --rm --mount type=volume,src="$V1",dst=/v "${RUN_ID}-pre" sh -c 'test -f /v/f'

echo "== B. host placeholder"
ls -ldn "$WS"/node_modules "$WS"/cachedir 2>&1 | sed 's/^/   /'
if [ -d "$WS/node_modules" ]; then
  owner="$(stat -c %u "$WS/node_modules")"
  result INFO "docker created host dir node_modules in the bind-mounted repo (owner uid $owner)"
  [ "$owner" = 0 ] && result INFO "   -> root-owned: a host-side 'npm install' would fail; prepare must pre-create such dirs as the user"
else
  result INFO "no host placeholder was created"
fi
# Pre-created by the user: nothing new, ownership unchanged.
mkdir "$WS/preexisting"; chown 1234:1234 "$WS/preexisting" 2>/dev/null || true
before="$(stat -c %u "$WS/preexisting")"
docker run --rm --mount type=bind,src="$WS",dst=/workspace --mount type=volume,src="${RUN_ID}-v3",dst=/workspace/preexisting "${RUN_ID}-pre" true 2>/dev/null; defer "docker volume rm -f ${RUN_ID}-v3"
after="$(stat -c %u "$WS/preexisting")"
[ "$before" = "$after" ] && result PASS "a pre-existing host directory keeps its owner when a volume is mounted over it" || result FAIL "owner changed $before -> $after"

echo "== C. tmpfs over a path inside a read-only bind mount"
C="${RUN_ID}-c"
docker run -d --name "$C" --user 1000:1000 \
  --mount type=bind,src="$WS",dst=/workspace \
  --mount type=bind,src="$WS/.kennel",dst=/workspace/.kennel,readonly \
  --mount type=tmpfs,dst=/workspace/.kennel/state,tmpfs-mode=0555,tmpfs-size=4096 \
  busybox:1.36 sleep 60 >/dev/null && defer "docker rm -f $C"
sleep 1
expect_ok   "control: agent can read the committed config through the ro mount" docker exec "$C" cat /workspace/.kennel/config.yaml
expect_fail "agent cannot see the state file (hidden by tmpfs)"                  docker exec "$C" cat /workspace/.kennel/state/policy.json
expect_ok   "the state directory exists but is empty" docker exec "$C" sh -c '[ -d /workspace/.kennel/state ] && [ -z "$(ls -A /workspace/.kennel/state)" ]'
expect_fail "agent cannot write other files into .kennel (ro)"                 docker exec "$C" sh -c 'echo x >/workspace/.kennel/evil'
# kennel sets the tmpfs mode explicitly (0555, one page) because the engine default differs:
# root-owned 0755 on Docker Engine 29.6, world-writable on Docker Desktop 4.92. With the explicit
# mode the non-root agent cannot write scratch files there on either.
expect_fail "agent cannot write into the hiding tmpfs either"                    docker exec "$C" sh -c 'echo x >/workspace/.kennel/state/scratch'
[ ! -e "$WS/.kennel/state/scratch" ] && result PASS "nothing reaches the host state directory" || result FAIL "write leaked to the host"
[ "$(cat "$WS/.kennel/state/policy.json")" = "secret-policy" ] && result PASS "host state file untouched" || result FAIL "host state file changed"
summary
