#!/usr/bin/env bash
# S1: a container attached only to the sandbox network has no route to external IPs or the
# host, and can still reach a sibling by name. The sandbox network is the chosen topology
# (ADR 0001): internal + gateway_mode_ipv4=isolated. s1b shows why `internal` alone is not enough.
source "$(dirname "$0")/lib.sh"

SANDBOX="${RUN_ID}-sandbox"
EGRESS="${RUN_ID}-egress"
docker network create --internal -o com.docker.network.bridge.gateway_mode_ipv4=isolated "$SANDBOX" >/dev/null && defer "docker network rm $SANDBOX"
docker network create "$EGRESS" >/dev/null && defer "docker network rm $EGRESS"

# Sibling "gateway" on both networks, agent on sandbox only.
docker run -d --name "${RUN_ID}-gateway" --network "$SANDBOX" --network-alias gateway "$IMAGE" \
  sh -c 'nc -lk -p 3128 -e echo pong' >/dev/null && defer "docker rm -f ${RUN_ID}-gateway"
docker network connect "$EGRESS" "${RUN_ID}-gateway"
docker run -d --name "${RUN_ID}-agent" --network "$SANDBOX" "$IMAGE" sleep 300 >/dev/null \
  && defer "docker rm -f ${RUN_ID}-agent"
sleep 1

agent() { docker exec "${RUN_ID}-agent" "$@"; }

echo "== agent routing table"
agent ip route || true
echo "== agent resolv.conf"
agent cat /etc/resolv.conf || true

expect_ok   "agent resolves and reaches gateway by name on :3128" agent sh -c 'echo | nc -w 3 gateway 3128'
expect_fail "agent cannot connect to 1.1.1.1:443"                 agent nc -w 3 -z 1.1.1.1 443
expect_fail "agent cannot connect to 8.8.8.8:53 (tcp)"            agent nc -w 3 -z 8.8.8.8 53
expect_fail "agent cannot ping 1.1.1.1"                           agent ping -c1 -W2 1.1.1.1

# Host reachability: bridge gateway of the default network and the sandbox's own gateway IP.
HOST_IP="$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}')"
SBX_GW="$(docker network inspect "$SANDBOX" -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}')"
echo "default bridge gateway: $HOST_IP, sandbox gateway: $SBX_GW"
expect_fail "agent cannot reach default bridge gateway ($HOST_IP) on :22/:2375" agent sh -c "nc -w 2 -z $HOST_IP 22 || nc -w 2 -z $HOST_IP 2375"
expect_fail "agent cannot ping default bridge gateway $HOST_IP" agent ping -c1 -W2 "$HOST_IP"
expect_fail "agent cannot reach host.docker.internal" agent nc -w 2 -z host.docker.internal 22
if [[ "$SBX_GW" =~ ^[0-9.]+$ ]]; then
  expect_fail "agent cannot ping the sandbox bridge gateway $SBX_GW" agent ping -c1 -W2 "$SBX_GW"
else
  result PASS "sandbox bridge has no host-side gateway address (isolated mode)"
fi

# A host service listening on 0.0.0.0 must not be reachable via the sandbox bridge address.
python3 -m http.server 18999 --bind 0.0.0.0 >/dev/null 2>&1 &
HOST_PID=$!
defer "kill $HOST_PID"
sleep 1
expect_ok   "(control) host service is reachable from host on 127.0.0.1:18999" nc -w 2 -z 127.0.0.1 18999
if [[ "$SBX_GW" =~ ^[0-9.]+$ ]]; then expect_fail "agent cannot reach host 0.0.0.0 service via sandbox gateway $SBX_GW:18999" agent nc -w 2 -z "$SBX_GW" 18999; fi
for hip in $(hostname -I); do expect_fail "agent cannot reach host service via host address $hip:18999" agent nc -w 2 -z "$hip" 18999; done
expect_fail "agent cannot reach host 0.0.0.0 service via default bridge $HOST_IP:18999" agent nc -w 2 -z "$HOST_IP" 18999
summary
