#!/usr/bin/env bash
# S3: ports cannot be published from a container that is only on an internal network,
# but a second container on both networks can publish and forward to it.
source "$(dirname "$0")/lib.sh"

SANDBOX="${RUN_ID}-sandbox"; EGRESS="${RUN_ID}-egress"
docker network create --internal -o com.docker.network.bridge.gateway_mode_ipv4=isolated "$SANDBOX" >/dev/null \
  && defer "docker network rm $SANDBOX"
docker network create "$EGRESS" >/dev/null && defer "docker network rm $EGRESS"

WWW="$(mktemp -d)"; echo cellwall-spike-ok >"$WWW/index.html"; defer "rm -rf $WWW"
docker run -d --name "${RUN_ID}-agent" --network "$SANDBOX" --network-alias agent \
  -v "$WWW:/www:ro" "$IMAGE" httpd -f -p 5173 -h /www >/dev/null && defer "docker rm -f ${RUN_ID}-agent"

# A) publishing directly from the internal-only container
PORT_A=15174
if docker run -d --name "${RUN_ID}-pub" --network "$SANDBOX" -p "127.0.0.1:${PORT_A}:5173" \
     -v "$WWW:/www:ro" "$IMAGE" httpd -f -p 5173 -h /www >/dev/null 2>"/tmp/${RUN_ID}.err"; then
  defer "docker rm -f ${RUN_ID}-pub"
  sleep 1
  expect_fail "A: host can NOT reach port published from internal-only container" \
    wget -q -T 3 -O- "http://127.0.0.1:${PORT_A}/"
  result INFO "A: docker accepted -p on internal-only container, port is dead (not an error)"
else
  result PASS "A: docker rejected/failed -p on internal-only container: $(head -c 200 /tmp/${RUN_ID}.err)"
fi

# B) gateway on both networks publishes loopback-only and forwards to the agent
PORT_B=15173
docker run -d --name "${RUN_ID}-gateway" --network "$SANDBOX" --network-alias gateway \
  -p "127.0.0.1:${PORT_B}:5173" "$IMAGE" \
  sh -c "nc -lk -p 5173 -e sh -c 'nc agent 5173'" >/dev/null && defer "docker rm -f ${RUN_ID}-gateway"
docker network connect "$EGRESS" "${RUN_ID}-gateway"
sleep 2
# Publishing must work once the container also has a non-internal network attached.
body="$(printf 'GET / HTTP/1.0\r\n\r\n' | nc -w 3 127.0.0.1 "$PORT_B" 2>/dev/null || true)"
case "$body" in
  *cellwall-spike-ok*) result PASS "B: host 127.0.0.1:$PORT_B reaches agent through gateway forwarder" ;;
  *) result FAIL "B: forward path failed (body='${body:0:80}')"
     docker port "${RUN_ID}-gateway"; docker logs "${RUN_ID}-gateway" 2>&1 | tail -3 ;;
esac

# C) loopback-only publish must not be reachable via other host addresses
OTHER="$(hostname -I | awk '{print $1}')"
expect_fail "C: published port NOT reachable on non-loopback host address $OTHER" nc -w 2 -z "$OTHER" "$PORT_B"

# D) the published-port path should work even when the gateway was created attached to ONLY the
#    internal network and the egress network is connected later (compose attaches both at create).
docker port "${RUN_ID}-gateway" | sed 's/^/   port map: /'
summary
