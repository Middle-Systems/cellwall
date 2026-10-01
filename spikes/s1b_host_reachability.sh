#!/usr/bin/env bash
# S1b: follow-up to S1. A plain `internal: true` bridge still gives the host an IP
# on the bridge, so containers can reach host services bound to 0.0.0.0. Test whether
# `com.docker.network.bridge.gateway_mode_ipv4=isolated` (Docker Engine 28+) closes that.
source "$(dirname "$0")/lib.sh"

python3 -m http.server 18999 --bind 0.0.0.0 >/dev/null 2>&1 &
defer "kill $!"
sleep 1
HOST_IPS="$(hostname -I) 127.0.0.1"
echo "host addresses: $HOST_IPS"

probe_network() { # probe_network <label> <expect: reachable|blocked> <create opts...>
  local label="$1" expect="$2"; shift 2
  local net="${RUN_ID}-${label}" ctr="${RUN_ID}-${label}-c"
  docker network create "$@" "$net" >/dev/null || { result FAIL "$label: network create failed"; return; }
  defer "docker network rm $net"
  docker run -d --name "$ctr" --network "$net" "$IMAGE" sleep 120 >/dev/null && defer "docker rm -f $ctr"
  local gw leaks=""
  gw="$(docker exec "$ctr" ip route | awk '/default/{print $3}')"
  echo "[$label] container routes: $(docker exec "$ctr" ip route | tr '\n' ';') default-gw='${gw}'"
  # Probe the bridge subnet's .1 and every host address.
  local subnet_gw
  subnet_gw="$(docker network inspect "$net" -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}')"
  for ip in $subnet_gw $HOST_IPS; do
    [[ "$ip" =~ ^[0-9.]+$ ]] || continue
    docker exec "$ctr" nc -w 2 -z "$ip" 18999 >/dev/null 2>&1 && leaks="$leaks $ip"
  done
  if [ "$expect" = reachable ]; then
    [ -n "$leaks" ] && result PASS "$label: (expected) host service reachable via:$leaks" \
                    || result FAIL "$label: expected host to be reachable, was not"
  else
    [ -z "$leaks" ] && result PASS "$label: host service unreachable on all host addresses" \
                    || result FAIL "$label: host service reachable via:$leaks"
  fi
  # Sibling reachability must still work on the isolated network.
  local sib="${ctr}-sib"
  docker run -d --name "$sib" --network "$net" --network-alias sib "$IMAGE" sh -c 'nc -lk -p 3128 -e echo pong' >/dev/null \
    && defer "docker rm -f $sib"
  sleep 1
  expect_ok "$label: sibling reachable by name" docker exec "$ctr" sh -c 'echo | nc -w 3 sib 3128'
}

probe_network plain    reachable --internal
probe_network isolated blocked   --internal -o com.docker.network.bridge.gateway_mode_ipv4=isolated
summary
