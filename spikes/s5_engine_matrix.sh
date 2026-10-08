#!/usr/bin/env bash
# S5: record how a container engine behaves for the properties cellwall relies on. Run it on each
# engine you want in the matrix (Docker Desktop, Colima, OrbStack, Rancher Desktop, Podman with
# its docker-compatible socket) and paste the printed row into docs/spikes.md.
#
#   spikes/s5_engine_matrix.sh
#
# Each spike is run as its own process; the row says yes/NO per property. A spike that cannot run
# at all (missing tool, daemon error) is reported as ERROR, never as yes.
cd "$(dirname "$0")" || exit 1

have() { command -v "$1" >/dev/null 2>&1; }
have docker || { echo "docker CLI not found"; exit 1; }
docker info >/dev/null 2>&1 || { echo "cannot reach the container engine"; exit 1; }

engine="$(docker version --format '{{.Server.Platform.Name}} {{.Server.Version}}' 2>/dev/null)"
osname="$(docker info --format '{{.OperatingSystem}} / {{.OSType}}-{{.Architecture}}' 2>/dev/null)"
host="$(uname -s)"
compose="$(docker compose version --short 2>/dev/null || echo none)"
rootless="$(docker info --format '{{range .SecurityOptions}}{{.}} {{end}}' 2>/dev/null | grep -o rootless || true)"

run() { # run <script> -> yes | NO | ERROR, with the log kept in /tmp
  local log="/tmp/s5-$1.log"
  bash "./$1" >"$log" 2>&1; local rc=$?
  if grep -q 'VACUOUS\|command not found\|Cannot connect' "$log"; then echo ERROR; return; fi
  [ "$rc" -eq 0 ] && echo yes || echo NO
}

echo "engine:  $engine ($osname), host $host, compose $compose${rootless:+, rootless}"
echo "running the spikes (a minute or two)..."
# s1b starts a service on the *host* and probes it from a container on the engine's bridge. That
# only means something when the engine shares the shell's network namespace (Linux). Docker
# Desktop and similar run the engine in a VM, where the bridge is not on the host at all: the
# host-reachability claim there is covered by `cellwall verify` (check 10), not by this spike.
if docker info --format '{{.OperatingSystem}}' 2>/dev/null | grep -qi 'desktop' || [ "$(uname -s | cut -c1-5)" != Linux ]; then
  host_blocked="n/a (engine in a VM: use cellwall verify, check 10)"
else
  host_blocked=$(run s1b_host_reachability.sh)
fi
dns=$(run s2_dns.sh)
ports=$(run s3_ports.sh)
mounts=$(run s4_protected_paths.sh)
nested=$(run s10_nested_mounts.sh)

echo
echo "| Engine | OS | internal+isolated host-blocked | DNS no-leak | publish via gateway | ro nested mounts | nested mounts (S10) | Notes |"
echo "|---|---|---|---|---|---|---|---|"
echo "| $engine | $host / $osname | $host_blocked | $dns | $ports | $mounts | $nested | compose $compose${rootless:+; rootless} |"
echo
echo "Logs: /tmp/s5-*.log (under Git Bash that is %TEMP%). A NO or ERROR needs the log read before it goes in the table."
for pair in "s1b_host_reachability.sh:${host_blocked%% *}" "s2_dns.sh:$dns" "s3_ports.sh:$ports" "s4_protected_paths.sh:$mounts" "s10_nested_mounts.sh:$nested"; do
  sc="${pair%%:*}"; res="${pair##*:}"
  if [ "$res" != yes ] && [ "$res" != n/a ]; then
    echo
    echo "=== $sc: $res (failing lines and the last 25 lines of its log)"
    grep -E '^(FAIL|ERROR)|VACUOUS' "/tmp/s5-$sc.log" | head -10
    echo "---"
    tail -25 "/tmp/s5-$sc.log"
  fi
done
