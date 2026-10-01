# 0001: Sandbox network must use `gateway_mode_ipv4=isolated`

Status: accepted (pending S5 on other engines)

## Context
Spike S1b showed `internal: true` does not remove the host's address from the bridge. Host
services bound to `0.0.0.0` (dev DBs, debug ports, Docker API on TCP, etc.) are reachable from
the agent. That violates the core claim "no route to the host".

## Decision
The generated compose file sets, on the `sandbox` network:
`internal: true` and `driver_opts: {com.docker.network.bridge.gateway_mode_ipv4: isolated}`.
`verify` includes a host-reachability check that probes every host address, not only the
bridge gateway. `doctor` requires Docker Engine >= 28 for this topology and refuses to start
otherwise unless `--insecure-allow-host-reachable` is passed (name chosen to be unattractive).

## Consequences
- Older engines and engines where the option is unsupported are not supported by default (safer
  default). Podman needs its own answer from S5.
- `verify` is the source of truth: if the check fails on some engine we say so rather than claim it.
