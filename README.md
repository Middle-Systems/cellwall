# cellwall

> Working name. Status: **M0 (skeleton and spikes)** — nothing here sandboxes anything yet.

cellwall will generate and run a hardened dev container in which a coding agent has no direct
network path to the internet; all egress goes through a policy-enforcing proxy in a separate
container the agent cannot modify. See `PROJECT_SPEC.md` for scope and milestones.

## What exists today

    make build && ./dist/cellwall doctor     # check your host (engine >= 28, Compose v2, ...)
    ./dist/cellwall version

`doctor` is deliberately strict: an engine too old to isolate the host from the sandbox network
fails the check instead of warning (`docs/decisions/0001-isolated-gateway-mode.md`).

## Findings so far

Spikes (`docs/spikes.md`) already changed the design: a plain `internal` Docker network still
lets the agent reach host services bound to `0.0.0.0`, and read-only mounts alone can be bypassed
by renaming a parent directory. Both have verified mitigations recorded as ADRs.
