# cellwall

> Working name. Status: **M2 (init and generation)** — `cellwall init` writes a sandbox for your
> project and `cellwall prepare` readies it; there is no `up`/`run` wrapper yet, so you start it with
> `docker compose` or the Dev Containers extension (see below).

cellwall will generate and run a hardened dev container in which a coding agent has no direct
network path to the internet; all egress goes through a policy-enforcing proxy in a separate
container the agent cannot modify. See `PROJECT_SPEC.md` for scope and milestones.

## What exists today

- `cellwall doctor` / `cellwall version`
- `cellwall init`: detects your stacks (node, python, go, rust, java, dotnet, ruby, php, polyglot
  repos included) and writes `.cellwall/config.yaml` + `.cellwall/policy.yaml` (yours to edit) and
  `.devcontainer/` (generated, digest-pinned). It never overwrites a file it did not generate or
  that you edited, never writes through a symlink, writes nothing if anything conflicts, and a
  second run changes nothing. `--merge` adds cellwall beside an existing devcontainer setup.
- `cellwall prepare`: compiles the effective policy, writes the per-session compose override
  (read-only protected-path mounts, secrets, state hidden from the agent) and pre-creates cache
  directories as you. Reports protected paths that do not exist, and drift from the config.
- The **gateway** (`cellwall gateway`, hidden): an HTTP CONNECT / plain-HTTP proxy that enforces a
  deny-by-default hostname policy, refuses IP literals and internal/metadata addresses, checks the
  TLS SNI against the requested host, writes an audit log, and hot-reloads its policy.
- A 3 MB `FROM scratch` gateway image (`make gateway-image`).
- End-to-end tests that build the real topology and attack it from the agent container (`make e2e`).

## Try it

    cellwall init && cellwall prepare
    docker compose -f .devcontainer/compose.yaml -f .cellwall/state/compose.override.yaml \
      --env-file .cellwall/state/compose.env up -d
    docker compose ... exec agent bash

Development:

    make build gateway-image
    make test lint        # unit tests, race detector, linters
    make e2e              # needs Docker: real containers, escape-suite checks 3-7 and 12
    make fuzz             # short fuzzing pass over the parsers and matcher
    make spikes           # the Docker-behaviour spikes behind the design

See `docs/policy.md` for the policy format, `docs/threat-model.md` for what is and is not
protected, `docs/spikes.md` for the evidence the design rests on, and `docs/decisions/` for the
reasoning behind it.

## Findings so far

Spikes and tests have already changed the design: a plain `internal` Docker network still lets the
agent reach host services on `0.0.0.0`; read-only mounts can be bypassed by renaming a parent
directory; a single-file bind mount never sees an atomically replaced policy; and an early ECH
check would have blocked ordinary OpenSSL clients. Each has a recorded mitigation.
