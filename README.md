# kennel

> Working name. Status: **M5 (cross-platform and releases)** — `kennel init && kennel run`
> starts the sandbox and drops you into the agent; dev servers preview on `localhost`;
> `kennel verify` attacks the running sandbox so the claims below are checkable; on macOS and
> Windows the agent works on its own copy (volume mode) and `kennel fetch` brings work back.
> Verified in CI on Linux; macOS and Windows results are tracked in `docs/platforms.md`.

kennel will generate and run a hardened dev container in which a coding agent has no direct
network path to the internet; all egress goes through a policy-enforcing proxy in a separate
container the agent cannot modify. See `PROJECT_SPEC.md` for scope and milestones.

## What exists today

- `kennel doctor` / `kennel version`
- `kennel init`: detects your stacks (node, python, go, rust, java, dotnet, ruby, php, polyglot
  repos included) and writes `.kennel/config.yaml` + `.kennel/policy.yaml` (yours to edit) and
  `.devcontainer/` (generated, digest-pinned). It never overwrites a file it did not generate or
  that you edited, never writes through a symlink, writes nothing if anything conflicts, and a
  second run changes nothing. `--merge` adds kennel beside an existing devcontainer setup.
- `kennel up | run | shell | down | status | logs | allow | deny`: the lifecycle (ADR 0007).
  `allow` is confirmed against the running gateway before it says "live", and is refused (and
  undone) if a deny elsewhere still wins or the host is a dangerous wildcard.
- `kennel ports ls|add|rm`: previews are published by the gateway on `127.0.0.1` and relayed to
  the agent by a forwarder whose upstream is fixed (ADR 0008). The agent never publishes ports.
- `kennel fetch [--apply]`: in volume mode, imports the agent's commits (strictly verified) as
  `refs/kennel/*` and shows what changed; `--apply` fast-forwards and stops at protected files
  (ADR 0009).
- `kennel verify`: twelve escape attempts against the live sandbox, each reported PASS, FAIL or
  SKIP (never a silent pass); `--strict` for CI. Also `kennel policy lint`.
- `kennel prepare`: compiles the effective policy, writes the per-session compose override
  (read-only protected-path mounts, secrets, state hidden from the agent) and pre-creates cache
  directories as you. Reports protected paths that do not exist, and drift from the config.
- The **gateway** (`kennel gateway`, hidden): an HTTP CONNECT / plain-HTTP proxy that enforces a
  deny-by-default hostname policy, refuses IP literals and internal/metadata addresses, checks the
  TLS SNI against the requested host, writes an audit log, and hot-reloads its policy.
- A 3 MB `FROM scratch` gateway image (`make gateway-image`).
- End-to-end tests that build the real topology and attack it from the agent container (`make e2e`).

## Try it

    kennel init                 # detect the stack, write .kennel/ and .devcontainer/
    kennel run                  # start the sandbox if needed, run the agent in it
    kennel run -- -p "fix the failing test"

    kennel logs --denied        # what the policy blocked, grouped, with the command to allow it
    kennel allow registry.example.org            # live, this session only
    kennel allow registry.example.org --save     # also write it to .kennel/policy.yaml
    kennel deny telemetry.example.org
    kennel status               # containers, network isolation, active policy, relaxations
    kennel shell                # a shell in the agent container
    kennel down [--volumes]

    kennel ports add 5173       # preview a dev server at http://localhost:5173 (hot reload works)
    kennel ports ls             # what is listening, and the fix if it listens on localhost only
    kennel verify               # run the escape suite against the live sandbox
    kennel policy lint          # dangerous wildcards, private-range allows, weakened controls

`up` builds the gateway image from the kennel binary itself (Linux) or from the Linux gateway
carried inside the release binary (macOS, Windows). A development build on macOS/Windows needs
`--gateway-image` or `make gateway-image` on Linux.

Install a release with `scripts/install.sh`; it verifies the checksum and Sigstore signature
(`docs/releasing.md`).

Development:

    make build gateway-image
    make test lint        # unit tests, race detector, linters
    make e2e              # needs Docker: real containers, escape-suite checks 3-7 and 12
    make fuzz             # short fuzzing pass over the parsers and matcher
    make spikes           # the Docker-behaviour spikes behind the design

See `docs/performance.md` for proxy overhead numbers and the regression gate, `docs/policy.md` for the policy format, `docs/threat-model.md` for what is and is not
protected, `docs/spikes.md` for the evidence the design rests on, and `docs/decisions/` for the
reasoning behind it.

## Findings so far

Spikes and tests have already changed the design: a plain `internal` Docker network still lets the
agent reach host services on `0.0.0.0`; read-only mounts can be bypassed by renaming a parent
directory; a single-file bind mount never sees an atomically replaced policy; and an early ECH
check would have blocked ordinary OpenSSL clients. Each has a recorded mitigation.

## Licence

MIT; see `LICENSE`.
