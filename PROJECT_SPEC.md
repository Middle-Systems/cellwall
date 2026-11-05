# kennel: Sandboxed Coding-Agent Environments (Go)

> **Name.** The product is `kennel` (working name `cellwall`; see `docs/decisions/0010-name-and-licence.md`). Do **not** use "claudew" (see Section 2) and do not put "Claude" or "Anthropic" in the product name.

## 0. How to use this document (read first, agent)

You are building a new open-source CLI from scratch. This document is the source of truth for scope, architecture, and acceptance criteria.

Working agreements:

1. Work milestone by milestone (Section 12). Do not start M(n+1) until M(n) acceptance criteria pass in CI.
2. **Spike before you build.** Section 13 lists Docker/Podman behaviors I believe are true but have not verified. Prove each with a throwaway script in `spikes/` and record the result in `docs/spikes.md` before designing around it. If an assumption is false, stop and write up an alternative rather than working around it silently.
3. Prefer the Go standard library. Every third-party dependency needs a one-line justification in `docs/dependencies.md`.
4. Security-relevant behavior must have a test. If you cannot test a claim, do not make it in the README.
5. When a decision is ambiguous, pick the safer default, note it in `docs/decisions/NNNN-title.md` (short ADR), and continue. Collect true blockers in Section 14 style at the end of each milestone.
6. Never write code that reads, copies, or imitates any proprietary implementation (Section 2).

## 1. Summary

`kennel init` in any repo generates a hardened dev-container setup in which a coding agent (Claude Code first, others configurable) runs **sandboxed with no direct network path to the internet**. All egress goes through a policy-enforcing proxy that runs in a **separate container outside the agent's trust boundary**, so the agent cannot weaken its own restrictions. `kennel run` starts everything and drops you into the agent. Dev-server previews are forwarded to the host browser.

Everything (CLI, proxy, forwarder, generator) is **one static Go binary**, cross-compiled for Linux, macOS, and Windows. The same binary runs as the gateway inside a container.

### Goals

- One-command setup: `kennel init && kennel run`.
- Egress control the agent cannot modify (enforced outside the agent container).
- Fast: CLI startup under 50 ms for non-Docker commands, proxy adds negligible latency, a sane filesystem story on macOS and Windows.
- Platform agnostic: Linux, macOS, Windows (Docker Desktop/WSL2); Docker first, Podman best-effort.
- Compatible with the Dev Containers spec so VS Code and the `devcontainer` CLI still work, but not dependent on them.
- Honest security claims: a documented threat model and an executable `verify` command.
- Supply-chain hygiene as a product feature (pinned digests, SBOM, signed releases).

### Non-goals (v1)

- Defending against container/kernel escapes. (Optionally support stronger runtimes such as gVisor via config; do not claim more.)
- TLS interception / path-level or content-level filtering (no MITM CA in v1).
- Data-loss prevention on allowlisted hosts (anything allowlisted can receive data).
- Being a general-purpose container manager or a CI system.
- Managing secrets beyond explicit, opt-in mounts.

## 2. Provenance and clean-room rules

The author has seen similar internal tooling at an employer. This project must be an independent design derived from this document and public documentation only.

- Do not ask the author for, paste in, or reference any employer source code, config, images, or internal docs.
- Do not reuse the employer's tool name, command names beyond what is natural (`init`, `up`, `run`), file layouts, or defaults.
- If you notice a design choice here that seems to mirror something proprietary, flag it in `docs/decisions/` rather than silently keeping it. The author will resolve ownership questions separately.

## 3. Users and core workflows

**Primary user:** a developer who wants to run an autonomous coding agent with fewer permission prompts and a contained blast radius, without hand-rolling Docker networking.

Core workflows:

1. **First run:** `kennel init` (detects stack, writes config + `.devcontainer/`), `kennel run` (builds, starts, attaches agent).
2. **Blocked request:** the agent's `npm install` hits a non-allowlisted host and fails with a clear message. The developer runs `kennel logs --denied`, then `kennel allow registry.example.com --save`. No restart needed.
3. **Preview:** the agent starts `vite` on 5173. The developer opens `http://localhost:5173` in the host browser. Hot reload works.
4. **Verify:** `kennel verify` runs the escape test suite against the live sandbox and prints pass/fail per property.
5. **Teardown:** `kennel down` (optionally `--volumes`).

## 4. Architecture

### 4.1 Components

```
Host
 ├─ kennel CLI (Go)  ── generates files, drives `docker compose`, execs into containers
 └─ Docker/Podman engine
     ├─ gateway container   (kennel binary, FROM scratch/distroless, non-root)
     │    ├─ egress proxy (HTTP CONNECT + plain HTTP), policy engine, audit log
     │    └─ inbound TCP forwarders for previewed ports
     └─ agent container     (dev toolchain + agent CLI, non-root, no capabilities)
```

### 4.2 Network topology

- `sandbox` network: Docker network with `internal: true`. Members: `agent`, `gateway`. No route to the internet or the host.
- `egress` network: normal bridge. Member: `gateway` only.
- The agent container is attached **only** to `sandbox`. Direct connections to external IPs must fail (no gateway route). Non-proxy-aware tools fail closed.
- The agent gets `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`-style env (plus lowercase variants) pointing at `gateway`, and `NO_PROXY` for `gateway,localhost,127.0.0.1`.
- **DNS:** the agent should not need external DNS. The proxy resolves names itself. Configure the agent so external resolution does not leak (see spike S2). Test it in `verify`.
- No `extra_hosts` / `host.docker.internal` entries. No published ports on the agent. No Docker socket mount. Ever.

### 4.3 Gateway (egress proxy)

Implemented in Go, `internal/proxy`, started via the hidden subcommand `kennel gateway`.

Behavior:

- **HTTPS:** handle `CONNECT host:port`. Check `host` and `port` against policy **before** resolving or dialing. Default allowed port set: `443`. Return `403` with a short plain-text body naming the denied host and how to allow it (`kennel allow <host>`), so the agent sees an actionable error.
- **Plain HTTP:** forward only if the `Host` matches policy; default policy for plain HTTP is deny (configurable per rule).
- **Resolution and dialing:** the gateway resolves the destination, then **dials the resolved IP** (no second lookup, preventing DNS-rebinding between check and use). Reject if any resolved address is loopback, link-local (incl. `169.254.169.254` and other metadata endpoints), private (RFC 1918, CGNAT, ULA), multicast, or unspecified, unless a rule explicitly sets `allow_private: true` (off by default; warn loudly).
- **IP-literal CONNECT targets:** denied by default.
- **TLS ClientHello check (defense in depth + logging):** after `200 Connection Established`, peek the first TLS record and parse SNI. If SNI is absent or does not equal the CONNECT host, close and log. Reject ClientHellos carrying the `encrypted_client_hello` extension unless `allow_ech: true`. Be accurate in docs about what this does and does not stop (see Section 5).
- **Limits:** per-connection idle and total timeouts, max concurrent connections, max bytes per connection (configurable), connection-rate limits per destination host.
- **Hostname hygiene:** reject over-long names or labels (DNS exfil via the name itself), and log high-entropy labels as `suspicious=true`.
- **Audit log:** JSON Lines, one record per decision: `ts, action(allow|deny), host, port, sni, rule, reason, bytes_up, bytes_down, duration_ms, suspicious`. Written to a state directory mounted into the gateway (not into the agent). Provide log rotation.
- **Hot reload:** policy changes take effect without dropping existing connections (watch the effective-policy file; atomic swap of the compiled matcher).

### 4.4 Agent container

- Image generated from a Dockerfile template, selected by stack detection (Section 8). Base: pinned Debian slim (or user-supplied image). Non-root user `dev` with a stable UID, matched to the host UID on Linux to avoid permission churn.
- Hardening defaults: `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`, `pids_limit`, memory/CPU limits (configurable), seccomp default profile, read-only root filesystem optional (`hardening.readonly_rootfs`), tmpfs for `/tmp`. No privileged mode, no `NET_ADMIN`/`NET_RAW`.
- Agent CLI installed per its current official instructions (verify at build time; installer methods change). Pin the version in the generated Dockerfile and expose `agent.version` in config.
- The agent command is configurable (`agent.command`) so other agents can be used. The sandbox is agent-agnostic; Claude Code is the first-class default with a tested preset.
- Image **builds happen on the host network** (not sandboxed). Runtime is sandboxed. Document this clearly.

### 4.5 Workspace modes and filesystem performance

This addresses the original pain: containers on macOS/Windows are slow and awkward.

`workspace.mode`:

- `bind` (default on Linux): host repo bind-mounted at `/workspace`.
- `volume` (recommended default on macOS and Windows): the repo lives in a named volume on the engine's native filesystem. Much faster. Changes return to the host via git (agent commits to a branch; `kennel fetch` pulls it into the host repo). Design `fetch` as a git remote over `docker exec`; keep it simple and document the tradeoff (you do not see files live in Finder/Explorer).

For both modes, **auto-generate named volumes for heavy, regenerable directories** based on detected stack (`node_modules`, `.venv`, `target/`, `.gradle`, `.next`, `__pycache__`, Go build/module cache) so they stay off the slow mount. Also a named volume for the agent's home (`/home/dev`) holding its auth and settings, **separate from the host's** `~/.claude` by default.

### 4.6 Previews (inbound ports)

Docker generally does not publish ports for containers attached only to an `internal: true` network (spike S3). So inbound previews go through the gateway:

- Config lists `ports: [3000, 5173]`. The compose file publishes `127.0.0.1:<port>:<port>` on the **gateway** (loopback only, never `0.0.0.0` unless explicitly configured).
- The gateway runs a TCP forwarder: `gateway:<port>` to `agent:<port>` over `sandbox`. The forwarder's upstream is fixed to the agent. It must not be usable as an outbound path.
- Adding a port later: `kennel ports add 8080` regenerates compose and recreates only the (stateless) gateway.
- The dev server inside the agent must bind `0.0.0.0`. `kennel doctor` and `kennel ports ls` probe for listeners (via `docker exec`, `ss`/`/proc/net/tcp`) and warn when something is listening on loopback only, with the framework-specific fix (`vite --host`, `next dev -H 0.0.0.0`, `flask run --host=0.0.0.0`, etc.).

### 4.7 Credentials and secrets

- Default: **nothing from the host is forwarded.** No SSH agent, no host env vars, no `~/.gitconfig` mount, no cloud credentials.
- Agent authentication: either log in inside the container (persisted in the agent-home volume), or an explicit `secrets:` entry that mounts a file read-only and/or injects an env var. Secrets are declared by name and path; never inlined in config.
- Git: set author identity from config. Pushing is by HTTPS with a user-provided, ideally fine-grained, token via `secrets:`. SSH is not proxied in v1 (see stretch goals).
- Redact secrets from logs; never write secret values to generated files.

### 4.8 Protected paths (anti-persistence)

A compromised agent has write access to the workspace, and the *host* later executes things from it. Mount these **read-only inside the agent container** (nested read-only bind over the writable workspace), by default:

- `.devcontainer/`, `.kennel/`
- `.git/hooks/` (and warn about `.git/config` since `core.fsmonitor`, `core.sshCommand`, aliases, and hooks run on the host)
- `.vscode/tasks.json`, `.vscode/settings.json`, `.idea/` run configurations
- Agent config that auto-executes (`.claude/settings*.json`, `.mcp.json`, and equivalents for other agents)

This list is configurable via `protected_paths:`. Document the tradeoff: the agent cannot edit these, so humans change them on the host. In `volume` mode, `kennel fetch` must show a diff of changes to any protected path and require explicit confirmation before they reach the host working tree.

## 5. Threat model

**Protects against:** a prompt-injected or misbehaving agent (or a malicious dependency script it runs) trying to (a) contact arbitrary internet hosts, (b) reach the host network or cloud metadata endpoints, (c) reconfigure its own egress rules, (d) plant executable config that the host later runs, (e) read host files or credentials not explicitly mounted.

**Does not protect against:**

- Data sent to **allowlisted** hosts (e.g., pushing code to a malicious repo on github.com, public gists, a package registry upload). Recommend narrowly scoped tokens and specific hostnames.
- **Domain fronting** via shared CDNs: without TLS interception, the HTTP Host header is invisible. The SNI == CONNECT-host check only blocks trivial mismatches. Mitigation is to allowlist specific hostnames, not wildcards on large multi-tenant CDNs.
- **DNS-based exfiltration through wildcard allow rules** over domains where an attacker controls subdomain DNS or user content (e.g., `*.github.io`, `*.s3.amazonaws.com`, `*.vercel.app`). The proxy resolves names, so a wildcard rule on such a domain leaks via lookups. The preset linter must reject known user-content wildcards (maintain an embedded list) and `policy lint` must warn.
- Kernel or container-runtime vulnerabilities (offer `runtime: runsc` or similar as opt-in hardening).
- Anything the user deliberately mounts or allows.
- A malicious or compromised host.

Ship this section (tightened) in the README. Ship `kennel verify` so claims are checkable.

## 6. CLI specification

Binary: `kennel`. Use `cobra` (justified: completions, subcommands). Global flags: `--project-dir`, `--verbose`, `--json`.

| Command | Behavior |
|---|---|
| `init [--stack auto\|node,python,go,rust,java,dotnet,ruby,php] [--workspace bind\|volume] [--agent claude] [--force]` | Detect stack; write `.kennel/config.yaml`, `.kennel/policy.yaml`, `.devcontainer/devcontainer.json`, generated Dockerfile and compose. **Non-destructive:** if `.devcontainer/` exists, refuse unless `--force`, or offer `--merge` that only adds files under a `kennel/` subfolder and prints manual steps. Idempotent: re-running with identical inputs produces no diff. |
| `up [-d] [--rebuild]` | Build if needed, start gateway then agent, wait for health, print preview URLs. |
| `run [-- agent args]` | `up` then exec the agent command interactively (TTY passthrough, signal forwarding, correct exit code, Windows ConPTY handled via the engine CLI). |
| `shell` | Interactive shell in the agent container. |
| `down [--volumes]` | Stop and remove containers; `--volumes` also removes named volumes (confirm). |
| `status` | Containers, network mode, active policy hash, previewed ports, workspace mode. |
| `allow <host...> [--port N] [--save]` / `deny <host...>` | Edit policy. Default scope is the current session (state dir); `--save` writes to the committed `.kennel/policy.yaml`. Hot reloads. Validates against the wildcard linter. |
| `logs [-f] [--denied] [--since 1h] [--json]` | Read the audit log. `--denied` groups by host with counts and suggested `allow` commands. |
| `ports ls\|add\|rm` | Manage previews; warn on loopback-only listeners. |
| `verify` | Run the escape suite (Section 10) live. Non-zero exit on any failure. |
| `doctor` | Host checks: engine present and version, compose v2, architecture, rootless/Podman detection, WSL2 detection, file-sharing mode, available resources. Actionable messages. |
| `fetch` | (`volume` mode) pull agent commits to the host repo with protected-path diff gate. |
| `policy lint` | Validate policy; warn on dangerous wildcards, private-range allows, ECH allow. |
| `gateway` (hidden) | Runs inside the gateway container. |
| `version`, `completion` | Standard. |

Control-plane transport: the host CLI talks to the gateway via `docker exec <gateway> kennel ctl ...` (portable across OSes, no sockets or open ports). The agent has no path to this.

Error UX rule: every failure message states what happened, why, and the next command to run.

## 7. Configuration

Two files in `.kennel/` (committed; protected from the agent):

`config.yaml`

```yaml
version: 1
project: myapp                  # used for compose project name and volume names
agent:
  command: ["claude"]           # any agent CLI
  version: "pinned-at-init"
  preset: claude                # adds required API endpoints to policy
workspace:
  mode: volume                  # bind | volume
  cache_volumes: auto           # or explicit list of paths
ports: [5173]
hardening:
  readonly_rootfs: false
  runtime: ""                   # e.g. "runsc" for gVisor, if installed
  pids_limit: 1024
  memory: "8g"
  cpus: 4
protected_paths: [".devcontainer", ".kennel", ".git/hooks", ".vscode/tasks.json", ".claude", ".mcp.json"]
secrets:
  - name: github_token
    source_file: ~/.config/kennel/github_token   # host path, mounted read-only
    env: GH_TOKEN
git:
  user_name: ""
  user_email: ""
```

`policy.yaml`

```yaml
version: 1
default: deny
presets: [node, github]         # embedded, versioned, reviewed
rules:
  - host: registry.npmjs.org
  - host: "*.pythonhosted.org"
  - host: api.example.com
    ports: [443]
    methods_note: "informational only; no L7 enforcement in v1"
limits:
  max_conns: 200
  idle_timeout: 60s
```

Rules: schema-validate with clear line/column errors; unknown keys are errors; layered merge order is embedded defaults, then user-global (`~/.config/kennel/`), then project, then session overrides. Effective policy is written by the host CLI to the state dir and mounted read-only into the gateway only.

## 8. Stack detection and presets

Detect by marker files (`package.json`, lockfiles, `pyproject.toml`, `requirements.txt`, `go.mod`, `Cargo.toml`, `pom.xml`/`build.gradle`, `*.csproj`, `Gemfile`, `composer.json`). Support multiple stacks per repo. Each stack provides: base toolchain install snippet, package-manager registry hosts for the allowlist, heavy dirs to put on volumes, common dev-server ports and the "bind to 0.0.0.0" hint.

Presets are embedded YAML, each reviewed and **pinned to specific hostnames** where possible. Include: `claude` (API host for the agent; telemetry/update endpoints off by default and opt-in; verify required endpoints empirically and against current docs), `node`, `python`, `go`, `rust`, `java`, `github` (git over HTTPS, API, raw/codeload as separate opt-ins), `docker-hub` (opt-in). Add a unit test that every preset passes the wildcard linter.

## 9. Go engineering standards

- Latest stable Go at project start; set in `go.mod`; renovate/dependabot to track.
- `CGO_ENABLED=0`, static binaries, `-trimpath`, version injected via `-ldflags`.
- Layout:
  ```
  cmd/kennel/main.go
  internal/cli        (cobra wiring only; no business logic)
  internal/config     (schema, load, merge, validate)
  internal/detect     (stack detection)
  internal/gen        (embed.FS templates -> Dockerfile, compose, devcontainer.json)
  internal/engine     (interface + docker impl; podman via same CLI/compose where possible)
  internal/proxy      (CONNECT/HTTP proxy, SNI peek, SSRF guard, audit)
  internal/policy     (compile, match, lint, presets)
  internal/forward    (TCP forwarder)
  internal/verify     (escape suite scenarios)
  internal/doctor
  presets/            (embedded YAML)
  spikes/  docs/  test/e2e/
  ```
- Engine abstraction: define an `Engine` interface (`Up`, `Down`, `Exec`, `Build`, `Inspect`). v1 implementation **shells out to `docker` and `docker compose`** for maximum compatibility (Docker Desktop, Colima, Rancher Desktop, OrbStack, Podman's Docker-compatible socket). Do not hard-depend on the Docker SDK unless a spike shows a concrete need.
- Use `log/slog`, `context` everywhere, `errors.Is/As` with wrapped errors, table-driven tests, `t.TempDir()`, `golden` files for generator output.
- Lint/format: `gofmt`, `go vet`, `golangci-lint`, `staticcheck`, `govulncheck` in CI. Fuzz the SNI/ClientHello parser and the policy matcher (`go test -fuzz`).
- Generator output must be deterministic (sorted keys, stable ordering) so diffs are reviewable.
- Windows: handle path translation for bind mounts (prefer `volume` mode by default there); handle CRLF in generated shell scripts (force LF); test in CI on `windows-latest` for non-engine commands.

## 10. Testing and verification

### Unit tests
Policy matching (exact, wildcard, port, case, trailing dots, IDN/punycode), SSRF guard (every blocked range, IPv6, IPv4-mapped IPv6), SNI/ClientHello parsing (fragmented records, missing SNI, ECH, garbage), config validation, stack detection, generator golden files, protected-path set.

### Integration/e2e (CI on Linux with Docker)
Spin up the real topology and run the **escape suite**, shared between CI and `kennel verify`. Each is a named, independently reported check run via `docker exec` in the agent container:

1. Direct TCP to a public IP (e.g., `1.1.1.1:443`) fails.
2. External DNS resolution does not leak (no query reaches an external resolver; verify with a controlled resolver in CI).
3. Via proxy: allowlisted host succeeds; non-allowlisted gets `403` and an audit `deny` record.
4. `CONNECT` to an IP literal is denied.
5. `CONNECT` to hostnames resolving to loopback/RFC1918/link-local/metadata is denied (use a test DNS fixture).
6. SNI mismatch and ECH ClientHello are closed and logged.
7. Plain HTTP is denied by default.
8. Agent cannot write to any protected path; cannot modify policy files (they are not mounted into it).
9. No Docker socket, no `/proc` host leaks, `CapEff` is `0`, `NoNewPrivs` is `1`, process runs as non-root.
10. Agent cannot reach the host (`host.docker.internal`, default gateway ranges) or the gateway's control surface.
11. Inbound preview works: host `127.0.0.1:<port>` reaches an agent HTTP server; the forwarder cannot be used to reach anything but the agent.
12. Policy hot reload: `allow` takes effect within 2s without dropping an in-flight connection.

Also benchmark: proxy overhead (p50/p99 CONNECT setup latency) and throughput; fail CI on large regressions.

## 11. Packaging and supply chain

- GoReleaser: Linux/macOS/Windows on amd64/arm64; checksums; SBOM (CycloneDX or SPDX) per artifact; **cosign keyless signatures**; SLSA provenance via GitHub Actions; reproducible builds (`-trimpath`, fixed timestamps).
- Distribution: GitHub Releases, Homebrew tap, Scoop bucket, `go install`, install script that verifies checksums/signatures (never `curl | sh` without verification).
- **Gateway image:** multi-arch image on a public registry, `FROM scratch` or distroless, non-root, read-only rootfs, built in CI, signed, referenced from generated compose **by digest**. The CLI pins the matching digest per release. (A macOS or Windows host runs a Linux VM, so the gateway image must be Linux regardless of host OS; do not try to run the host binary in the container.) Provide an offline path: embed the linux binaries and build the gateway image locally with `kennel up --offline-gateway`.
- Generated Dockerfiles pin base image digests and verify checksums of anything downloaded during build.
- Minimal dependency tree; `go mod verify` and `govulncheck` gate merges; Dependabot/Renovate with review.
- Security policy (`SECURITY.md`), coordinated disclosure contact, and a changelog.

## 12. Milestones and acceptance criteria

**M0: Skeleton and spikes**
- Repo, CI (lint, vet, test, govulncheck, cross-compile matrix), cobra skeleton with `version`, `doctor`.
- All spikes in Section 13 executed; results in `docs/spikes.md`.
- Done when: CI green on three OSes; spikes documented with go/no-go for the topology.

**M1: Gateway and policy**
- `internal/policy`, `internal/proxy`, `kennel gateway`; audit log; SSRF guard; SNI peek; limits; hot reload.
- Done when: unit + fuzz tests pass; proxy runs standalone in a container; checks 3-7 and 12 pass against it.

**M2: Generator and `init`**
- Stack detection, templates, presets, config/policy schemas, non-destructive/idempotent `init`, golden tests.
- Done when: `init` on fixtures for node, python, go, rust, and a polyglot repo produces valid compose + devcontainer files; re-run produces no diff; existing `.devcontainer/` is never clobbered.

**M3: Lifecycle**
- `up`, `run`, `shell`, `down`, `status`, `logs`, `allow`/`deny`, TTY and signal handling, health checks.
- Done when: on a clean Linux machine, `init && run` yields a working agent session; `allow` unblocks a host live; exit codes propagate.

**M4: Hardening, previews, verify**
- Internal-network topology finalized per spikes, protected paths, forwarders, `ports`, `verify`, `policy lint`.
- Done when: the full escape suite (Section 10) passes in CI and via `kennel verify`; previews work with hot reload on a sample Vite and a sample Flask app.

**M5: Cross-platform and release**
- macOS and Windows (Docker Desktop/WSL2) validation, `volume` workspace mode plus `fetch`, path translation, GoReleaser, signing, SBOM, Homebrew/Scoop, docs site/README, `SECURITY.md`.
- Done when: manual test matrix recorded for macOS (arm64), Windows 11 (WSL2), Ubuntu; signed release artifacts verifiable by a documented command.

**M6: Stretch (separate ADRs before starting)**
- `kennel watch` TUI: live blocked-request prompts to approve once/session/forever.
- SSH-over-CONNECT (`ProxyCommand`) for allowlisted Git hosts on port 22.
- Per-task git worktrees with one sandbox per task for parallel agents.
- Optional stronger runtimes (gVisor `runsc`, Kata); microVM backends.
- Opt-in, local-only TLS inspection (high risk; needs its own threat model).
- Podman rootless as a fully supported target.

## 13. Assumptions to verify in spikes (do these first)

| ID | Assumption | Why it matters |
|---|---|---|
| S1 | A container attached only to an `internal: true` network has no route to external IPs or the host, and can still reach a sibling container on that network by name. | Core of the design. |
| S2 | External DNS resolution from such a container fails or can be made to fail (embedded DNS behavior, `dns:` overrides). Determine the exact config that guarantees no external DNS egress. | DNS exfil path. |
| S3 | Ports cannot be published from containers on internal-only networks, but a second container on both networks can publish and forward. | Preview design. |
| S4 | Nested read-only bind mounts over a writable workspace mount behave correctly on Linux, macOS (VirtioFS), and Windows (WSL2), including for `.git/hooks` as a subpath. | Protected paths. |
| S5 | Docker Desktop, Colima, OrbStack, Rancher Desktop, and Podman differ in `internal` network, compose, and `host-gateway` behavior. Record the matrix. | Platform claims. |
| S6 | Which endpoints the chosen agent actually needs at runtime (observe via audit log with a permissive policy), and how it behaves when optional ones are blocked. | Presets and UX. |
| S7 | Build-time vs run-time image caching: how to keep `up` fast after the first build (layer ordering, BuildKit cache mounts). | Performance goal. |
| S8 | Measured filesystem throughput and latency for `bind` vs `volume` on macOS/Windows for a representative `npm install` and test run. | Justifies defaults. |

## 14. Open questions (agent: raise at milestone boundaries, do not block)

- ~~Final project name and org/module path.~~ Kennel, `github.com/middle-systems/kennel` (ADR 0010).
- ~~License.~~ MIT (ADR 0010).
- Default `workspace.mode` per OS once S8 data exists.
- Whether `fetch` should exist in v1 or whether volume mode ships behind a flag.
- Telemetry: default is **none**. Any future opt-in telemetry needs an ADR.

## 15. Documentation deliverables

- `README.md`: 60-second quickstart, a diagram of the topology, the honest threat model (Section 5), and comparison to alternatives (agent built-in sandboxing, reference devcontainers that enforce iptables inside the container, microVM approaches). **Search for current projects before writing the comparison; this space moves fast.**
- `docs/threat-model.md`, `docs/architecture.md`, `docs/policy.md`, `docs/platforms.md`, `docs/troubleshooting.md` (blocked requests, loopback-bound dev servers, slow filesystems).
- `CONTRIBUTING.md` with the clean-room statement from Section 2.

## Appendix A: Illustrative generated compose (shape, not final)

```yaml
name: kennel-${PROJECT_ID}
networks:
  sandbox:
    internal: true        # agent <-> gateway only (verify S1)
  egress: {}              # gateway <-> internet
volumes:
  agent-home: {}
  node-modules: {}
services:
  gateway:
    image: ghcr.io/OWNER/kennel-gateway@sha256:REPLACE_ME
    command: ["kennel", "gateway", "--policy", "/etc/kennel/policy.yaml"]
    networks: [sandbox, egress]
    ports:
      - "127.0.0.1:5173:5173"       # one per previewed port
    volumes:
      - ${STATE_DIR}/policy.effective.yaml:/etc/kennel/policy.yaml:ro
      - ${STATE_DIR}/audit:/var/log/kennel
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    user: "65532:65532"
  agent:
    build: { context: .devcontainer, dockerfile: Dockerfile }
    networks: [sandbox]
    environment:
      HTTP_PROXY: http://gateway:3128
      HTTPS_PROXY: http://gateway:3128
      http_proxy: http://gateway:3128
      https_proxy: http://gateway:3128
      NO_PROXY: gateway,localhost,127.0.0.1
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    pids_limit: 1024
    volumes:
      - ${WORKSPACE}:/workspace
      - ${WORKSPACE}/.devcontainer:/workspace/.devcontainer:ro
      - ${WORKSPACE}/.kennel:/workspace/.kennel:ro
      - ${WORKSPACE}/.git/hooks:/workspace/.git/hooks:ro
      - agent-home:/home/dev
      - node-modules:/workspace/node_modules
    depends_on: [gateway]
```
