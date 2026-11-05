# Spike results (M0)

Each spike is a throwaway script in `spikes/`. Environment for every result below:
Docker Engine 29.6.2 (Linux, cgroup v1, iptables backend), Compose v5.3.1, run as root in a
cloud container. **Nothing here has been verified on macOS, Windows, Podman, Colima, OrbStack or
Rancher Desktop** — those columns are explicitly *pending*.

## Summary

| ID | Status | Verdict | One line |
|----|--------|---------|----------|
| S1 | done (Linux/Docker) | **GO, with a required change** | `internal: true` alone does **not** isolate the host; add `gateway_mode_ipv4=isolated`. See ADR 0001. |
| S2 | done (Linux/Docker) | **GO** | No external DNS resolution and no port-53 packets leave the host from the sandbox network. |
| S3 | done (Linux/Docker) | **GO** | Publishing from an internal-only container is silently dead; gateway on both networks forwards fine. |
| S4 | Linux done; macOS/Windows **pending** | **GO, with required changes** | Nested ro mounts work, but protected paths can be evaded by renaming a parent directory. See ADR 0002. |
| S5 | **partial** | Linux, Windows (Docker Desktop) | Docker Engine on Linux passes every row (below). Other engines need their hosts: run `spikes/s5_engine_matrix.sh`, which prints a table row. |
| S6 | **partial** | Windows | One authenticated Claude Code session on Docker Desktop: the preset's hosts were enough to sign in and work (including a web-search tool call). Two optional hosts were denied at start-up without visible effect. See below. |
| S7 | done (Linux/Docker) | **GO** | Warm rebuild 0.7 s vs 7 s cold; layer order matters. |
| S8 | **partial** | Linux, Windows | Windows (Docker Desktop, bind from the Windows filesystem) is 65-300x slower than a volume; Linux shows no consistent difference. macOS and bind-from-WSL-filesystem pending. |
| S9 | done (Linux/Docker) | **GO, design change** | Single-file bind mounts go stale on atomic replace; mount the policy *directory*. |
| S10 | done (Linux/Docker) | **GO, with requirements** | Cache volumes need the image to pre-create+chown the dir; Docker leaves root-owned placeholders in the repo unless `prepare` pre-creates them; a tmpfs cleanly hides the gateway state. |

## S1 — internal network isolation (`spikes/s1_internal_network.sh`, `s1b_host_reachability.sh`)

`s1` asserts the chosen topology (internal + isolated). `s1b` compares plain `internal` against `isolated` and is where the hole is demonstrated.

Confirmed on a plain `internal: true` bridge:
- Container cannot reach `1.1.1.1:443`, `8.8.8.8:53`, or ping external IPs. Container has no default route.
- Container reaches a sibling on the same network by name (embedded DNS).
- `host.docker.internal` does not resolve.

**Spec assumption that is FALSE:** the container has *no route to the host*. The host owns the
bridge's gateway address (e.g. `172.22.0.1`), and **any host service bound to `0.0.0.0` is reachable
from the agent through that address** (S1b, `plain` variant: reachable).

**Fix verified:** creating the network with
`com.docker.network.bridge.gateway_mode_ipv4=isolated` (together with `internal`) stops the host
from taking an address on the bridge. S1b `isolated` variant: the host service is unreachable on
the bridge address *and on every other host address*, and sibling-by-name still works.
Caveats: requires Docker Engine 28+ (the daemon rejects `isolated` on non-internal networks, which
is the safe direction). Older engines/Podman need a separate answer (S5). IPv6 was not tested.

## S2 — DNS (`spikes/s2_dns.sh`)

On the isolated internal network, for three resolver configurations (default, `--dns` blackhole,
`--dns 127.0.0.1`): external names do not resolve (`nslookup`, and `ping`, which reports
`bad address` only when getaddrinfo itself fails), sibling names do.

> **Correction (found via CI):** the first version of this spike claimed a `getent`-based
> getaddrinfo check, but busybox has no `getent`, so that check passed vacuously (exit 127). The
> harness now treats exit 126/127 in `expect_fail` as a failure, `s1` has positive controls for
> every tool used in a "must fail" check, and the getaddrinfo check uses `ping`.
`resolv.conf` always shows the embedded resolver `127.0.0.11`; `--dns` is **not** honoured for
user-defined networks, so it cannot be relied on as a control either way.

Leak measurement: an iptables `FORWARD` counter on port 53 (embedded-resolver upstream queries
cross FORWARD, not OUTPUT — my first attempt on OUTPUT had a blind meter, caught by the control).
Sandbox queries, including exfil-shaped labels: counter unchanged (0→0). Control container on a
normal bridge: counter moved (0→2). So the meter works and the sandbox does not leak.
Caveat: tested for UDP/TCP 53 only; DoT/DoH are just TCP and are covered by S1's no-route result.

## S3 — preview ports (`spikes/s3_ports.sh`)

- `-p` on a container attached only to an internal network is accepted but the port is dead
  (host cannot connect). Silent failure, so the CLI must never rely on it and `verify` must test
  the preview path end to end.
- A gateway on the sandbox network that also has an egress network publishes
  `127.0.0.1:<port>`, and a forwarder to `agent:<port>` works (HTTP round-trip verified).
- Loopback-only publish is not reachable on the host's other addresses.

## S4 — protected paths (`spikes/s4_protected_paths.sh`), Linux only

Works: read-only nested bind mounts block create/modify/delete under `.git/hooks`,
`.devcontainer`, `.kennel`, and a file-level ro mount on `.mcp.json`; `mv`-ing a *mount point*
fails; remount/umount fail without `CAP_SYS_ADMIN`.

**Hole found:** a ro submount does not stop its *parent* being renamed. Without mitigation,
`mv /workspace/.git /workspace/.git.old` succeeds and the agent can create a fresh `.git/hooks`
that the host later executes. **Fix verified:** also bind-mount each intermediate parent of a
protected path rw onto itself, making it a mount point (`mv` then fails). See ADR 0002.

Other findings:
- `--mount type=bind` with a missing source is a hard error. `-v` silently *creates a directory
  on the host*. The generator must use long-form mounts only.
- A ro mount at a target that does not exist in the workspace **creates an empty placeholder in
  the host workspace**. So a protected path that does not exist yet cannot be protected without
  touching the host tree. Open design question; see ADR 0002.
- Not tested: macOS VirtioFS, Windows WSL2/9p, git worktrees (`.git` as a file), symlinked paths.

## S7 — build caching (`spikes/s7_build_cache.sh`)

Cold 7.05 s, warm no-op 0.72 s, bumping an `ARG` late in the file re-runs everything after it
(3.4 s on a fresh run; the script's INFO line depends on what is already in the BuildKit cache, so a repeat run reuses the earlier `AGENT_VERSION=2` layer and reports ~0.8 s — only the PASS assertion is stable). Rule for the generated Dockerfile: slowest, rarest-changing steps first; agent install
and version args last; use `RUN --mount=type=cache` for package caches.

## S9 — policy hot reload vs bind mounts (`spikes/s9_policy_reload_mount.sh`)

Added during M1. The CLI (and any editor) replaces files by write-temp-then-rename, which swaps the
inode. After an atomic replace the single-file bind mount still showed the **old** contents (`v1`)
while a directory bind mount showed the new file (`v2`); an in-place write is visible through both,
which is why a casual test would miss the hazard. Consequence (ADR 0004): the gateway mounts the
policy *directory* read-only and detects changes by polling (inotify across this boundary is not
something to rely on), and the generated compose must not mount `policy.json` as a single file —
Appendix A of the spec does, which is wrong for hot reload. Tested on Linux only; Docker Desktop's
file sharing may behave differently (S5).

## S10 — nested mounts the generated compose relies on (`spikes/s10_nested_mounts.sh`)

Added during M2. Linux/Docker only; Docker Desktop's file sharing may differ (S5).

- **Cache volumes under a bind mount** (e.g. `node_modules` on a named volume inside `/workspace`):
  a fresh volume is root-owned unless the *image* already has that directory owned by the target
  user, in which case Docker copies the ownership into the volume. The generated Dockerfile
  therefore creates and `chown`s every cache directory.
- **Host placeholders:** mounting a volume at a path that does not exist in the bind-mounted repo
  makes Docker create it **in the user's repository, owned by root**, which breaks a later
  host-side `npm install`/`cargo build` with `EACCES`. A directory that already exists keeps its
  owner. `kennel prepare` therefore pre-creates cache directories as the invoking user.
- **Hiding gateway state:** a `tmpfs` mounted at `/workspace/.kennel/state`, inside the read-only
  `.kennel` bind mount, hides the state directory (policy, audit) from the agent completely, and
  the agent cannot write into it either (the tmpfs is root-owned `0755`). Nothing reaches the host.

## Pending spikes

- **S5 on Windows, second run (Docker Desktop 4.92.0, Engine 29.8.0, Git Bash, after the script
  fixes): DNS no-leak yes, publish via gateway yes, read-only nested mounts yes, host reachability
  n/a (engine in a VM; covered by `kennel verify`), nested mounts (S10) 10 of 11 pass.** The one
  difference is real: the `tmpfs` that hides the state directory is world-writable on Docker
  Desktop (the agent user could write scratch files into it) but root-owned 0755 on Docker Engine
  29.6. Nothing reaches the host either way (the spike's host-side checks pass) and it is memory
  only, so this is not an escape, but the behaviour depended on the engine. The generated override
  now sets the mode explicitly (0555, one page), which is read-only on both; the Linux run of the
  spike passes with it and Compose renders it as `555 root`. To re-confirm on Docker Desktop, rerun
  `spikes/s10_nested_mounts.sh` after pulling.
- **S5 on Windows, first run (same machine, before the script fixes): not valid, do not use.** The
  host-side tools and paths the spikes assumed (`hostname -I`, `wget`, `nc`, POSIX temp paths that
  the Windows daemon cannot resolve) did not exist, so controls failed and results read NO/ERROR.
  Only DNS no-leak (yes) and the read-only evasion checks inside s4 (all PASS) ran meaningfully.
  The scripts now use portable helpers (`spikes/lib.sh`), and the host-reachability spike is
  reported n/a on engines that run in a VM; that claim is covered there by `kennel verify`
  (check 10). A re-run is needed.
- **S5 engine matrix:** run `spikes/s5_engine_matrix.sh` on each engine (it runs
  `s1b_host_reachability.sh`, `s2_dns.sh`, `s3_ports.sh`, `s4_protected_paths.sh` and
  `s10_nested_mounts.sh` and prints the row) and fill in:

  | Engine | OS | internal+isolated host-blocked | DNS no-leak | publish via gateway | ro nested mounts | Notes |
  |---|---|---|---|---|---|---|
  | Docker Engine 29.6 | Linux | yes | yes | yes | yes (with parent pinning) | this report |
  | Docker Desktop | macOS / Windows | pending | pending | pending | pending | |
  | Colima / OrbStack / Rancher Desktop | macOS | pending | pending | pending | pending | |
  | Podman (rootless) | Linux | pending | pending | pending | pending | `gateway_mode_ipv4` likely unsupported |

- **S6 endpoints:** procedure in `spikes/s6_agent_endpoints.md`.

  First observation (Windows 10, Docker Desktop 4.92.0, volume mode, Claude Code with the shipped
  `claude` preset and no other rules; audit log from the gateway, one sign-in plus a short
  conversation that included a web-search tool call):

  | host | decision | notes |
  |---|---|---|
  | `api.anthropic.com:443` | allowed (preset rule 0) | the model API; carried all traffic, including the web search (it runs server-side, so no extra host) |
  | `platform.claude.com:443` | allowed (preset rule 2) | contacted at start-up and again later; short connections |
  | `claude.ai:443` | not contacted | in the preset for sign-in; not seen in this session, so keep it until a fresh sign-in has been observed |
  | `downloads.claude.ai:443` | denied (default-deny) | once, a few seconds after start-up; no visible effect |
  | `github.com:443` | denied (default-deny) | once, right after the one above; no visible effect |

  The agent worked normally with the two denied hosts blocked. What they are for (probably an
  update check and a plugin or release lookup) is not established from this log; the preset
  stays as it is, and `kennel logs --denied` lists them with the allow command for anyone who
  wants them.

  Also seen: long-lived tunnels to `api.anthropic.com` and `platform.claude.com` were closed by
  the gateway's 120 s `idle_timeout` while idle (`reason: idle-timeout`), and the client simply
  reconnected. A single request that is silent for longer than that would be cut; raise
  `limits.idle_timeout` if a long non-streaming call is ever interrupted.

  Still to do for S6: a fresh sign-in (to see whether `claude.ai` is used), a session that uses
  tools needing the network (package installs, git over https), and the other agents.
- **S8 filesystem timing:** `spikes/s8_fs_timing.sh [--npm] [--dir <host path>]` on macOS and
  Windows (run it once with `--dir` on the Windows/macOS filesystem and, on Windows, once inside
  WSL for comparison).

  Linux baseline (Docker Engine 29.6, 5000 small files, ext4/overlay; one run, 10 ms resolution):

  | phase | bind (ms) | volume (ms) |
  |---|---|---|
  | write small files | 3120 | 3250 |
  | walk and stat | 70 | 70 |
  | read all | 80 | 100 |
  | delete tree | 150 | 130 |

  On Linux the two modes cost about the same (a second run showed a 2x write difference, so single
  runs are noisy); the default stays `bind` there.

  Windows 10 22H2, Docker Desktop 4.92.0 (Engine 29.8.0, WSL2 backend), 20000 small files,
  `busybox:1.36`, one run per row set. The bind directory is on the Windows filesystem (NTFS): the
  first run used `--dir /c/Users/jack/s8`, the second `--dir /tmp/s8`, which under Git Bash is
  also a Windows path (`%TEMP%`), so the two are repeats of the same case.

  | phase | bind, run 1 (ms) | volume, run 1 (ms) | ratio | bind, run 2 (ms) | volume, run 2 (ms) | ratio |
  |---|---|---|---|---|---|---|
  | write small files | 101460 | 1550 | 65x | 100840 | 1130 | 89x |
  | walk and stat | 66940 | 230 | 291x | 66000 | 220 | 300x |
  | read all | 70040 | 380 | 184x | 64120 | 340 | 189x |
  | delete tree | 46630 | 420 | 111x | 42600 | 500 | 85x |

  The two runs agree within about 10%, so the gap is real, not noise: working directly on a
  Windows-filesystem bind mount takes minutes for a 20,000-file tree (a `node_modules`-sized
  workload) where a volume takes about a second. This justifies `volume` as the Windows default.
  **Not yet measured:** a bind mount of a directory inside the WSL filesystem (run the script from
  a WSL shell with `--dir /home/<you>/s8`), which is the case the platform notes recommend for
  people who want a bind mount on Windows; and macOS.

## CI notes (GitHub-hosted ubuntu runner, run 3 onward)

All of S1, S1b, S2, S3, S4 and S7 pass on the runner as well as locally, so the Linux results
above hold on a second kernel/engine build, including both halves of the two design-changing
findings: plain `internal` still exposes host `0.0.0.0` services (S1b), and `.git` can be renamed
away unless pinned (S4 "DEMO (hole)" passes, i.e. the hole is real there too).

- The first CI run failed in `s2` on "sibling `gateway` resolves via embedded DNS", which used
  busybox `nslookup`. The runner's resolver config differs (`options edns0 trust-ad`, a `search`
  domain, systemd-resolved upstream). After switching that check to the `getaddrinfo` path (`ping`)
  it passed on the first attempt, with no retry needed, so this was **not** a registration race.
  Most likely a busybox `nslookup` quirk on that resolver setup, but that is a hypothesis: it was
  not isolated.
- Consequence for reading S2: the `getaddrinfo` (`ping ... bad address`) assertions are the
  authoritative DNS checks. The `nslookup` "does not resolve" assertions are corroboration only,
  because that tool behaved inconsistently across environments.
- `actions/checkout@v4.4.0` logs a Node 20 deprecation warning (forced to Node 24). Not a failure;
  Dependabot will propose a newer major.
