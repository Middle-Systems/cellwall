# 0007: Lifecycle commands (M3)

Status: accepted. Items 1 and 2 differ from the literal text of `PROJECT_SPEC.md`; each says why.

## Deviations from the spec text

1. **Policy changes do not go through `docker exec <gateway> kennel ctl`.** The spec's control
   plane carries commands to the gateway. We already have a channel that is simpler, portable and
   cannot be reached from the agent: the host writes the effective policy atomically into the
   state directory (mounted read-only into the gateway) and the gateway hot-reloads it by content
   hash (ADR 0004, spike S9: ~60 ms). `allow` and `deny` therefore only edit policy and re-run
   `prepare`. `docker exec` is used for one read-only call, `kennel gateway status`, so the host
   can confirm which policy the gateway is *actually* enforcing before saying "it's live". If it
   cannot be confirmed within the wait the command says so instead of claiming success.
2. **`up -d`.** `-d` is accepted and is the default: `up` always returns once the gateway is
   healthy. A foreground `up` that streams logs adds nothing over `logs -f`.

## Session rules and `--save`

- `allow`/`deny` write to the **session layer**, `.kennel/state/session-policy.yaml`: local,
  uncommitted, merged by `prepare` with the highest precedence, and invisible to the agent (the
  state directory is hidden by a tmpfs in the agent container).
- `--save` appends to the committed `.kennel/policy.yaml` through the YAML node tree, so the
  user's comments and other settings survive. The result is parsed and validated before it
  replaces the file, and the edit is undone if the policy then fails to compile.
- **No `unsafe_*` option can be set through these commands**, and the session file refuses them
  when loaded. Relaxations must be written by hand into the reviewed project policy (ADR 0003).
  Asking for plain HTTP (`--port 80`) explains this instead of quietly doing nothing.
- **Verified, not assumed.** After applying, the new policy is matched against the requested
  host(s). If a deny elsewhere still wins, or a lint error (for example `*.github.io`) makes the
  policy refuse to compile, the change is rolled back, the effective policy is restored, and the
  error names the rule and the next step. A refused command leaves nothing behind.
- Session rules are listed with the active relaxations in `prepare`, `up`, `run` and `status`:
  a policy that differs from what is committed must never be silent.
- `deny` after `allow` (same host and ports) replaces the session allow; it does not stack.

## The gateway image

`up` makes sure `kennel-gateway:local` exists. On Linux it is **built from the running binary**
(embedded Dockerfile, `FROM scratch`), labelled with that binary's SHA-256. The gateway can
therefore never be a different version from the CLI that configured it, and `init && run` works
on a clean machine with nothing to download. A labelled image from another binary is rebuilt; an
unlabelled image (made by hand) is trusted; any other reference (`--gateway-image`, a release
digest) is never touched. A dynamically linked binary is refused with an explanation, since it
would fail to start in `scratch`. On macOS and Windows the host binary cannot run in a Linux
container, so the image must come from a release or `make gateway-image`; the error says so.
The choice is remembered in `compose.env`, so a later `allow` does not reset it.

## `run`, `shell`, signals and exit codes

- Interactive commands are started **through the image entrypoint** (`docker exec` skips
  `ENTRYPOINT`), so declared secrets are exported exactly as for the container's main process.
  Arguments are passed as an argv; no shell is involved. `shell` uses `bash` if present, else `sh`.
- A pseudo-terminal is requested only when both stdin and stdout are terminals (`--no-tty`
  forces it off). The test is standard-library only, so any character device other than the null
  device counts as a terminal.
- `run` exits with exactly the agent's status; a command killed by signal N gives 128+N. Because
  the agent may legitimately exit 1, kennel's own failures are indistinguishable by code alone:
  its own messages are on stderr and begin with `error:`.
- SIGINT, SIGTERM and SIGHUP sent to kennel are forwarded to the docker client. Known limit:
  `docker exec` does not forward signals to the process inside the container, so in `--no-tty`
  mode a SIGTERM stops the client but not the agent; `kennel down` stops it. With a terminal,
  Ctrl-C reaches the agent as input, which is what a TUI wants.
- `down --volumes` deletes the agent's login, history and dependency caches, so it needs an
  interactive `yes` or `--yes`; with no terminal and no `--yes` it refuses.

## Running as root

When kennel runs as root (sudo, a root-only runner) the sandbox still runs as an unprivileged
uid. `prepare` now hands the audit and cache directories it creates to that uid; otherwise the
gateway could not open its audit log and (correctly, fail closed) refuses to start. Found by
running the real lifecycle, not by a unit test.

## Not yet

Preview forwarding and `ports` (M4), `verify` (M4), `policy lint` (M4), `fetch`/volume mode (M5).
`logs` reads the host-side copy of the audit log; it works while the sandbox is down.
Windows `run`/`shell` rely on the docker client's console handling and are untested.
