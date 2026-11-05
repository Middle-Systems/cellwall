# 0006: `init`, generated files and `prepare` (M2)

Status: accepted.

## Ownership of files: stamped, seeded, verbatim

Every file `init` writes is one of three kinds.

- **Generated** (`.devcontainer/*`): carries `kennel:generated sha256=<hash of the body>`. The
  hash lets `init` distinguish *pristine* (safe to regenerate), *edited* (kept, reported) and
  *foreign* (no stamp: never touched without `--force`). Output is deterministic (no timestamps,
  sorted maps), which is what makes re-running `init` a no-op and the golden tests meaningful.
- **Seed** (`.kennel/config.yaml`, `.kennel/policy.yaml`): written once and never overwritten,
  not even by `--force`. They hold the user's security decisions.
- **Verbatim** (the Claude Code npm lockfile): copied byte for byte so the integrity hashes in it
  are exactly the reviewed ones.

All-or-nothing: if any file conflicts, nothing is written and the message names `--merge`,
`--force` and moving the file aside. Nothing is ever written through a symlink on the path
(`internal/safefs`), and writes are atomic (temp file + rename).

## Existing devcontainers

An existing `.devcontainer/` is never clobbered. `--merge` leaves it untouched and writes kennel
under `.devcontainer/kennel/` (`devcontainer.dir` records the choice).

## Why the agent is installed from an npm lockfile

The agent CLI is installed with `npm ci` against a committed lockfile (sha512 integrity per
package) rather than a curl-to-shell installer: the artifact is pinned, reviewable and fetched
from the registry the policy already needs for Node projects, and it works where
`downloads.claude.ai` is not reachable. Unpinned versions produce a warning.

## Protected paths

Detection, not creation, is the default: missing protected paths are reported and recorded in the
prepare manifest so ones created mid-session are surfaced. Config is additive: a project's
`protected_paths` extend the built-in defaults; only `unsafe.unprotect` removes a default. Each is
a read-only bind mount and every parent directory is pinned as its own mount point (ADR 0002 and
spike S4). Symlinked protected paths are warned about, not followed.

## Gateway state

Policy, audit log and the override live in `.kennel/state/` on the host. The agent sees the
workspace bind mount, so a tmpfs is mounted over `/workspace/.kennel/state` in the agent only.
The gateway runs as the invoking user's uid/gid so it can write the audit directory in bind mode.

## Caches

Dependency directories (`node_modules`, `.venv`, ...) become named volumes when they are gitignored
or empty/absent, so installs do not hit slow bind mounts and never hide tracked files. `prepare`
pre-creates them as the user (spike S10), which is why *empty* counts as eligible: planning must
give the same answer before and after `prepare` (regression test
`TestPrepareDoesNotChangeThePlan`).

## Still open

Workspace `volume` mode is accepted by the schema but bind mode is the default everywhere until
spike S8 (macOS/Windows file-sharing performance and semantics) is run on real hosts.
