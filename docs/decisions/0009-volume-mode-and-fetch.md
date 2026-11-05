# 0009: Volume workspace mode and `fetch` (M5)

Status: accepted.

## Why

A bind mount shares the host tree with the agent: anything it writes (hooks, `.git/config`, CI
files) lands on the host immediately. On macOS and Windows bind mounts are also slow. Volume mode
gives the agent its own copy in a named volume; the host only changes when the user asks.

## Decisions

- **Seeding** copies `git bundle create - HEAD` from the host into the agent, then overlays
  uncommitted, untracked and deleted files as a tar stream, then `git init/fetch/checkout`. Ignored
  files are not copied (secrets in `.env` stay on the host unless tracked). The base commit is
  recorded in `.kennel/state/volume.json`.
- **`fetch` imports, it does not `git fetch`.** `git fetch <bundle>` skips object verification, so a
  hostile agent could ship malformed objects (for example a tree containing `.git`). The bundle is
  verified with `git bundle verify`, unpacked with `git index-pack --stdin --fix-thin --strict`,
  checked for reachability from the new tips, and only then referenced, under `refs/kennel/*`
  (never `refs/heads`, never tags). A test with a hostile tree is mutation-verified.
- **Nothing is applied by default.** `fetch` prints the commits and changed files per branch.
  `fetch --apply` is a fast-forward merge onto a clean working tree.
- **Protected paths gate `--apply`.** Changes to the configured protected paths plus a fixed set that
  can execute code on the host (`.gitmodules`, `.gitattributes`, `.husky`, `.pre-commit-config.yaml`)
  stop `--apply` with the list of files; `--allow-protected` or an interactive confirmation is
  required after review.
- **Losing work is loud.** `down --volumes` states how many commits were never fetched and whether
  the volume has uncommitted changes, and asks first.
- **Defaults per OS.** `init` chooses `volume` on macOS/Windows when the project is a git repository
  with a commit, `bind` on Linux; the choice is printed and overridable with `--workspace`.
- **`verify` adapts.** In volume mode the protected-paths check becomes a workspace-isolation check:
  a marker on the host is invisible to the agent, a marker in the agent is invisible on the host, and
  the kennel state and policy directories are not visible in the agent.
